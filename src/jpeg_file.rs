use std::io::{Seek, Write};
use std::path::{Path, PathBuf};
use std::{fs, fs::File, io, io::Read};

use thiserror::Error;

use crate::jpeg::{JpegError, OwnedJpeg, get_capacity, read_owned_jpeg, write_owned_jpeg};
use crate::lsb::{ensure_byte_aligned, get_lsb, is_embeddable_coeff, read_bit_from_bytes, set_lsb};
use crate::zigzag::{RESERVED_ZIGZAG_COEFFS, ZIGZAG_INDICES};

#[derive(Debug, Error)]
pub enum JpegFileError {
	#[error("failed to open input file '{path}'")]
	OpenInput {
		path: PathBuf,
		#[source]
		source: io::Error,
	},
	#[error("failed to rewind input file '{path}'")]
	RewindInput {
		path: PathBuf,
		#[source]
		source: io::Error,
	},
	#[error("failed to read input file '{path}'")]
	ReadInput {
		path: PathBuf,
		#[source]
		source: io::Error,
	},
	#[error("failed to compute JPEG capacity")]
	CapacityComputation(#[source] JpegError),
	#[error(transparent)]
	Jpeg(#[from] JpegError),
	#[error("bit offset {bit_offset} is not byte-aligned")]
	NotByteAligned { bit_offset: usize },
	#[error("bit offset {bit_offset} exceeds available capacity of {capacity_bits} bits")]
	BitOffsetOutOfRange { bit_offset: usize, capacity_bits: usize },
	#[error("requested {requested_bytes} bytes exceeds available capacity of {available_bytes} bytes")]
	ReadOutOfCapacity {
		requested_bytes: usize,
		available_bytes: usize,
	},
	#[error("not enough capacity to write {requested_bytes} bytes; only {available_bytes} bytes available")]
	WriteOutOfCapacity {
		requested_bytes: usize,
		available_bytes: usize,
	},
	#[error("failed to create '{path}'")]
	CreateOutput {
		path: PathBuf,
		#[source]
		source: io::Error,
	},
	#[error("failed to write output file '{path}'")]
	WriteOutput {
		path: PathBuf,
		#[source]
		source: io::Error,
	},
	#[error("failed to copy '{from}' to '{to}'")]
	CopyFile {
		from: PathBuf,
		to: PathBuf,
		#[source]
		source: io::Error,
	},
}

pub fn init_file(path: &Path) -> Result<JpegFileHandle, JpegFileError> {
	let mut file = File::open(path).map_err(|source| JpegFileError::OpenInput {
		path: path.to_owned(),
		source,
	})?;

	let content = JpegFileHandle::read_all_from_file(&mut file, path)?;
	let capacity = get_capacity(&content).map_err(JpegFileError::CapacityComputation)?;
	println!("Opened file '{}' capacity: {}", path.display(), capacity);

	Ok(JpegFileHandle {
		file,
		path: path.to_owned(),
		capacity,
	})
}

pub struct JpegFileHandle {
	file: File,
	path: PathBuf,
	capacity: usize,
}

pub struct JpegSession {
	path: PathBuf,
	source_jpeg: Vec<u8>,
	owned_jpeg: OwnedJpeg,
	bit_slots: Vec<BitSlot>,
	cursor_bits: usize,
	dirty: bool,
}

#[derive(Clone, Copy)]
pub struct BitSlot {
	pub component_index: usize,
	pub block_index: usize,
	pub coeff_index: usize,
}

impl JpegSession {
	pub fn new(path: PathBuf, source_jpeg: Vec<u8>) -> Result<Self, JpegFileError> {
		let owned_jpeg = unsafe { read_owned_jpeg(&source_jpeg)? };
		let bit_slots = Self::collect_bit_slots(&owned_jpeg);
		Ok(Self {
			path,
			source_jpeg,
			owned_jpeg,
			bit_slots,
			cursor_bits: 0,
			dirty: false,
		})
	}

	pub fn capacity(&self) -> usize {
		self.bit_slots.len() / 8
	}

	pub fn seek_bits(&mut self, bit_offset: usize) -> Result<(), JpegFileError> {
		if bit_offset > self.bit_slots.len() {
			return Err(JpegFileError::BitOffsetOutOfRange {
				bit_offset,
				capacity_bits: self.bit_slots.len(),
			});
		}
		self.cursor_bits = bit_offset;
		Ok(())
	}

	pub fn seek(&mut self, byte_offset: usize) -> Result<(), JpegFileError> {
		self.seek_bits(byte_offset * 8)
	}

	pub fn remaining_bytes(&self) -> usize {
		(self.bit_slots.len().saturating_sub(self.cursor_bits)) / 8
	}

	pub fn read(&mut self, out: &mut [u8]) -> usize {
		let n = out.len().min(self.remaining_bytes());
		out[..n].fill(0);

		for (byte_idx, out_byte) in out[..n].iter_mut().enumerate() {
			for bit_in_byte in 0..8usize {
				let absolute_bit = self.cursor_bits + (byte_idx * 8) + bit_in_byte;
				let slot = self.bit_slots[absolute_bit];
				let coeff = self.owned_jpeg.components[slot.component_index].blocks[slot.block_index][slot.coeff_index];
				let bit = get_lsb(coeff);
				if bit == 1 {
					*out_byte |= 1 << (7 - bit_in_byte);
				}
			}
		}

		self.cursor_bits += n * 8;
		n
	}

	pub fn write(&mut self, data: &[u8]) -> usize {
		let n = data.len().min(self.remaining_bytes());

		for byte_idx in 0..n {
			for bit_in_byte in 0..8usize {
				let absolute_bit = self.cursor_bits + (byte_idx * 8) + bit_in_byte;
				let slot = self.bit_slots[absolute_bit];
				let bit = read_bit_from_bytes(data, (byte_idx * 8) + bit_in_byte).unwrap_or(0);
				let coeff =
					&mut self.owned_jpeg.components[slot.component_index].blocks[slot.block_index][slot.coeff_index];
				*coeff = set_lsb(*coeff, bit);
			}
		}

		if n > 0 {
			self.dirty = true;
		}
		self.cursor_bits += n * 8;
		n
	}

	pub fn read_data(&mut self, len: usize) -> Result<Vec<u8>, JpegFileError> {
		ensure_byte_aligned(self.cursor_bits).ok_or(JpegFileError::NotByteAligned {
			bit_offset: self.cursor_bits,
		})?;
		if len > self.remaining_bytes() {
			return Err(JpegFileError::ReadOutOfCapacity {
				requested_bytes: len,
				available_bytes: self.remaining_bytes(),
			});
		}

		let mut out = vec![0u8; len];
		let read = self.read(&mut out);
		debug_assert_eq!(read, len);
		Ok(out)
	}

	pub fn write_data(&mut self, data: &[u8]) -> Result<(), JpegFileError> {
		ensure_byte_aligned(self.cursor_bits).ok_or(JpegFileError::NotByteAligned {
			bit_offset: self.cursor_bits,
		})?;
		if data.len() > self.remaining_bytes() {
			return Err(JpegFileError::WriteOutOfCapacity {
				requested_bytes: data.len(),
				available_bytes: self.remaining_bytes(),
			});
		}

		let written = self.write(data);
		debug_assert_eq!(written, data.len());
		Ok(())
	}

	pub fn flush(&mut self) -> Result<(), JpegFileError> {
		if !self.dirty {
			return Ok(());
		}

		let output_jpeg = unsafe { write_owned_jpeg(&self.source_jpeg, &self.owned_jpeg)? };

		let mut output_file = File::create(&self.path).map_err(|source| JpegFileError::CreateOutput {
			path: self.path.clone(),
			source,
		})?;
		output_file
			.write_all(&output_jpeg)
			.map_err(|source| JpegFileError::WriteOutput {
				path: self.path.clone(),
				source,
			})?;

		println!("Wrote '{}': {}KiB", self.path.display(), output_jpeg.len() / 1024);

		self.source_jpeg = output_jpeg;
		self.dirty = false;
		Ok(())
	}

	pub fn collect_bit_slots(owned_jpeg: &OwnedJpeg) -> Vec<BitSlot> {
		let mut bit_slots = Vec::new();
		for (component_index, component) in owned_jpeg.components.iter().enumerate() {
			for (block_index, block) in component.blocks.iter().enumerate() {
				for &coeff_index in ZIGZAG_INDICES.iter().skip(RESERVED_ZIGZAG_COEFFS) {
					if is_embeddable_coeff(block[coeff_index]) {
						bit_slots.push(BitSlot {
							component_index,
							block_index,
							coeff_index,
						});
					}
				}
			}
		}
		bit_slots
	}
}

impl JpegFileHandle {
	pub fn from_parts(file: File, path: PathBuf, capacity: usize) -> Self {
		Self { file, path, capacity }
	}

	pub fn capacity(&self) -> usize {
		self.capacity
	}

	fn read_all_from_file(file: &mut File, path: &Path) -> Result<Vec<u8>, JpegFileError> {
		file.rewind().map_err(|source| JpegFileError::RewindInput {
			path: path.to_owned(),
			source,
		})?;
		let mut content = Vec::<u8>::new();
		file.read_to_end(&mut content)
			.map_err(|source| JpegFileError::ReadInput {
				path: path.to_owned(),
				source,
			})?;
		Ok(content)
	}

	fn read_all(&mut self) -> Result<Vec<u8>, JpegFileError> {
		Self::read_all_from_file(&mut self.file, &self.path)
	}

	pub fn copy_to(&self, target_path: &Path) -> Result<JpegFileHandle, JpegFileError> {
		fs::copy(&self.path, target_path).map_err(|source| JpegFileError::CopyFile {
			from: self.path.clone(),
			to: target_path.to_owned(),
			source,
		})?;
		init_file(target_path)
	}

	pub fn write_data(&mut self, data: &[u8]) -> Result<(), JpegFileError> {
		let input_jpeg = self.read_all()?;
		let mut session = JpegSession::new(self.path.clone(), input_jpeg)?;
		session.seek(0)?;
		session.write_data(data)?;
		session.flush()?;

		Ok(())
	}

	pub fn read_data(&mut self, len: usize) -> Result<Vec<u8>, JpegFileError> {
		let input_jpeg = self.read_all()?;
		let mut session = JpegSession::new(self.path.clone(), input_jpeg)?;
		session.seek(0)?;
		session.read_data(len)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::jpeg::OwnedComponent;

	fn dummy_session() -> JpegSession {
		let component = OwnedComponent {
			width_in_blocks: 1,
			height_in_blocks: 1,
			blocks: vec![[0; 64]],
		};
		JpegSession {
			path: PathBuf::from("dummy.jpg"),
			source_jpeg: Vec::new(),
			owned_jpeg: OwnedJpeg {
				components: [component.clone(), component.clone(), component],
			},
			bit_slots: vec![
				BitSlot {
					component_index: 0,
					block_index: 0,
					coeff_index: 5,
				};
				8
			],
			cursor_bits: 0,
			dirty: false,
		}
	}

	#[test]
	fn seek_bits_rejects_offsets_past_capacity() {
		let mut session = dummy_session();
		let err = session
			.seek_bits(9)
			.expect_err("seeking past the bit capacity should fail");
		assert!(matches!(
			err,
			JpegFileError::BitOffsetOutOfRange {
				bit_offset: 9,
				capacity_bits: 8
			}
		));
	}

	#[test]
	fn read_data_rejects_requests_past_capacity() {
		let mut session = dummy_session();
		let err = session
			.read_data(2)
			.expect_err("reading more than one byte should exceed capacity");
		assert!(matches!(
			err,
			JpegFileError::ReadOutOfCapacity {
				requested_bytes: 2,
				available_bytes: 1
			}
		));
	}

	#[test]
	fn write_data_rejects_requests_past_capacity() {
		let mut session = dummy_session();
		let err = session
			.write_data(&[1, 2])
			.expect_err("writing more than one byte should exceed capacity");
		assert!(matches!(
			err,
			JpegFileError::WriteOutOfCapacity {
				requested_bytes: 2,
				available_bytes: 1
			}
		));
	}
}
