use std::io::Write;
use std::path::PathBuf;
use std::{fs::File, io};

use crate::crypto::STRATEGY_MARKER_SIZE;
use crate::jpeg::{JpegError, OwnedJpeg, read_owned_jpeg, write_owned_jpeg};
use crate::lsb::{ensure_byte_aligned, get_lsb, is_embeddable_coeff, read_bit_from_bytes, set_lsb};
use crate::strategy::{EmbeddingStrategy, EmbeddingStrategyId, strategy_from_id};
use crate::zigzag::{RESERVED_ZIGZAG_COEFFS, ZIGZAG_INDICES};
use thiserror::Error;

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
	#[error("byte offset {byte_offset} exceeds available capacity of {capacity_bytes} bytes")]
	ByteOffsetOutOfRange { byte_offset: usize, capacity_bytes: usize },
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

pub struct EmbeddingSession {
	jpeg: JpegSession,
	strategy: Box<dyn EmbeddingStrategy>,
	cursor_bytes: usize,
	data_start_slot: usize,
}

impl EmbeddingSession {
	pub fn remaining_bytes(&self) -> usize {
		self.strategy
			.capacity_bytes(self.data_slot_count())
			.saturating_sub(self.cursor_bytes)
	}

	pub fn data_slot_count(&self) -> usize {
		self.jpeg.bit_slots.len().saturating_sub(self.data_start_slot)
	}

	pub fn seek(&mut self, byte_offset: usize) -> Result<(), JpegFileError> {
		let capacity_bytes = self.strategy.capacity_bytes(self.data_slot_count());
		if byte_offset > capacity_bytes {
			return Err(JpegFileError::ByteOffsetOutOfRange {
				byte_offset,
				capacity_bytes,
			});
		}
		self.cursor_bytes = byte_offset;
		Ok(())
	}

	pub fn read_data(&mut self, len: usize) -> Result<Vec<u8>, JpegFileError> {
		if len > self.remaining_bytes() {
			return Err(JpegFileError::ReadOutOfCapacity {
				requested_bytes: len,
				available_bytes: self.remaining_bytes(),
			});
		}

		let mut out = vec![0u8; len];
		let read = self.strategy.read(
			&self.jpeg.owned_jpeg,
			&self.jpeg.bit_slots,
			self.data_start_slot,
			self.cursor_bytes,
			&mut out,
		);
		debug_assert_eq!(read, len);
		self.cursor_bytes += read;
		Ok(out)
	}

	pub fn write_data(&mut self, data: &[u8]) -> Result<(), JpegFileError> {
		if data.len() > self.remaining_bytes() {
			return Err(JpegFileError::WriteOutOfCapacity {
				requested_bytes: data.len(),
				available_bytes: self.remaining_bytes(),
			});
		}

		let written = self.strategy.write(
			&mut self.jpeg.owned_jpeg,
			&self.jpeg.bit_slots,
			self.data_start_slot,
			self.cursor_bytes,
			data,
		);
		debug_assert_eq!(written, data.len());
		self.cursor_bytes += written;
		self.jpeg.dirty = true;
		Ok(())
	}

	pub fn into_jpeg_session(self) -> JpegSession {
		self.jpeg
	}

	pub fn to_jpeg_bytes(&self) -> Result<Vec<u8>, JpegFileError> {
		self.jpeg.to_jpeg_bytes()
	}
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

	pub fn into_embedding_session(self, embedding_strategy_id: EmbeddingStrategyId) -> EmbeddingSession {
		EmbeddingSession {
			jpeg: self,
			strategy: strategy_from_id(embedding_strategy_id),
			cursor_bytes: 0,
			data_start_slot: STRATEGY_MARKER_SIZE * 8,
		}
	}

	/// Creates an in-memory session not backed by any file.
	/// `flush()` must not be called on sessions created this way.
	pub fn in_memory(source_jpeg: Vec<u8>) -> Result<Self, JpegFileError> {
		Self::new(PathBuf::new(), source_jpeg)
	}

	pub fn read_strategy_marker_lsb(&mut self) -> Result<u8, JpegFileError> {
		let cursor_bits = self.cursor_bits;
		self.seek(0)?;
		let result = self.read_data(STRATEGY_MARKER_SIZE).map(|data| data[0]);
		self.cursor_bits = cursor_bits;
		result
	}

	pub fn write_strategy_marker_lsb(&mut self, marker: u8) -> Result<(), JpegFileError> {
		let cursor_bits = self.cursor_bits;
		self.seek(0)?;
		let result = self.write_data(&[marker]);
		self.cursor_bits = cursor_bits;
		result
	}

	fn seek_bits(&mut self, bit_offset: usize) -> Result<(), JpegFileError> {
		if bit_offset > self.bit_slots.len() {
			return Err(JpegFileError::BitOffsetOutOfRange {
				bit_offset,
				capacity_bits: self.bit_slots.len(),
			});
		}
		self.cursor_bits = bit_offset;
		Ok(())
	}

	fn seek(&mut self, byte_offset: usize) -> Result<(), JpegFileError> {
		self.seek_bits(byte_offset * 8)
	}

	fn remaining_bytes(&self) -> usize {
		(self.bit_slots.len().saturating_sub(self.cursor_bits)) / 8
	}

	fn read(&mut self, out: &mut [u8]) -> usize {
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

	fn write(&mut self, data: &[u8]) -> usize {
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

	fn read_data(&mut self, len: usize) -> Result<Vec<u8>, JpegFileError> {
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

	fn write_data(&mut self, data: &[u8]) -> Result<(), JpegFileError> {
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

	/// Re-encodes the (possibly modified) DCT coefficients into JPEG bytes without
	/// writing to disk.
	pub fn to_jpeg_bytes(&self) -> Result<Vec<u8>, JpegFileError> {
		Ok(unsafe { write_owned_jpeg(&self.source_jpeg, &self.owned_jpeg)? })
	}

	pub fn flush(&mut self) -> Result<(), JpegFileError> {
		if !self.dirty {
			return Ok(());
		}

		let output_jpeg = self.to_jpeg_bytes()?;

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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::jpeg::OwnedComponent;
	fn dummy_session() -> JpegSession {
		dummy_session_with_bit_slots(8)
	}

	fn dummy_session_with_bit_slots(bit_slot_count: usize) -> JpegSession {
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
				bit_slot_count
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

	#[test]
	fn embedding_session_reports_zero_capacity_when_marker_slots_exceed_capacity() {
		let session = dummy_session_with_bit_slots(STRATEGY_MARKER_SIZE * 8 - 1);
		let mut embedding_session = session.into_embedding_session(EmbeddingStrategyId::Lsb);

		assert_eq!(embedding_session.data_slot_count(), 0);
		assert_eq!(embedding_session.remaining_bytes(), 0);

		let seek_err = embedding_session
			.seek(1)
			.expect_err("seeking past zero data capacity should fail");
		assert!(matches!(
			seek_err,
			JpegFileError::ByteOffsetOutOfRange {
				byte_offset: 1,
				capacity_bytes: 0
			}
		));

		let read_err = embedding_session
			.read_data(1)
			.expect_err("reading from zero data capacity should fail");
		assert!(matches!(
			read_err,
			JpegFileError::ReadOutOfCapacity {
				requested_bytes: 1,
				available_bytes: 0
			}
		));

		let write_err = embedding_session
			.write_data(&[1])
			.expect_err("writing to zero data capacity should fail");
		assert!(matches!(
			write_err,
			JpegFileError::WriteOutOfCapacity {
				requested_bytes: 1,
				available_bytes: 0
			}
		));
	}
}
