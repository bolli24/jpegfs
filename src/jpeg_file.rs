use std::io::{Seek, Write};
use std::path::{Path, PathBuf};
use std::{fs, fs::File, io::Read};

use anyhow::{Context, bail};

use crate::jpeg::{OwnedJpeg, get_capacity, read_owned_jpeg, write_owned_jpeg};
use crate::lsb::{ensure_byte_aligned, get_lsb, is_embeddable_coeff, read_bit_from_bytes, set_lsb};
use crate::zigzag::ZIGZAG_INDICES;

pub fn init_file(path: &Path) -> anyhow::Result<JpegFileHandle> {
	let mut file = File::open(path).context("failed to open input file")?;

	let content = JpegFileHandle::read_all_from_file(&mut file)?;
	let capacity = get_capacity(&content).context("failed to compute capacity")?;
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
struct BitSlot {
	component_index: usize,
	block_index: usize,
	coeff_index: usize,
}

impl JpegSession {
	pub fn new(path: PathBuf, source_jpeg: Vec<u8>) -> anyhow::Result<Self> {
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

	pub fn seek_bits(&mut self, bit_offset: usize) -> anyhow::Result<()> {
		if bit_offset > self.bit_slots.len() {
			bail!(
				"bit offset {} exceeds available capacity of {} bits",
				bit_offset,
				self.bit_slots.len()
			);
		}
		self.cursor_bits = bit_offset;
		Ok(())
	}

	pub fn seek(&mut self, byte_offset: usize) -> anyhow::Result<()> {
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

	pub fn read_data(&mut self, len: usize) -> anyhow::Result<Vec<u8>> {
		ensure_byte_aligned(self.cursor_bits)?;
		if len > self.remaining_bytes() {
			bail!(
				"requested {} KiB exceeds available capacity of {} KiB",
				len / 1024,
				self.remaining_bytes() / 1024
			);
		}

		let mut out = vec![0u8; len];
		let read = self.read(&mut out);
		debug_assert_eq!(read, len);
		Ok(out)
	}

	pub fn write_data(&mut self, data: &[u8]) -> anyhow::Result<()> {
		ensure_byte_aligned(self.cursor_bits)?;
		if data.len() > self.remaining_bytes() {
			bail!(
				"not enough capacity to write {} KiB; only {} KiB available",
				data.len() / 1024,
				self.remaining_bytes() / 1024
			);
		}

		let written = self.write(data);
		debug_assert_eq!(written, data.len());
		Ok(())
	}

	pub fn flush(&mut self) -> anyhow::Result<()> {
		if !self.dirty {
			return Ok(());
		}

		let output_jpeg = unsafe { write_owned_jpeg(&self.source_jpeg, &self.owned_jpeg)? };

		let mut output_file =
			File::create(&self.path).with_context(|| format!("failed to create '{}'", self.path.display()))?;
		output_file
			.write_all(&output_jpeg)
			.context("failed to write output file")?;

		println!("Wrote '{}': {}KiB", self.path.display(), output_jpeg.len() / 1024);

		self.source_jpeg = output_jpeg;
		self.dirty = false;
		Ok(())
	}

	fn collect_bit_slots(owned_jpeg: &OwnedJpeg) -> Vec<BitSlot> {
		let mut bit_slots = Vec::new();
		for (component_index, component) in owned_jpeg.components.iter().enumerate() {
			for (block_index, block) in component.blocks.iter().enumerate() {
				for &coeff_index in ZIGZAG_INDICES.iter().skip(5) {
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

	fn read_all_from_file(file: &mut File) -> anyhow::Result<Vec<u8>> {
		file.rewind().context("failed to rewind input file")?;
		let mut content = Vec::<u8>::new();
		file.read_to_end(&mut content).context("failed to read input file")?;
		Ok(content)
	}

	fn read_all(&mut self) -> anyhow::Result<Vec<u8>> {
		Self::read_all_from_file(&mut self.file)
	}

	pub fn copy_to(&self, target_path: &Path) -> anyhow::Result<JpegFileHandle> {
		fs::copy(&self.path, target_path).with_context(|| {
			format!(
				"failed to copy '{}' to '{}'",
				self.path.display(),
				target_path.display()
			)
		})?;
		init_file(target_path)
	}

	pub fn write_data(&mut self, data: &[u8]) -> anyhow::Result<()> {
		let input_jpeg = self.read_all()?;
		let mut session = JpegSession::new(self.path.clone(), input_jpeg)?;
		session.seek(0)?;
		session.write_data(data)?;
		session.flush()?;

		Ok(())
	}

	pub fn read_data(&mut self, len: usize) -> anyhow::Result<Vec<u8>> {
		let input_jpeg = self.read_all()?;
		let mut session = JpegSession::new(self.path.clone(), input_jpeg)?;
		session.seek(0)?;
		session.read_data(len)
	}
}
