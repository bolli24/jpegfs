#![allow(unsafe_op_in_unsafe_fn, dead_code)]

use std::io::{Seek, Write};
use std::path::{Path, PathBuf};
use std::{fs, fs::File, io::Read};

use anyhow::{Context, bail};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha256::digest;

use crate::jpeg::{Block, BlockData, get_capacity, process_jpeg_blocks, read_jpeg_blocks};
use crate::zigzag::ZigZagExt;

pub mod jpeg;
pub mod zigzag;

const INPUT_PATH: &str = "./test/CRW_2614_(Elsterflutbecken).jpg";
const OUTPUT_PATH: &str = "./test/output.jpg";

fn main() -> anyhow::Result<()> {
	let file_info = init_file(PathBuf::from(INPUT_PATH).as_path())?;
	let mut output_file_info = file_info.copy_to(PathBuf::from(OUTPUT_PATH).as_path())?;
	let data = vec![1, 2, 3, 4];
	output_file_info.write_data(&data)?;

	let read_data = output_file_info.read_data(data.len())?;

	println!("Read data: {read_data:?}");

	Ok(())
}

pub fn init_file(path: &Path) -> anyhow::Result<FileInfo> {
	let mut file = File::open(path).context("Error opening input file.")?;

	let content = FileInfo::read_all_from_file(&mut file)?;
	let capacity = get_capacity(&content).context("Error getting capacity.")?;
	println!("Opened file '{}' capacity: {}", path.display(), capacity);

	Ok(FileInfo {
		file,
		path: path.to_owned(),
		capacity,
	})
}

pub struct FileInfo {
	file: File,
	path: PathBuf,
	capacity: usize,
}

fn set_lsb(coeff: i16, bit: u8) -> i16 {
	let is_skipped = |c: i16| matches!(c, -1 | 0 | 1);
	let target = (bit & 1) as i16;
	let current = coeff & 1;

	if current == target && !is_skipped(coeff) {
		return coeff;
	}

	let down = coeff.checked_sub(1).filter(|c| !is_skipped(*c) && ((*c & 1) == target));
	let up = coeff.checked_add(1).filter(|c| !is_skipped(*c) && ((*c & 1) == target));

	match (down, up) {
		(Some(d), Some(u)) => {
			if (u as i32).abs() < (d as i32).abs() {
				u
			} else {
				d
			}
		}
		(Some(d), None) => d,
		(None, Some(u)) => u,
		(None, None) => unreachable!("set_lsb called with a skipped coefficient"),
	}
}

fn get_lsb(coeff: i16) -> u8 {
	(coeff & 1) as u8
}

impl FileInfo {
	fn read_all_from_file(file: &mut File) -> anyhow::Result<Vec<u8>> {
		file.rewind().context("Error rewinding input file")?;
		let mut content = Vec::<u8>::new();
		file.read_to_end(&mut content).context("Error reading input file")?;
		Ok(content)
	}

	fn read_all(&mut self) -> anyhow::Result<Vec<u8>> {
		Self::read_all_from_file(&mut self.file)
	}

	pub fn copy_to(&self, target_path: &Path) -> anyhow::Result<FileInfo> {
		fs::copy(&self.path, target_path).with_context(|| {
			format!(
				"Error copying '{}' to '{}'.",
				self.path.display(),
				target_path.display()
			)
		})?;
		init_file(target_path)
	}

	pub fn write_data(&mut self, data: &[u8]) -> anyhow::Result<()> {
		if data.len() > self.capacity {
			bail!(
				"Not enough capacity to write {} KiB. Only {} KiB available.",
				data.len() / 1024,
				self.capacity / 1024
			);
		}

		let mut data_bits = BitReader::new(data);
		let mut done = false;

		let set_data_bits = |_: Block, coeffs: &mut BlockData| {
			if done {
				return;
			}

			for c in coeffs.zigzag_mut().skip(5) {
				if *c == -1 || *c == 0 || *c == 1 {
					continue;
				}

				if let Some(bit) = data_bits.read_bit() {
					*c = set_lsb(*c, bit);
				} else {
					done = true;
					break;
				}
			}
		};

		let input_jpeg = self.read_all()?;

		let output_jpeg = unsafe { process_jpeg_blocks(&input_jpeg, set_data_bits)? };

		let mut output_file =
			File::create(&self.path).with_context(|| format!("Error creating '{}'.", self.path.display()))?;
		output_file
			.write_all(&output_jpeg)
			.context("Error writing output file.")?;

		println!("Wrote '{}': {}KiB", self.path.display(), output_jpeg.len() / 1024);
		println!("SHA256: {}", digest(output_jpeg));

		Ok(())
	}

	pub fn read_data(&mut self, len: usize) -> anyhow::Result<Vec<u8>> {
		if len > self.capacity {
			bail!(
				"Requested {} KiB exceeds available capacity of {} KiB.",
				len / 1024,
				self.capacity / 1024
			);
		}

		let mut data_bits = BitWriter::new();
		let mut remaining = len * 8;

		let get_data_bits = |_: Block, coeffs: &BlockData| {
			for c in coeffs.zigzag().skip(5) {
				if remaining == 0 {
					break;
				}
				if *c != -1 && *c != 0 && *c != 1 {
					data_bits.write_bit(get_lsb(*c));
					remaining -= 1;
				}
			}
		};

		let input_jpeg = self.read_all()?;

		unsafe { read_jpeg_blocks(&input_jpeg, get_data_bits)? };

		Ok(data_bits.finish())
	}
}

pub fn rng_from_passphrase(passphrase: &str, salt: &[u8]) -> anyhow::Result<ChaCha20Rng> {
	let params = argon2::Params::new(
		19 * 1024, // m_cost in KiB (19 MiB)
		2,         // t_cost iterations
		1,         // p_cost parallelism
		Some(32),  // output length (seed size)
	)
	.expect("valid params");

	let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

	let mut seed = [0u8; 32];
	argon2
		.hash_password_into(passphrase.as_bytes(), salt, &mut seed)
		.context("Argon2 failed")?;

	Ok(ChaCha20Rng::from_seed(seed))
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Header {
	id: u32,
	capacity: usize,
}

struct BitReader<'a> {
	data: &'a [u8],
	byte_pos: usize,
	bit_pos: u8,
}

impl<'a> BitReader<'a> {
	fn new(data: &'a [u8]) -> Self {
		Self {
			data,
			byte_pos: 0,
			bit_pos: 0,
		}
	}

	fn read_bit(&mut self) -> Option<u8> {
		if self.byte_pos >= self.data.len() {
			return None;
		}

		let byte = self.data[self.byte_pos];
		let bit = (byte >> (7 - self.bit_pos)) & 1;

		self.bit_pos += 1;
		if self.bit_pos == 8 {
			self.bit_pos = 0;
			self.byte_pos += 1;
		}

		Some(bit)
	}
}

pub struct BitWriter {
	out: Vec<u8>,
	cur: u8,   // current byte being built
	nbits: u8, // number of bits currently in `cur` (0..=7)
}

impl BitWriter {
	pub fn new() -> Self {
		Self {
			out: Vec::new(),
			cur: 0,
			nbits: 0,
		}
	}

	pub fn with_capacity(cap: usize) -> Self {
		Self {
			out: Vec::with_capacity(cap),
			cur: 0,
			nbits: 0,
		}
	}

	/// Write a single bit (0 or 1). Bits are packed MSB-first within each byte.
	pub fn write_bit(&mut self, bit: u8) {
		self.cur = (self.cur << 1) | (bit & 1);
		self.nbits += 1;

		if self.nbits == 8 {
			self.out.push(self.cur);
			self.cur = 0;
			self.nbits = 0;
		}
	}

	/// Flush remaining bits to the output, padding the last byte with zeros on the right.
	pub fn finish(mut self) -> Vec<u8> {
		if self.nbits != 0 {
			self.cur <<= 8 - self.nbits;
			self.out.push(self.cur);
			self.cur = 0;
			self.nbits = 0;
		}
		self.out
	}

	pub fn as_bytes(&self) -> &[u8] {
		&self.out
	}

	pub fn into_inner(self) -> Vec<u8> {
		self.finish()
	}
}

impl Default for BitWriter {
	fn default() -> Self {
		Self::new()
	}
}
