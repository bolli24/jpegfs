use crate::jpeg::{Block, BlockData};
use crate::zigzag::ZigZagExt;
use crate::{BlockReader, BlockWriter};

fn set_lsb(coeff: i16, bit: u8) -> i16 {
	let is_skipped = |c: i16| matches!(c, -1..=1);
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

pub struct LsbReader {
	data_bits: BitWriter,
	remaining: usize,
}

impl LsbReader {
	pub fn new(len: usize) -> Self {
		Self {
			data_bits: BitWriter::new(),
			remaining: len * 8,
		}
	}

	pub fn finish(self) -> Vec<u8> {
		self.data_bits.finish()
	}
}

impl BlockReader for LsbReader {
	fn read_block(&mut self, _block: Block, coeffs: &BlockData) {
		for c in coeffs.zigzag().skip(5) {
			if self.remaining == 0 {
				break;
			}
			if *c != -1 && *c != 0 && *c != 1 {
				self.data_bits.write_bit(get_lsb(*c));
				self.remaining -= 1;
			}
		}
	}
}

pub struct LsbWriter<'a> {
	data_bits: BitReader<'a>,
	done: bool,
}

impl<'a> LsbWriter<'a> {
	pub fn new(data: &'a [u8]) -> Self {
		Self {
			data_bits: BitReader::new(data),
			done: false,
		}
	}
}

impl BlockWriter for LsbWriter<'_> {
	fn write_block(&mut self, _block: Block, coeffs: &mut BlockData) {
		if self.done {
			return;
		}

		for c in coeffs.zigzag_mut().skip(5) {
			if *c == -1 || *c == 0 || *c == 1 {
				continue;
			}

			if let Some(bit) = self.data_bits.read_bit() {
				*c = set_lsb(*c, bit);
			} else {
				self.done = true;
				break;
			}
		}
	}
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

struct BitWriter {
	out: Vec<u8>,
	cur: u8,
	nbits: u8,
}

impl BitWriter {
	fn new() -> Self {
		Self {
			out: Vec::new(),
			cur: 0,
			nbits: 0,
		}
	}

	fn write_bit(&mut self, bit: u8) {
		self.cur = (self.cur << 1) | (bit & 1);
		self.nbits += 1;

		if self.nbits == 8 {
			self.out.push(self.cur);
			self.cur = 0;
			self.nbits = 0;
		}
	}

	fn finish(mut self) -> Vec<u8> {
		if self.nbits != 0 {
			self.cur <<= 8 - self.nbits;
			self.out.push(self.cur);
			self.cur = 0;
			self.nbits = 0;
		}
		self.out
	}
}
