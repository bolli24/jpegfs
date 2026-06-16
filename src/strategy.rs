use std::fmt;
use std::str::FromStr;

use crate::crypto::CryptoError;
use crate::jpeg::{BlockData, OwnedJpeg};
use crate::jpeg_file::{BitSlot, BitSlotSearchStart};
use crate::lsb::{get_lsb, is_embeddable_coeff, read_bit_from_bytes, set_lsb};
use crate::matrix_strategy::{MatrixMode, MatrixStrategy};
use crate::zigzag::{RESERVED_ZIGZAG_COEFFS, ZIGZAG_INDICES};

pub fn iter_coefficients<F>(
	owned_jpeg: &OwnedJpeg,
	start: BitSlotSearchStart,
	skip_zigzag_coeffs: usize,
	mut for_each: F,
) where
	F: FnMut(&BlockData, usize, usize, usize) -> bool,
{
	let components = &owned_jpeg.components;

	'outer: for component_index in start.component_index..components.len() {
		let component = &components[component_index];

		let block_start = if component_index == start.component_index {
			start.block_index
		} else {
			0
		};

		for block_index in block_start..component.blocks.len() {
			let block = &component.blocks[block_index];

			let zigzag_start = if component_index == start.component_index && block_index == start.block_index {
				usize::max(skip_zigzag_coeffs, start.zigzag_index)
			} else {
				skip_zigzag_coeffs
			};

			for &coeff_index in ZIGZAG_INDICES.iter().skip(zigzag_start) {
				if !for_each(block, component_index, block_index, coeff_index) {
					break 'outer;
				}
			}
		}
	}
}

pub fn iter_coefficients_mut<F>(
	owned_jpeg: &mut OwnedJpeg,
	start: BitSlotSearchStart,
	skip_zigzag_coeffs: usize,
	mut for_each: F,
) where
	F: FnMut(&mut BlockData, usize, usize, usize) -> bool,
{
	let components = &mut owned_jpeg.components;

	'outer: for component_index in start.component_index..components.len() {
		let component = &mut components[component_index];

		let block_start = if component_index == start.component_index {
			start.block_index
		} else {
			0
		};

		for block_index in block_start..component.blocks.len() {
			let block = &mut component.blocks[block_index];

			let zigzag_start = if component_index == start.component_index && block_index == start.block_index {
				usize::max(skip_zigzag_coeffs, start.zigzag_index)
			} else {
				skip_zigzag_coeffs
			};

			for &coeff_index in ZIGZAG_INDICES.iter().skip(zigzag_start) {
				if !for_each(block, component_index, block_index, coeff_index) {
					break 'outer;
				}
			}
		}
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EmbeddingStrategyId {
	Lsb = 1,
	Lsb50 = 2,
	Matrix2 = 3,
	Matrix3 = 4,
	Matrix4 = 5,
	Matrix5 = 6,
	Matrix6 = 7,
	Matrix7 = 8,
}

impl TryFrom<u8> for EmbeddingStrategyId {
	type Error = CryptoError;

	fn try_from(id: u8) -> Result<Self, Self::Error> {
		match id {
			1 => Ok(Self::Lsb),
			2 => Ok(Self::Lsb50),
			3 => Ok(Self::Matrix2),
			4 => Ok(Self::Matrix3),
			5 => Ok(Self::Matrix4),
			6 => Ok(Self::Matrix5),
			7 => Ok(Self::Matrix6),
			8 => Ok(Self::Matrix7),
			_ => Err(CryptoError::UnsupportedEmbeddingStrategy { id }),
		}
	}
}

impl TryFrom<&str> for EmbeddingStrategyId {
	type Error = String;

	fn try_from(value: &str) -> Result<Self, Self::Error> {
		match value {
			"lsb" => Ok(EmbeddingStrategyId::Lsb),
			"lsb50" => Ok(EmbeddingStrategyId::Lsb50),
			"matrix" | "matrix5" => Ok(EmbeddingStrategyId::Matrix5),
			"matrix2" => Ok(EmbeddingStrategyId::Matrix2),
			"matrix3" => Ok(EmbeddingStrategyId::Matrix3),
			"matrix4" => Ok(EmbeddingStrategyId::Matrix4),
			"matrix6" => Ok(EmbeddingStrategyId::Matrix6),
			"matrix7" => Ok(EmbeddingStrategyId::Matrix7),
			_ => Err(format!("unsupported embedding strategy '{value}'")),
		}
	}
}

impl FromStr for EmbeddingStrategyId {
	type Err = String;

	fn from_str(value: &str) -> Result<Self, Self::Err> {
		Self::try_from(value)
	}
}

impl From<EmbeddingStrategyId> for u8 {
	fn from(id: EmbeddingStrategyId) -> Self {
		id as u8
	}
}

impl fmt::Display for EmbeddingStrategyId {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Lsb => write!(f, "lsb"),
			Self::Lsb50 => write!(f, "lsb50"),
			Self::Matrix2 => write!(f, "matrix2"),
			Self::Matrix3 => write!(f, "matrix3"),
			Self::Matrix4 => write!(f, "matrix4"),
			Self::Matrix5 => write!(f, "matrix5"),
			Self::Matrix6 => write!(f, "matrix6"),
			Self::Matrix7 => write!(f, "matrix7"),
		}
	}
}

impl EmbeddingStrategyId {
	pub const ALL: [Self; 8] = [
		Self::Lsb,
		Self::Lsb50,
		Self::Matrix2,
		Self::Matrix3,
		Self::Matrix4,
		Self::Matrix5,
		Self::Matrix6,
		Self::Matrix7,
	];

	pub fn description(self) -> &'static str {
		match self {
			Self::Lsb => "use every embeddable coefficient",
			Self::Lsb50 => "use every second embeddable coefficient",
			Self::Matrix2 => "matrix encoding strategy (k=2)",
			Self::Matrix3 => "matrix encoding strategy (k=3)",
			Self::Matrix4 => "matrix encoding strategy (k=4)",
			Self::Matrix5 => "matrix encoding strategy (k=5)",
			Self::Matrix6 => "matrix encoding strategy (k=6)",
			Self::Matrix7 => "matrix encoding strategy (k=7)",
		}
	}

	pub fn matrix_mode(self) -> Option<MatrixMode> {
		let k = match self {
			Self::Matrix2 => 2,
			Self::Matrix3 => 3,
			Self::Matrix4 => 4,
			Self::Matrix5 => 5,
			Self::Matrix6 => 6,
			Self::Matrix7 => 7,
			Self::Lsb | Self::Lsb50 => return None,
		};
		MatrixMode::new(k)
	}
}

pub fn strategy_from_id(id: EmbeddingStrategyId, seed: [u8; 32]) -> Box<dyn EmbeddingStrategy> {
	match id {
		EmbeddingStrategyId::Lsb => Box::new(LsbStrategy),
		EmbeddingStrategyId::Lsb50 => Box::new(Lsb50Strategy),
		EmbeddingStrategyId::Matrix2
		| EmbeddingStrategyId::Matrix3
		| EmbeddingStrategyId::Matrix4
		| EmbeddingStrategyId::Matrix5
		| EmbeddingStrategyId::Matrix6
		| EmbeddingStrategyId::Matrix7 => Box::new(MatrixStrategy(id.matrix_mode().expect("matrix mode is valid"), seed)),
	}
}

pub trait EmbeddingStrategy {
	fn id(&self) -> EmbeddingStrategyId;

	fn capacity_bytes(&self, slots_count: usize) -> usize;

	fn slots_for_bytes(&self, byte_count: usize) -> usize;

	fn collect_bit_slots(&self, jpeg: &OwnedJpeg, start_slot: BitSlotSearchStart) -> Vec<BitSlot>;

	fn read(&self, jpeg: &OwnedJpeg, slots: &[BitSlot], out: &mut [u8]) -> usize;

	fn write(&self, jpeg: &mut OwnedJpeg, slots: &[BitSlot], data: &[u8]) -> usize;
}

pub struct LsbStrategy;

impl EmbeddingStrategy for LsbStrategy {
	fn id(&self) -> EmbeddingStrategyId {
		EmbeddingStrategyId::Lsb
	}

	fn capacity_bytes(&self, slot_count: usize) -> usize {
		lsb_capacity_bytes(slot_count, 1)
	}

	fn slots_for_bytes(&self, byte_count: usize) -> usize {
		lsb_slots_for_bytes(byte_count, 1)
	}

	fn collect_bit_slots(&self, jpeg: &OwnedJpeg, start_slot: BitSlotSearchStart) -> Vec<BitSlot> {
		collect_lsb_bit_slots(jpeg, start_slot, 0)
	}

	fn read(&self, jpeg: &OwnedJpeg, slots: &[BitSlot], out: &mut [u8]) -> usize {
		read_lsb_with_stride(jpeg, slots, out, 1)
	}

	fn write(&self, jpeg: &mut OwnedJpeg, slots: &[BitSlot], data: &[u8]) -> usize {
		write_lsb_with_stride(jpeg, slots, data, 1)
	}
}

pub struct Lsb50Strategy;

impl EmbeddingStrategy for Lsb50Strategy {
	fn id(&self) -> EmbeddingStrategyId {
		EmbeddingStrategyId::Lsb50
	}

	fn capacity_bytes(&self, slot_count: usize) -> usize {
		lsb_capacity_bytes(slot_count, 2)
	}

	fn slots_for_bytes(&self, byte_count: usize) -> usize {
		lsb_slots_for_bytes(byte_count, 2)
	}

	fn collect_bit_slots(&self, jpeg: &OwnedJpeg, start_slot: BitSlotSearchStart) -> Vec<BitSlot> {
		collect_lsb_bit_slots(jpeg, start_slot, 0)
	}

	fn read(&self, jpeg: &OwnedJpeg, slots: &[BitSlot], out: &mut [u8]) -> usize {
		read_lsb_with_stride(jpeg, slots, out, 2)
	}

	fn write(&self, jpeg: &mut OwnedJpeg, slots: &[BitSlot], data: &[u8]) -> usize {
		write_lsb_with_stride(jpeg, slots, data, 2)
	}
}

fn lsb_capacity_bytes(slot_count: usize, stride: usize) -> usize {
	slot_count / (8 * stride)
}

fn lsb_slots_for_bytes(byte_count: usize, stride: usize) -> usize {
	byte_count * 8 * stride
}

fn read_lsb_with_stride(jpeg: &OwnedJpeg, slots: &[BitSlot], out: &mut [u8], stride: usize) -> usize {
	let capacity_bytes = lsb_capacity_bytes(slots.len(), stride);
	let n = out.len().min(capacity_bytes);
	out[..n].fill(0);

	for (byte_idx, out_byte) in out[..n].iter_mut().enumerate() {
		for bit_in_byte in 0..8usize {
			let logical_bit = (byte_idx * 8) + bit_in_byte;
			let slot = slots[logical_bit * stride];
			let coeff = jpeg.components[slot.component_index as usize].blocks[slot.block_index as usize]
				[slot.coeff_index as usize];
			let bit = get_lsb(coeff);
			if bit == 1 {
				*out_byte |= 1 << (7 - bit_in_byte);
			}
		}
	}

	n
}

fn write_lsb_with_stride(jpeg: &mut OwnedJpeg, slots: &[BitSlot], data: &[u8], stride: usize) -> usize {
	let capacity_bytes = lsb_capacity_bytes(slots.len(), stride);
	let n = data.len().min(capacity_bytes);

	for byte_idx in 0..n {
		for bit_in_byte in 0..8usize {
			let logical_bit = (byte_idx * 8) + bit_in_byte;
			let slot = slots[logical_bit * stride];
			let bit = read_bit_from_bytes(data, (byte_idx * 8) + bit_in_byte).unwrap_or(0);
			let coeff = &mut jpeg.components[slot.component_index as usize].blocks[slot.block_index as usize]
				[slot.coeff_index as usize];
			*coeff = set_lsb(*coeff, bit);
		}
	}

	n
}

pub fn collect_lsb_bit_slots(owned_jpeg: &OwnedJpeg, start: BitSlotSearchStart, limit: usize) -> Vec<BitSlot> {
	let mut bit_slots = Vec::new();

	iter_coefficients(
		owned_jpeg,
		start,
		RESERVED_ZIGZAG_COEFFS,
		|block: &BlockData, component_index: usize, block_index: usize, coeff_index: usize| -> bool {
			if is_embeddable_coeff(block[coeff_index]) {
				bit_slots.push(BitSlot {
					component_index: component_index as u32,
					block_index: block_index as u32,
					coeff_index: coeff_index as u32,
				});
				if limit != 0 && bit_slots.len() == limit {
					return false;
				}
			}
			true
		},
	);

	if limit != 0 {
		bit_slots.truncate(limit);
	}

	bit_slots
}
