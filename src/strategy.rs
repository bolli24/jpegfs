use std::fmt;
use std::str::FromStr;

use crate::crypto::CryptoError;
use crate::f5_strategy::F5Strategy;
use crate::jpeg::OwnedJpeg;
use crate::jpeg_file::{BitSlot, BitSlotSearchStart};
use crate::lsb::{get_lsb, is_embeddable_coeff, read_bit_from_bytes, set_lsb};
use crate::zigzag::{RESERVED_ZIGZAG_COEFFS, ZIGZAG_INDICES};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EmbeddingStrategyId {
	Lsb = 1,
	Lsb50 = 2,
	F5 = 3,
}

impl TryFrom<u8> for EmbeddingStrategyId {
	type Error = CryptoError;

	fn try_from(id: u8) -> Result<Self, Self::Error> {
		match id {
			1 => Ok(Self::Lsb),
			2 => Ok(Self::Lsb50),
			3 => Ok(Self::F5),
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
			"f5" => Ok(EmbeddingStrategyId::F5),
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
			Self::F5 => write!(f, "f5"),
		}
	}
}

impl EmbeddingStrategyId {
	pub const ALL: [Self; 2] = [Self::Lsb, Self::Lsb50];

	pub fn description(self) -> &'static str {
		match self {
			Self::Lsb => "use every embeddable coefficient",
			Self::Lsb50 => "use every second embeddable coefficient",
			Self::F5 => "implementation of F5 algorithm",
		}
	}
}

pub fn strategy_from_id(id: EmbeddingStrategyId) -> Box<dyn EmbeddingStrategy> {
	match id {
		EmbeddingStrategyId::Lsb => Box::new(LsbStrategy),
		EmbeddingStrategyId::Lsb50 => Box::new(Lsb50Strategy),
		EmbeddingStrategyId::F5 => Box::new(F5Strategy),
	}
}

pub trait EmbeddingStrategy {
	fn id(&self) -> EmbeddingStrategyId;

	fn capacity_bytes(&self, slots_count: usize) -> usize;

	fn collect_bit_slots(&self, jpeg: &OwnedJpeg, start_slot: BitSlotSearchStart) -> Vec<BitSlot>;

	fn read(&self, jpeg: &OwnedJpeg, slots: &[BitSlot], byte_offset: usize, out: &mut [u8]) -> usize;

	fn write(&self, jpeg: &mut OwnedJpeg, slots: &[BitSlot], byte_offset: usize, data: &[u8]) -> usize;
}

pub struct LsbStrategy;

impl EmbeddingStrategy for LsbStrategy {
	fn id(&self) -> EmbeddingStrategyId {
		EmbeddingStrategyId::Lsb
	}

	fn capacity_bytes(&self, slot_count: usize) -> usize {
		lsb_capacity_bytes(slot_count, 1)
	}

	fn collect_bit_slots(&self, jpeg: &OwnedJpeg, start_slot: BitSlotSearchStart) -> Vec<BitSlot> {
		collect_lsb_bit_slots(jpeg, start_slot, 0)
	}

	fn read(&self, jpeg: &OwnedJpeg, slots: &[BitSlot], byte_offset: usize, out: &mut [u8]) -> usize {
		read_lsb_with_stride(jpeg, slots, byte_offset, out, 1)
	}

	fn write(&self, jpeg: &mut OwnedJpeg, slots: &[BitSlot], byte_offset: usize, data: &[u8]) -> usize {
		write_lsb_with_stride(jpeg, slots, byte_offset, data, 1)
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

	fn collect_bit_slots(&self, jpeg: &OwnedJpeg, start_slot: BitSlotSearchStart) -> Vec<BitSlot> {
		collect_lsb_bit_slots(jpeg, start_slot, 0)
	}

	fn read(&self, jpeg: &OwnedJpeg, slots: &[BitSlot], byte_offset: usize, out: &mut [u8]) -> usize {
		read_lsb_with_stride(jpeg, slots, byte_offset, out, 2)
	}

	fn write(&self, jpeg: &mut OwnedJpeg, slots: &[BitSlot], byte_offset: usize, data: &[u8]) -> usize {
		write_lsb_with_stride(jpeg, slots, byte_offset, data, 2)
	}
}

fn lsb_capacity_bytes(slot_count: usize, stride: usize) -> usize {
	slot_count / (8 * stride)
}

fn read_lsb_with_stride(
	jpeg: &OwnedJpeg,
	slots: &[BitSlot],
	byte_offset: usize,
	out: &mut [u8],
	stride: usize,
) -> usize {
	let capacity_bytes = lsb_capacity_bytes(slots.len(), stride);
	let n = out.len().min(capacity_bytes.saturating_sub(byte_offset));
	out[..n].fill(0);

	for (byte_idx, out_byte) in out[..n].iter_mut().enumerate() {
		for bit_in_byte in 0..8usize {
			let logical_bit = ((byte_offset + byte_idx) * 8) + bit_in_byte;
			let slot = slots[logical_bit * stride];
			let coeff = jpeg.components[slot.component_index].blocks[slot.block_index][slot.coeff_index];
			let bit = get_lsb(coeff);
			if bit == 1 {
				*out_byte |= 1 << (7 - bit_in_byte);
			}
		}
	}

	n
}

fn write_lsb_with_stride(
	jpeg: &mut OwnedJpeg,
	slots: &[BitSlot],
	byte_offset: usize,
	data: &[u8],
	stride: usize,
) -> usize {
	let capacity_bytes = lsb_capacity_bytes(slots.len(), stride);
	let n = data.len().min(capacity_bytes.saturating_sub(byte_offset));

	for byte_idx in 0..n {
		for bit_in_byte in 0..8usize {
			let logical_bit = ((byte_offset + byte_idx) * 8) + bit_in_byte;
			let slot = slots[logical_bit * stride];
			let bit = read_bit_from_bytes(data, (byte_idx * 8) + bit_in_byte).unwrap_or(0);
			let coeff = &mut jpeg.components[slot.component_index].blocks[slot.block_index][slot.coeff_index];
			*coeff = set_lsb(*coeff, bit);
		}
	}

	n
}

pub fn collect_lsb_bit_slots(owned_jpeg: &OwnedJpeg, start: BitSlotSearchStart, limit: usize) -> Vec<BitSlot> {
	let mut bit_slots = Vec::new();
	let components = &owned_jpeg.components;

	for component_index in start.component_index..components.len() {
		let component = &components[component_index];

		let block_start = if component_index == start.component_index {
			start.block_index
		} else {
			0
		};

		for block_index in block_start..component.blocks.len() {
			let block = &component.blocks[block_index];

			let zigzag_start = if component_index == start.component_index && block_index == start.block_index {
				usize::max(RESERVED_ZIGZAG_COEFFS, start.zigzag_index)
			} else {
				RESERVED_ZIGZAG_COEFFS
			};

			for &coeff_index in ZIGZAG_INDICES.iter().skip(zigzag_start) {
				if is_embeddable_coeff(block[coeff_index]) {
					bit_slots.push(BitSlot {
						component_index,
						block_index,
						coeff_index,
					});
					if limit != 0 && bit_slots.len() == limit {
						return bit_slots;
					}
				}
			}
		}
	}
	bit_slots
}
