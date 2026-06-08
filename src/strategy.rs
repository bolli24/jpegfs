use std::fmt;

use crate::crypto::CryptoError;
use crate::f5_strategy::F5Strategy;
use crate::jpeg::OwnedJpeg;
use crate::jpeg_file::BitSlot;
use crate::lsb::{get_lsb, read_bit_from_bytes, set_lsb};

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

	fn read(&self, jpeg: &OwnedJpeg, slots: &[BitSlot], start_slot: usize, byte_offset: usize, out: &mut [u8])
	-> usize;

	fn write(
		&self,
		jpeg: &mut OwnedJpeg,
		slots: &[BitSlot],
		start_slot: usize,
		byte_offset: usize,
		data: &[u8],
	) -> usize;
}

pub struct LsbStrategy;

impl EmbeddingStrategy for LsbStrategy {
	fn id(&self) -> EmbeddingStrategyId {
		EmbeddingStrategyId::Lsb
	}

	fn capacity_bytes(&self, slot_count: usize) -> usize {
		lsb_capacity_bytes(slot_count, 1)
	}

	fn read(
		&self,
		jpeg: &OwnedJpeg,
		slots: &[BitSlot],
		start_slot: usize,
		byte_offset: usize,
		out: &mut [u8],
	) -> usize {
		read_lsb_with_stride(jpeg, slots, start_slot, byte_offset, out, 1)
	}

	fn write(
		&self,
		jpeg: &mut OwnedJpeg,
		slots: &[BitSlot],
		start_slot: usize,
		byte_offset: usize,
		data: &[u8],
	) -> usize {
		write_lsb_with_stride(jpeg, slots, start_slot, byte_offset, data, 1)
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

	fn read(
		&self,
		jpeg: &OwnedJpeg,
		slots: &[BitSlot],
		start_slot: usize,
		byte_offset: usize,
		out: &mut [u8],
	) -> usize {
		read_lsb_with_stride(jpeg, slots, start_slot, byte_offset, out, 2)
	}

	fn write(
		&self,
		jpeg: &mut OwnedJpeg,
		slots: &[BitSlot],
		start_slot: usize,
		byte_offset: usize,
		data: &[u8],
	) -> usize {
		write_lsb_with_stride(jpeg, slots, start_slot, byte_offset, data, 2)
	}
}

fn lsb_capacity_bytes(slot_count: usize, stride: usize) -> usize {
	slot_count / (8 * stride)
}

fn read_lsb_with_stride(
	jpeg: &OwnedJpeg,
	slots: &[BitSlot],
	start_slot: usize,
	byte_offset: usize,
	out: &mut [u8],
	stride: usize,
) -> usize {
	let capacity_bytes = lsb_capacity_bytes(slots.len().saturating_sub(start_slot), stride);
	let n = out.len().min(capacity_bytes.saturating_sub(byte_offset));
	out[..n].fill(0);

	for (byte_idx, out_byte) in out[..n].iter_mut().enumerate() {
		for bit_in_byte in 0..8usize {
			let logical_bit = ((byte_offset + byte_idx) * 8) + bit_in_byte;
			let slot = slots[start_slot + logical_bit * stride];
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
	start_slot: usize,
	byte_offset: usize,
	data: &[u8],
	stride: usize,
) -> usize {
	let capacity_bytes = lsb_capacity_bytes(slots.len().saturating_sub(start_slot), stride);
	let n = data.len().min(capacity_bytes.saturating_sub(byte_offset));

	for byte_idx in 0..n {
		for bit_in_byte in 0..8usize {
			let logical_bit = ((byte_offset + byte_idx) * 8) + bit_in_byte;
			let slot = slots[start_slot + logical_bit * stride];
			let bit = read_bit_from_bytes(data, (byte_idx * 8) + bit_in_byte).unwrap_or(0);
			let coeff = &mut jpeg.components[slot.component_index].blocks[slot.block_index][slot.coeff_index];
			*coeff = set_lsb(*coeff, bit);
		}
	}

	n
}
