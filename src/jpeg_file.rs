use crate::crypto::{STRATEGY_MARKER_SIZE, STRATEGY_MARKER_SLOTS};
use crate::jpeg::{JpegError, OwnedComponent, OwnedJpeg, read_owned_jpeg, write_owned_jpeg};
use crate::lsb::{get_lsb, set_lsb};
use crate::strategy::{EmbeddingStrategy, EmbeddingStrategyId, collect_lsb_bit_slots, strategy_from_id};
use crate::zigzag::ZIGZAG_INDICES;
use arrayvec::ArrayVec;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum JpegFileError {
	#[error(transparent)]
	Jpeg(#[from] JpegError),
	#[error("not enough capacity for strategy marker: required {required_slots} slots, available {available_slots}")]
	NotEnoughStrategyMarkerSlots {
		required_slots: usize,
		available_slots: usize,
	},
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
}

pub struct EmbeddingSession {
	jpeg: JpegSession,
	strategy: Box<dyn EmbeddingStrategy>,
	bit_slots: Vec<BitSlot>,
}

impl EmbeddingSession {
	pub fn capacity(&self) -> usize {
		self.strategy.capacity_bytes(self.data_slot_count())
	}

	pub fn data_slot_count(&self) -> usize {
		self.bit_slots.len()
	}

	pub fn bit_slots(&self) -> &[BitSlot] {
		&self.bit_slots
	}

	/// Read len bytes from the beginning
	pub fn read(&self, len: usize) -> Result<Vec<u8>, JpegFileError> {
		let capacity = self.capacity();
		if len > capacity {
			return Err(JpegFileError::ReadOutOfCapacity {
				requested_bytes: len,
				available_bytes: capacity,
			});
		}

		let mut out = vec![0u8; len];
		let read = self.strategy.read(&self.jpeg.owned_jpeg, &self.bit_slots, &mut out);
		debug_assert_eq!(read, len);
		Ok(out)
	}

	/// Write data bytes to the beginning
	pub fn write(&mut self, data: &[u8]) -> Result<(), JpegFileError> {
		let capacity = self.capacity();
		if data.len() > capacity {
			return Err(JpegFileError::WriteOutOfCapacity {
				requested_bytes: data.len(),
				available_bytes: capacity,
			});
		}

		let written = self.strategy.write(&mut self.jpeg.owned_jpeg, &self.bit_slots, data);
		debug_assert_eq!(written, data.len());
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
	source_jpeg: Vec<u8>,
	owned_jpeg: OwnedJpeg,
	strategy_marker_slots: [BitSlot; STRATEGY_MARKER_SLOTS],
	embed_search_start: BitSlotSearchStart,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BitSlot {
	pub component_index: u32,
	pub block_index: u32,
	pub coeff_index: u32,
}

/// Bit slot index for denoting where to start the search for the new know unused slots
/// eg. after strategy maker slots have been found
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BitSlotSearchStart {
	pub component_index: usize,
	pub block_index: usize,
	pub zigzag_index: usize,
}

impl JpegSession {
	pub fn new(source_jpeg: Vec<u8>) -> Result<Self, JpegFileError> {
		let owned_jpeg = unsafe { read_owned_jpeg(&source_jpeg)? };
		let (strategy_marker_slots, embed_search_start) = Self::strategy_marker_bitslots(&owned_jpeg)?;
		Ok(Self {
			source_jpeg,
			owned_jpeg,
			strategy_marker_slots,
			embed_search_start,
		})
	}

	pub fn into_embedding_session(
		self,
		embedding_strategy_id: EmbeddingStrategyId,
		seed: [u8; 32],
	) -> EmbeddingSession {
		let strategy = strategy_from_id(embedding_strategy_id, seed);
		EmbeddingSession {
			bit_slots: strategy.collect_bit_slots(&self.owned_jpeg, self.embed_search_start),
			jpeg: self,
			strategy,
		}
	}

	pub fn components(&self) -> &ArrayVec<OwnedComponent, 3> {
		&self.owned_jpeg.components
	}

	pub fn read_strategy_marker_lsb(&self) -> u8 {
		const { assert!(STRATEGY_MARKER_SIZE == 1) };
		let mut out_byte = 0u8;
		for bit_in_byte in 0..8usize {
			let slot = self.strategy_marker_slots[bit_in_byte];
			let coeff = self.owned_jpeg.components[slot.component_index as usize].blocks[slot.block_index as usize]
				[slot.coeff_index as usize];
			let bit = get_lsb(coeff);
			if bit == 1 {
				out_byte |= 1 << (7 - bit_in_byte);
			}
		}
		out_byte
	}

	pub fn write_strategy_marker_lsb(&mut self, marker: u8) {
		const { assert!(STRATEGY_MARKER_SIZE == 1) };
		for bit_in_byte in 0..8usize {
			let slot = self.strategy_marker_slots[bit_in_byte];
			let bit = (marker >> (7 - bit_in_byte)) & 1;
			let coeff = &mut self.owned_jpeg.components[slot.component_index as usize].blocks
				[slot.block_index as usize][slot.coeff_index as usize];
			*coeff = set_lsb(*coeff, bit);
		}
	}

	/// Re-encodes the (possibly modified) DCT coefficients into JPEG bytes without
	/// writing to disk.
	pub fn to_jpeg_bytes(&self) -> Result<Vec<u8>, JpegFileError> {
		Ok(unsafe { write_owned_jpeg(&self.source_jpeg, &self.owned_jpeg)? })
	}

	/// Returns exactly the required amount of bit slots for the purpose of embedding the strategy marker
	/// and where it is safe to start searching for new bitslots e.g. for the actual embedding
	/// Errors if not enough bit slots could be found.
	fn strategy_marker_bitslots(
		jpeg: &OwnedJpeg,
	) -> Result<([BitSlot; STRATEGY_MARKER_SLOTS], BitSlotSearchStart), JpegFileError> {
		let slots_vec = collect_lsb_bit_slots(jpeg, BitSlotSearchStart::default(), STRATEGY_MARKER_SLOTS);
		let count = slots_vec.len();
		debug_assert!(count <= STRATEGY_MARKER_SLOTS);

		let slots: [BitSlot; STRATEGY_MARKER_SLOTS] =
			slots_vec
				.try_into()
				.map_err(|_| JpegFileError::NotEnoughStrategyMarkerSlots {
					required_slots: STRATEGY_MARKER_SLOTS,
					available_slots: count,
				})?;

		let last = slots[STRATEGY_MARKER_SLOTS - 1];

		let last_zigzag_index = ZIGZAG_INDICES
			.iter()
			.position(|&idx| idx == last.coeff_index as usize)
			.expect("marker slot came from zigzag indices");

		let embed_search_start = BitSlotSearchStart {
			component_index: last.component_index as usize,
			block_index: last.block_index as usize,
			zigzag_index: last_zigzag_index + 1,
		};
		Ok((slots, embed_search_start))
	}
}
