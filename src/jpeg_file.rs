use crate::crypto::{STRATEGY_MARKER_SIZE, STRATEGY_MARKER_SLOTS};
use crate::jpeg::{JpegError, OwnedComponent, OwnedJpeg, read_owned_jpeg, write_owned_jpeg};
use crate::lsb::{get_lsb, set_lsb};
use crate::strategy::{EmbeddingStrategy, EmbeddingStrategyId, collect_lsb_bit_slots, strategy_from_id};
use crate::zigzag::ZIGZAG_INDICES;
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
}

pub struct EmbeddingSession {
	jpeg: JpegSession,
	strategy: Box<dyn EmbeddingStrategy>,
	bit_slots: Vec<BitSlot>,
	cursor_bytes: usize,
}

impl EmbeddingSession {
	pub fn remaining_bytes(&self) -> usize {
		self.strategy
			.capacity_bytes(self.data_slot_count())
			.saturating_sub(self.cursor_bytes)
	}

	pub fn data_slot_count(&self) -> usize {
		self.bit_slots.len()
	}

	pub fn bit_slots(&self) -> &[BitSlot] {
		&self.bit_slots
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
		let read = self
			.strategy
			.read(&self.jpeg.owned_jpeg, &self.bit_slots, self.cursor_bytes, &mut out);
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

		let written = self
			.strategy
			.write(&mut self.jpeg.owned_jpeg, &self.bit_slots, self.cursor_bytes, data);
		debug_assert_eq!(written, data.len());
		self.cursor_bytes += written;
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

#[derive(Clone, Copy, Default)]
pub struct BitSlot {
	pub component_index: usize,
	pub block_index: usize,
	pub coeff_index: usize,
}

/// Bit slot index for denoting where to start the search for the new know unused slots
/// eg. after strategy maker slots have been found
#[derive(Clone, Copy, Default)]
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

	pub fn into_embedding_session(self, embedding_strategy_id: EmbeddingStrategyId) -> EmbeddingSession {
		let strategy = strategy_from_id(embedding_strategy_id);
		EmbeddingSession {
			bit_slots: strategy.collect_bit_slots(&self.owned_jpeg, self.embed_search_start),
			jpeg: self,
			strategy,
			cursor_bytes: 0,
		}
	}

	pub fn components(&self) -> &[OwnedComponent; 3] {
		&self.owned_jpeg.components
	}

	pub fn read_strategy_marker_lsb(&self) -> u8 {
		const { assert!(STRATEGY_MARKER_SIZE == 1) };
		let mut out_byte = 0u8;
		for bit_in_byte in 0..8usize {
			let slot = self.strategy_marker_slots[bit_in_byte];
			let coeff = self.owned_jpeg.components[slot.component_index].blocks[slot.block_index][slot.coeff_index];
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
			let coeff =
				&mut self.owned_jpeg.components[slot.component_index].blocks[slot.block_index][slot.coeff_index];
			*coeff = set_lsb(*coeff, bit);
		}
	}

	/// Re-encodes the (possibly modified) DCT coefficients into JPEG bytes without
	/// writing to disk.
	pub fn to_jpeg_bytes(&self) -> Result<Vec<u8>, JpegFileError> {
		Ok(unsafe { write_owned_jpeg(&self.source_jpeg, &self.owned_jpeg)? })
	}

	/// Returns exactly the required ammount of bit slots for the purpose of embedding the stragy marker
	/// and where it is safe to start searching for new bitslots eg. for the actual embedding
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
			.position(|&idx| idx == last.coeff_index)
			.expect("marker slot came from zigzag indices");

		let embed_search_start = BitSlotSearchStart {
			component_index: last.component_index,
			block_index: last.block_index,
			zigzag_index: last_zigzag_index + 1,
		};
		return Ok((slots, embed_search_start));
	}
}
