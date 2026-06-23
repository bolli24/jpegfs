#![allow(dead_code, unused_variables)]
use crate::jpeg::BlockData;
use crate::strategy::iter_coefficients;
use crate::{
	jpeg::{OwnedComponent, OwnedJpeg},
	jpeg_file::{BitSlot, BitSlotSearchStart, JpegSession},
	strategy::{EmbeddingStrategy, EmbeddingStrategyId},
};
use rand::seq::SliceRandom;
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};

const MATRIX_PERMUTATION_SEED_LABEL: &[u8] = b"jpegfs matrix permutation v1";
const MATRIX_WHITENING_SEED_LABEL: &[u8] = b"jpegfs matrix whitening v1";
const MATRIX_MUTATION_SEED_LABEL: &[u8] = b"jpegfs matrix mutation v1";

/// |   k |   n | Capacity of slots | Expected changes/group | Changes/embedded bit |
/// | ---:| ---:| -----------------:| ----------------------:| --------------------:|
/// |   2 |   3 |            66.67% |                 0.7500 |               0.3750 |
/// |   3 |   7 |            42.86% |                 0.8750 |               0.2917 |
/// |   4 |  15 |            26.67% |                 0.9375 |               0.2344 |
/// |   5 |  31 |            16.13% |                 0.9688 |               0.1938 |
/// |   6 |  63 |             9.52% |                 0.9844 |               0.1641 |
/// |   7 | 127 |             5.51% |                 0.9922 |               0.1417 |
///
/// n = 2^k - 1, capacity = k / (2^k - 1),
/// expected changes/group = n / 2^k.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatrixMode {
	pub k: usize,
	pub n: usize,
}

impl MatrixMode {
	pub fn new(k: usize) -> Option<Self> {
		(2..8).contains(&k).then(|| Self { k, n: (1 << k) - 1 })
	}

	pub fn capacity_bytes(self, usable_coefficients: usize) -> usize {
		(usable_coefficients / self.n * self.k) / 8
	}

	pub fn slots_for_bytes(self, byte_count: usize) -> usize {
		(byte_count * 8).div_ceil(self.k) * self.n
	}
}

pub struct MatrixStrategy(pub MatrixMode, pub [u8; 32]);

impl MatrixStrategy {
	fn rng(&self, label: &[u8]) -> StdRng {
		let mut hasher = Sha256::new();
		hasher.update(label);
		hasher.update(self.1);
		hasher.update([self.0.k as u8]);
		StdRng::from_seed(hasher.finalize().into())
	}
}

impl EmbeddingStrategy for MatrixStrategy {
	fn id(&self) -> EmbeddingStrategyId {
		match self.0.k {
			2 => EmbeddingStrategyId::Matrix2,
			3 => EmbeddingStrategyId::Matrix3,
			4 => EmbeddingStrategyId::Matrix4,
			5 => EmbeddingStrategyId::Matrix5,
			6 => EmbeddingStrategyId::Matrix6,
			7 => EmbeddingStrategyId::Matrix7,
			_ => unreachable!("MatrixMode only allows k=2..=7"),
		}
	}

	fn collect_bit_slots(&self, jpeg: &OwnedJpeg, start_slot: BitSlotSearchStart) -> Vec<BitSlot> {
		let mut bit_slots = Vec::new();

		iter_coefficients(
			jpeg,
			start_slot,
			1,
			|block: &BlockData, component_index: usize, block_index: usize, coeff_index: usize| -> bool {
				if block[coeff_index] != 0 {
					bit_slots.push(BitSlot {
						component_index: component_index as u32,
						block_index: block_index as u32,
						coeff_index: coeff_index as u32,
					});
				}
				true
			},
		);
		let mut permutation_rng = self.rng(MATRIX_PERMUTATION_SEED_LABEL);
		bit_slots.shuffle(&mut permutation_rng);

		bit_slots
	}

	fn capacity_bytes(&self, slots_count: usize) -> usize {
		self.0.capacity_bytes(slots_count)
	}

	fn slots_for_bytes(&self, byte_count: usize) -> usize {
		self.0.slots_for_bytes(byte_count)
	}

	fn read(&self, jpeg: &OwnedJpeg, slots: &[BitSlot], out: &mut [u8]) -> usize {
		let mut extracted_byte = 0u8;
		let mut available_extracted_bits = 0usize;
		let mut rng = self.rng(MATRIX_WHITENING_SEED_LABEL);
		let MatrixMode { k, n } = self.0;

		let mut start_of_n = 0;
		let mut read_bytes = 0usize;

		while read_bytes < out.len() {
			if start_of_n + n > slots.len() {
				break;
			}

			let code_word = &slots[start_of_n..start_of_n + n];
			let mut hash = 0usize;
			for i in 0..n {
				let slot = code_word[i];
				let coeff = jpeg.components[slot.component_index as usize].blocks[slot.block_index as usize]
					[slot.coeff_index as usize];

				if matrix_bit(coeff) == 1 {
					hash ^= i + 1;
				}
			}
			start_of_n += n;

			for i in 0..k {
				let bit = (hash >> i) & 1;

				extracted_byte |= ((bit & 1) as u8) << available_extracted_bits;
				available_extracted_bits += 1;

				if available_extracted_bits == 8 {
					extracted_byte ^= rng.random::<u8>();
					out[read_bytes] = extracted_byte;
					read_bytes += 1;
					extracted_byte = 0;
					available_extracted_bits = 0;

					if read_bytes == out.len() {
						break;
					}
				}
			}
		}

		read_bytes
	}

	fn write(&self, jpeg: &mut OwnedJpeg, slots: &[BitSlot], data: &[u8]) -> usize {
		let mut byte_to_embed = 0u8;
		let mut available_bits_to_embed = 0;
		let mut bytes = data.iter();
		let mut mutation_rng = self.rng(MATRIX_MUTATION_SEED_LABEL);
		let mut rng = self.rng(MATRIX_WHITENING_SEED_LABEL);
		let MatrixMode { k, n } = self.0;

		let mut start_of_n = 0;
		let mut written_bits = 0usize;

		loop {
			let mut k_bits_to_embed = 0usize;
			let mut bits_in_group = 0usize;
			let mut is_done = false;

			for i in 0..k {
				if available_bits_to_embed == 0 {
					let Some(next_byte) = bytes.next() else {
						is_done = true;
						break;
					};
					byte_to_embed = *next_byte;
					byte_to_embed ^= rng.random::<u8>();
					available_bits_to_embed = 8;
				}
				let next_bit_to_embed = (byte_to_embed & 1) as usize;
				byte_to_embed >>= 1;
				available_bits_to_embed -= 1;
				k_bits_to_embed |= next_bit_to_embed << i;
				bits_in_group += 1;
			}
			if bits_in_group == 0 {
				break;
			}

			if start_of_n + n > slots.len() {
				break;
			}

			let code_word = &slots[start_of_n..start_of_n + n];

			let mut hash = 0;
			for i in 0..n {
				let slot = code_word[i];
				let coeff = jpeg.components[slot.component_index as usize].blocks[slot.block_index as usize]
					[slot.coeff_index as usize];
				if matrix_bit(coeff) == 1 {
					hash ^= i + 1;
				}
			}

			let mut i = hash ^ k_bits_to_embed;
			if i != 0 {
				i -= 1;

				let slot = code_word[i];
				let coeff = &mut jpeg.components[slot.component_index as usize].blocks[slot.block_index as usize]
					[slot.coeff_index as usize];

				*coeff = balanced_matrix_flip(*coeff, &mut mutation_rng);
			}
			start_of_n += n;
			written_bits += bits_in_group;

			if is_done {
				break;
			}
		}

		written_bits / 8
	}
}

fn index_permutation<T: Rng>(length: usize, rng: &mut T) -> Vec<usize> {
	let mut vec: Vec<usize> = (0..length).collect();
	vec.shuffle(rng);
	vec
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct MatrixStats {
	embedded: usize,
	changed: usize,
	thrown: usize,
	examined: usize,
}

fn flatten_components(components: &[OwnedComponent; 3]) -> Vec<i16> {
	components
		.iter()
		.flat_map(|comp| comp.blocks.iter())
		.flat_map(|block| block.iter().copied())
		.collect()
}

fn flatten_owned_jpeg(jpeg: &OwnedJpeg) -> Vec<i16> {
	flatten_components(&jpeg.components)
}

fn flatten_coefficients(jpeg_session: &JpegSession) -> Vec<i16> {
	flatten_components(jpeg_session.components())
}

fn coefficient_counts(coeff: &[i16]) -> (usize, usize, usize, usize) {
	let mut one = 0;
	let mut zero = 0;

	for (i, &c) in coeff.iter().enumerate() {
		if i % 64 == 0 {
			continue;
		}
		if c == 1 || c == -1 {
			one += 1;
		}
		if c == 0 {
			zero += 1;
		}
	}

	let coeff_count = coeff.len();
	let large = coeff_count - zero - one - coeff_count / 64; // count of coeff != 0, -1 , 1 and non dc
	let usable = large + one;
	(zero, one, large, usable)
}

fn matrix_capacity_bytes(usable_coefficients: usize, mode: MatrixMode) -> usize {
	mode.capacity_bytes(usable_coefficients)
}

fn matrix_bit(coeff: i16) -> usize {
	if coeff > 0 {
		(coeff & 1) as usize
	} else {
		(1 - (coeff & 1)) as usize
	}
}

fn balanced_matrix_flip<T: Rng>(coeff: i16, rng: &mut T) -> i16 {
	match coeff {
		1 => 2,
		-1 => -2,
		i16::MIN => i16::MIN + 1,
		i16::MAX => i16::MAX - 1,
		_ if rng.random::<bool>() => coeff - 1,
		_ => coeff + 1,
	}
}

#[cfg(test)]
mod test {
	use super::{balanced_matrix_flip, matrix_bit};
	use crate::{jpeg_file::JpegSession, strategy::EmbeddingStrategyId};
	use rand::{SeedableRng, rngs::StdRng};

	#[test]
	fn matrix_strategy_read_write_roundtrip() {
		let image_bytes = include_bytes!("../test/CRW_2614_(Elsterflutbecken).jpg");
		let payload = b"matrix strategy roundtrip";

		for strategy in [
			EmbeddingStrategyId::Matrix2,
			EmbeddingStrategyId::Matrix3,
			EmbeddingStrategyId::Matrix4,
			EmbeddingStrategyId::Matrix5,
			EmbeddingStrategyId::Matrix6,
			EmbeddingStrategyId::Matrix7,
		] {
			let session = JpegSession::new(image_bytes.to_vec()).unwrap();
			let mut embedding_session = session.into_embedding_session(strategy, [7u8; 32]);
			embedding_session.write_data(payload).unwrap();
			let encoded = embedding_session.to_jpeg_bytes().unwrap();

			let session = JpegSession::new(encoded).unwrap();
			let mut embedding_session = session.into_embedding_session(strategy, [7u8; 32]);
			let decoded = embedding_session.read_data(payload.len()).unwrap();

			assert_eq!(decoded, payload);
		}
	}

	#[test]
	fn matrix_balanced_flip_never_creates_zero_and_flips_bit() {
		let mut rng = StdRng::seed_from_u64(1234);

		for coeff in i16::MIN..=i16::MAX {
			if coeff == 0 {
				continue;
			}
			let flipped = balanced_matrix_flip(coeff, &mut rng);

			assert_ne!(flipped, 0);
			assert_eq!((coeff - flipped).abs(), 1);
			assert_ne!(matrix_bit(coeff), matrix_bit(flipped));
		}
	}
}
