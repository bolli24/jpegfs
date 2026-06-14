#![allow(dead_code, unused_variables)]
use crate::{
	jpeg::{OwnedComponent, OwnedJpeg},
	jpeg_file::{BitSlot, BitSlotSearchStart, JpegSession},
	strategy::{EmbeddingStrategy, EmbeddingStrategyId},
};
use rand::seq::SliceRandom;
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};

const MATRIX_POC_SEED: u64 = 9391839189381839;
const MATRIX_MUTATION_SEED: u64 = 0x4d47_5258;

pub struct MatrixStrategy;

impl EmbeddingStrategy for MatrixStrategy {
	fn id(&self) -> EmbeddingStrategyId {
		EmbeddingStrategyId::Matrix
	}

	fn collect_bit_slots(&self, jpeg: &OwnedJpeg, start_slot: BitSlotSearchStart) -> Vec<BitSlot> {
		todo!();
	}

	fn capacity_bytes(&self, slots_count: usize) -> usize {
		todo!()
	}

	fn read(&self, jpeg: &OwnedJpeg, slots: &[BitSlot], byte_offset: usize, out: &mut [u8]) -> usize {
		todo!()
	}

	fn write(&self, jpeg: &mut OwnedJpeg, slots: &[BitSlot], byte_offset: usize, data: &[u8]) -> usize {
		todo!()
	}
}

fn permutation<T: Rng>(length: usize, rng: &mut T) -> Vec<usize> {
	let mut vec: Vec<usize> = (0..length).collect();
	vec.shuffle(rng);
	vec
}

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

fn print_expected_capacity(usable_coefficients: usize, one: usize, large: usize) {
	for i in 1..8 {
		let n = (1 << i) - 1;
		let usable = matrix_capacity_bytes(usable_coefficients, MatrixMode { k: i, n });
		let mut changed = large - large % (n + 1);
		changed = (changed + one + one / 2 - one / (n + 1)) / (n + 1);

		if usable == 0 {
			break;
		}
		print!("(1, {n}, {i})");

		println!(
			" code: {usable} bytes (efficiency {:.1} bits per change)",
			(usable * 8) as f64 / changed as f64
		)
	}
}

fn print_mode(mode: MatrixMode) {
	println!("using (1, {}, {}) code", mode.n, mode.k);
}

fn matrix_bit(coeff: i16) -> usize {
	if coeff > 0 {
		(coeff & 1) as usize
	} else {
		(1 - (coeff & 1)) as usize
	}
}

fn balanced_matrix_flip<T: Rng>(coeff: i16, rng: &mut T) -> Option<i16> {
	let current_bit = matrix_bit(coeff);
	let is_valid = |candidate: i16| candidate != 0 && matrix_bit(candidate) != current_bit;
	let down = coeff.checked_sub(1).filter(|&candidate| is_valid(candidate));
	let up = coeff.checked_add(1).filter(|&candidate| is_valid(candidate));

	match (down, up) {
		(Some(down), Some(up)) => {
			if rng.random::<bool>() {
				Some(down)
			} else {
				Some(up)
			}
		}
		(Some(down), None) => Some(down),
		(None, Some(up)) => Some(up),
		(None, None) => None,
	}
}

fn encode_payload<T: Rng>(
	coeff: &mut [i16],
	permutation: &[usize],
	data: &[u8],
	mode: MatrixMode,
	rng: &mut T,
) -> MatrixStats {
	let mut byte_to_embed = 0u8;
	let mut available_bits_to_embed = 0;
	let mut stats = MatrixStats::default();
	let mut bytes = data.iter();
	let mut mutation_rng = StdRng::seed_from_u64(MATRIX_MUTATION_SEED);
	let MatrixMode { k, n } = mode;

	let mut code_word = vec![0usize; n];
	let mut start_of_n = 0;

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
			stats.embedded += 1;
		}
		if bits_in_group == 0 {
			break;
		}

		let end_of_n;
		loop {
			let mut j = start_of_n;
			let mut i = 0usize;
			while i < n {
				if j >= coeff.len() {
					return stats;
				}
				let shuffled_index = permutation[j];
				j += 1;

				if shuffled_index % 64 == 0 {
					continue; // Skip DC
				}
				if coeff[shuffled_index] == 0 {
					continue; // Skip zeroes
				}
				code_word[i] = shuffled_index;
				i += 1;
			}
			end_of_n = j;
			let mut hash = 0;
			for i in 0..n {
				if matrix_bit(coeff[code_word[i]]) == 1 {
					hash ^= i + 1;
				}
			}

			let mut i = hash ^ k_bits_to_embed;
			if i == 0 {
				break; // embedded without change
			}
			i -= 1;

			coeff[code_word[i]] = balanced_matrix_flip(coeff[code_word[i]], &mut mutation_rng)
				.expect("non-zero coefficient has a matrix-bit flip");
			stats.changed += 1;
			break;
		}
		start_of_n = end_of_n;

		if is_done {
			break;
		}
	}

	stats
}

fn push_decoded_bit<T: Rng>(
	out: &mut Vec<u8>,
	out_len: usize,
	extracted_byte: &mut u8,
	available_extracted_bits: &mut usize,
	bit: usize,
	rng: &mut T,
) -> bool {
	*extracted_byte |= ((bit & 1) as u8) << *available_extracted_bits;
	*available_extracted_bits += 1;

	if *available_extracted_bits == 8 {
		*extracted_byte ^= rng.random::<u8>();
		out.push(*extracted_byte);
		*extracted_byte = 0;
		*available_extracted_bits = 0;
	}

	out.len() == out_len
}

fn decode_payload<T: Rng>(
	coeff: &[i16],
	permutation: &[usize],
	out_len: usize,
	mode: MatrixMode,
	rng: &mut T,
) -> Vec<u8> {
	let mut out = Vec::with_capacity(out_len);
	let mut extracted_byte = 0u8;
	let mut available_extracted_bits = 0usize;
	let MatrixMode { k, n } = mode;

	let mut start_of_n = 0;

	loop {
		let mut hash = 0usize;
		let mut j = start_of_n;
		let mut code = 1usize;

		while code <= n {
			if j >= coeff.len() {
				return out;
			}

			let shuffled_index = permutation[j];
			j += 1;

			if shuffled_index % 64 == 0 {
				continue; // Skip DC
			}
			if coeff[shuffled_index] == 0 {
				continue; // Skip zeroes
			}

			if matrix_bit(coeff[shuffled_index]) == 1 {
				hash ^= code;
			}
			code += 1;
		}

		start_of_n = j;
		for i in 0..k {
			if push_decoded_bit(
				&mut out,
				out_len,
				&mut extracted_byte,
				&mut available_extracted_bits,
				(hash >> i) & 1,
				rng,
			) {
				return out;
			}
		}
	}
}

pub fn matrix_poc_roundtrip(owned_jpeg: &OwnedJpeg, data: &[u8], mode: MatrixMode) -> Option<Vec<u8>> {
	let mut coeff = flatten_owned_jpeg(owned_jpeg);
	let coeff_count = coeff.len();
	let (_, _, _, usable) = coefficient_counts(&coeff);
	if data.len() > matrix_capacity_bytes(usable, mode) {
		return None;
	}

	let mut encode_rng = StdRng::seed_from_u64(MATRIX_POC_SEED);
	let shuffled = permutation(coeff_count, &mut encode_rng);
	let stats = encode_payload(&mut coeff, &shuffled, data, mode, &mut encode_rng);
	if stats.embedded / 8 < data.len() {
		return None;
	}

	let mut decode_rng = StdRng::seed_from_u64(MATRIX_POC_SEED);
	let decode_permutation = permutation(coeff_count, &mut decode_rng);
	Some(decode_payload(
		&coeff,
		&decode_permutation,
		data.len(),
		mode,
		&mut decode_rng,
	))
}

fn embed(mode: MatrixMode) -> Vec<u8> {
	let mut rng = StdRng::seed_from_u64(MATRIX_POC_SEED);
	let data = b"Hello, this is a test to embed data with matrix encoding in Rust";

	let image_bytes = include_bytes!("../test/CRW_2614_(Elsterflutbecken).jpg");
	let jpeg_session = JpegSession::new(image_bytes.to_vec()).unwrap();
	println!("Loaded image of {} bytes", image_bytes.len());

	let mut coeff = flatten_coefficients(&jpeg_session);
	let coeff_count = coeff.len();
	let (zero, one, large, usable) = coefficient_counts(&coeff);

	println!("zero={zero}\tone={one}\tlarge={large}");
	println!("usable capacity: {usable} bits");
	println!("expected capacity with");
	print_expected_capacity(usable, one, large);

	println!("permutation starts");
	let shuffled = permutation(coeff_count, &mut rng);

	println!("Embedding of {} bits", data.len() * 8);
	assert!(data.len() <= matrix_capacity_bytes(usable, mode));
	print_mode(mode);

	let stats = encode_payload(&mut coeff, &shuffled, data, mode, &mut rng);

	println!("{} coefficients examined", stats.examined);
	if stats.changed > 0 {
		println!(
			"{} coefficients changed (efficiency {:.1} bits per change)",
			stats.changed,
			stats.embedded as f64 / stats.changed as f64
		);
	} else {
		println!("{} coefficients changed", stats.changed);
	}
	println!("{} coefficients thrown (zeroed)", stats.thrown);
	println!("{} bits ({} bytes) embeded", stats.embedded, stats.embedded / 8);

	let mut decode_rng = StdRng::seed_from_u64(MATRIX_POC_SEED);
	let decode_permutation = permutation(coeff_count, &mut decode_rng);
	let decoded = decode_payload(&coeff, &decode_permutation, data.len(), mode, &mut decode_rng);

	decoded
}

#[cfg(test)]
mod test {
	use rand::{RngExt, SeedableRng, rngs::StdRng};

	use super::{MatrixMode, balanced_matrix_flip, embed, encode_payload, matrix_bit, permutation};

	#[test]
	pub fn matrix_permutation_handles_empty_and_singleton() {
		let mut rng = StdRng::seed_from_u64(1234);
		assert_eq!(permutation(0, &mut rng), Vec::<usize>::new());
		assert_eq!(permutation(1, &mut rng), vec![0]);
	}

	#[test]
	pub fn matrix_permutation_contains_each_index_once() {
		let mut rng = StdRng::seed_from_u64(1234);
		let length = 1024;
		let mut permuted = permutation(length, &mut rng);
		permuted.sort_unstable();

		assert_eq!(permuted, (0..length).collect::<Vec<_>>());
	}

	#[test]
	fn matrix_embed() {
		let decoded = embed(MatrixMode::new(7).expect("valid matrix mode"));
		assert_eq!(
			decoded,
			b"Hello, this is a test to embed data with matrix encoding in Rust"
		);
	}

	#[test]
	fn matrix_balanced_flip_never_creates_zero_and_flips_bit() {
		let mut rng = StdRng::seed_from_u64(1234);

		for coeff in -16..=16 {
			if coeff == 0 {
				continue;
			}
			let flipped = balanced_matrix_flip(coeff, &mut rng).expect("non-zero coefficient should be flippable");

			assert_ne!(flipped, 0);
			assert_eq!((coeff - flipped).abs(), 1);
			assert_ne!(matrix_bit(coeff), matrix_bit(flipped));
		}
	}

	#[test]
	fn matrix_repeated_random_embeds_keep_capacity_stable() {
		let mode = MatrixMode { k: 3, n: 7 };
		let mut coeff = (0..4096)
			.map(|i| {
				if i % 64 == 0 {
					0
				} else if i % 2 == 0 {
					1
				} else {
					-1
				}
			})
			.collect::<Vec<_>>();
		let initial = capacity_and_shape(&coeff, mode);

		for iteration in 0..3 {
			let payload = random_payload(initial.0, iteration);
			let mut encode_rng = StdRng::seed_from_u64(MATRIX_SAMPLE_SEED);
			let shuffled = permutation(coeff.len(), &mut encode_rng);
			let stats = encode_payload(&mut coeff, &shuffled, &payload, mode, &mut encode_rng);
			let after = capacity_and_shape(&coeff, mode);

			assert_eq!(stats.thrown, 0);
			assert_eq!(after, initial);
		}
	}

	fn capacity_and_shape(coeff: &[i16], mode: MatrixMode) -> (usize, usize, usize) {
		let (zero, one, large, usable) = super::coefficient_counts(coeff);
		let capacity_bytes = super::matrix_capacity_bytes(usable, mode);

		(capacity_bytes, zero, one + large)
	}

	fn random_payload(len: usize, iteration: usize) -> Vec<u8> {
		let mut rng = StdRng::seed_from_u64(0xF5CA_0000 | ((iteration as u64) << 32) | len as u64);
		(0..len).map(|_| rng.random::<u8>()).collect()
	}

	const MATRIX_SAMPLE_SEED: u64 = 0xF500_51A7;
}
