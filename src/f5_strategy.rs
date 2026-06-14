#![allow(dead_code, unused_variables)]
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};

use crate::{
	jpeg::OwnedJpeg,
	jpeg_file::{BitSlot, BitSlotSearchStart, JpegSession},
	strategy::{EmbeddingStrategy, EmbeddingStrategyId},
};

pub const F5_MAX_CAPACITY: usize = 0x007fffff;

pub struct F5Strategy;

impl EmbeddingStrategy for F5Strategy {
	fn id(&self) -> EmbeddingStrategyId {
		EmbeddingStrategyId::F5
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

	for max in (1..length).rev() {
		let index: usize = rng.random_range(0..=max);
		vec.swap(index, max);
	}

	vec
}

fn embed() {
	let seed = 9391839189381839;
	let mut rng = StdRng::seed_from_u64(seed);
	let data = b"Hello, this is a test to embed data with F5 in Rust";

	let image_bytes = include_bytes!("../test/CRW_2614_(Elsterflutbecken).jpg");
	let jpeg_session = JpegSession::new(image_bytes.to_vec()).unwrap();
	println!("Loaded image of {} bytes", image_bytes.len());

	let mut one = 0;
	let mut zero = 0;

	let mut coeff = Vec::new();

	for (i, &c) in jpeg_session
		.components()
		.iter()
		.flat_map(|comp| comp.blocks.iter())
		.flat_map(|block| block.iter().enumerate())
	{
		coeff.push(c);
		if i == 0 {
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
	let expected = large + ((0.49 * one as f64) as usize);

	println!("zero={zero}\tone={one}\tlarge={large}");
	println!("expected capacity: {expected} bits");
	println!("expected capacity with");

	for i in 1..8 {
		let n = (1 << i) - 1;
		let usable = (expected * i / n - expected * i / n % n) / 8;
		let mut changed = large - large % (n + 1);
		changed = (changed + one + one / 2 - one / (n + 1)) / (n + 1);

		if usable == 0 {
			break;
		}
		if i == 1 {
			print!("default");
		} else {
			print!("(1, {n}, {i})");
		}

		println!(
			" code: {usable} bytes (efficiency {:.1} bits per change)",
			(usable * 8) as f64 / changed as f64
		)
	}

	println!("permutation starts");
	let permutation = permutation(coeff_count, &mut rng);

	let mut byte_to_embed = 0u8;
	let mut available_bits_to_embed = 0;
	let mut embedded = 0;
	let mut changed = 0;
	let mut thrown = 0;
	let mut examined = 0;

	println!("Embedding of {} bits", data.len() * 8);

	if data.len() > F5_MAX_CAPACITY {
		// FIXME: in proper implementation we must limit the payload size correctly in the pager
		panic!("Payload to large");
	}
	let mut k = 0;
	for candidate_k in 1..8 {
		let candidate_n = (1 << candidate_k) - 1;
		let usable = (expected * candidate_k / candidate_n - expected * candidate_k / candidate_n % candidate_n) / 8;
		if usable == 0 || usable < data.len() {
			break;
		}
		k = candidate_k;
	}

	let mut n = (1 << k) - 1;

	match n {
		0 => {
			println!("using default code, file will not fit");
			n += 1
		}
		1 => {
			println!("using default code");
		}
		_ => println!("using (1, {n}, {k}) code"),
	}

	let mut bytes = data.iter();

	if n > 1 {
		let mut is_done = false;
		let mut code_word = vec![0usize; n];
		let mut start_of_n = 0;

		loop {
			let mut k_bits_to_embed = 0usize;

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
				embedded += 1;
			}
			if is_done {
				break;
			}
			let mut end_of_n;
			loop {
				let mut j = start_of_n;
				let mut i = 0usize;
				while i < n as usize {
					if j >= coeff_count {
						// FIXME: we must calculate the capacity properly before we ever try embedding
						panic!("Capacity exhausted");
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
					let extracted_bit = if coeff[code_word[i]] > 0 {
						coeff[code_word[i]] & 1
					} else {
						1 - (coeff[code_word[i]] & 1)
					};

					if extracted_bit == 1 {
						hash ^= i + 1;
					}
				}
				let mut i = hash ^ k_bits_to_embed;
				if i == 0 {
					break; // embedded without change
				}
				i -= 1;

				if coeff[code_word[i]] > 0 {
					coeff[code_word[i]] -= 1;
				} else {
					coeff[code_word[i]] += 1;
				}
				changed += 1;

				if coeff[code_word[i]] == 0 {
					thrown += 1;
				}

				if coeff[code_word[i]] != 0 {
					break;
				}
			}
			start_of_n = end_of_n;
		}
	} else {
		// default code
		let Some(next_byte) = bytes.next() else {
			println!("{examined} coefficients examined");
			println!("{changed} coefficients changed");
			println!("{thrown} coefficients thrown (zeroed)");
			println!("{embedded} bits ({} bytes) embeded", embedded / 8);
			return;
		};
		byte_to_embed = *next_byte;
		byte_to_embed ^= rng.random::<u8>();
		available_bits_to_embed = 8;
		let mut next_bit_to_embed = (byte_to_embed & 1) as i16;
		byte_to_embed >>= 1;
		available_bits_to_embed -= 1;
		embedded += 1;

		for i in 0..coeff_count {
			let shuffled_index = permutation[i];
			if shuffled_index % 64 == 0 {
				continue; // Skip DC
			}
			if coeff[shuffled_index] == 0 {
				continue; // Skip zeroes
			}

			examined += 1;

			if coeff[shuffled_index] > 0 {
				if coeff[shuffled_index] & 1 != next_bit_to_embed {
					coeff[shuffled_index] -= 1;
					changed += 1;
				}
			} else {
				if coeff[shuffled_index] & 1 == next_bit_to_embed {
					coeff[shuffled_index] += 1;
					changed += 1;
				}
			}

			if coeff[shuffled_index] != 0 {
				if available_bits_to_embed == 0 {
					let Some(next_byte) = bytes.next() else {
						break;
					};
					byte_to_embed = *next_byte;
					byte_to_embed ^= rng.random::<u8>();
					available_bits_to_embed = 8;
				}
				next_bit_to_embed = (byte_to_embed & 1) as i16;
				byte_to_embed >>= 1;
				available_bits_to_embed -= 1;
				embedded += 1;
			} else {
				// unsuccessful embed, loop and try the next index
				thrown += 1;
			}
		}
	}

	println!("{examined} coefficients examined");
	println!(
		"{changed} coefficients changed (efficiency {:.1} bits per change)",
		embedded as f64 / changed as f64
	);
	println!("{thrown} coefficients thrown (zeroed)");
	println!("{embedded} bits ({} bytes) embeded", embedded / 8);
}

#[cfg(test)]
mod test {
	use rand::{SeedableRng, rngs::StdRng};

	use super::{embed, permutation};

	#[test]
	pub fn f5_permutation_handles_empty_and_singleton() {
		let mut rng = StdRng::seed_from_u64(1234);
		assert_eq!(permutation(0, &mut rng), Vec::<usize>::new());
		assert_eq!(permutation(1, &mut rng), vec![0]);
	}

	#[test]
	pub fn f5_permutation_contains_each_index_once() {
		let mut rng = StdRng::seed_from_u64(1234);
		let length = 1024;
		let mut permuted = permutation(length, &mut rng);
		permuted.sort_unstable();

		assert_eq!(permuted, (0..length).collect::<Vec<_>>());
	}

	#[test]
	fn f5_embed() {
		embed();
	}
}
