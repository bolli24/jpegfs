#![allow(dead_code, unused_variables)]
use rand::{
	Rng, RngExt, SeedableRng,
	rngs::{StdRng, ThreadRng},
};

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

	let mut n = 0;

	for i in 1..8 {
		n = (1 << i) - 1;
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

	let mut next_bit_to_embed = 0i16;
	let mut byte_to_embed = data.len() as u32;
	let mut available_bits_to_embed = 0;
	let mut embedded = 0;
	let mut changed = 0;
	let mut thrown = 0;
	let mut examined = 0;

	println!("Embedding of {} bit", byte_to_embed * 8 + 32);

	if byte_to_embed > F5_MAX_CAPACITY as u32 {
		// FIXME: in proper implementation we must limit the payload size correctly in the pager
		panic!("Payload to large");
	}
	let mut i = 1;
	while i < 8 {
		let usable = (expected * i / n - expected * i / n % n) / 8;
		i += 1;
		if usable == 0 || usable < byte_to_embed as usize + 4 {
			break;
		}
	}

	let k = i - 1;
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

	byte_to_embed |= (k << 24) as u32;
	byte_to_embed ^= rng.random::<u8>() as u32;
	byte_to_embed ^= (rng.random::<u8>() as u32) << 8;
	byte_to_embed ^= (rng.random::<u8>() as u32) << 16;
	byte_to_embed ^= (rng.random::<u8>() as u32) << 24;

	next_bit_to_embed = (byte_to_embed & 1) as i16;
	byte_to_embed >>= 1;
	available_bits_to_embed = 31;
	embedded += 1;

	let mut bytes = data.iter();

	if n > 1 {
		let mut is_last_byte = false;
		let mut code_word = vec![0usize; n];

		for i in 0..coeff_count {
			let shuffled_index = permutation[i];

			if shuffled_index % 64 == 0 {
				continue; // Skip DC
			}
			if coeff[shuffled_index] == 0 {
				continue; // Skip zeroes
			}
			if coeff[shuffled_index] > 0 {
				if (coeff[shuffled_index] & 1) != next_bit_to_embed {
					coeff[shuffled_index] -= 1;
					changed += 1;
				}
			} else {
				if (coeff[shuffled_index] & 1) == next_bit_to_embed {
					coeff[shuffled_index] += 1;
					changed += 1;
				}
			}
			if coeff[shuffled_index] != 0 {
				// successfully embedded bit
				// (maybe we can reorder this similar to how lsb works later)
				if available_bits_to_embed == 0 {
					break;
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
		// status word embedded
		let mut start_of_N = i + 1;

		loop {
			let mut k_bits_to_embed = 0;

			for i in 0..k {
				if available_bits_to_embed == 0 {
					// last byte embedded successfully, get the next one
					let Some(next_byte) = bytes.next() else {
						is_last_byte = true;
						break;
					};
					byte_to_embed = *next_byte as u32;
					byte_to_embed ^= rng.random::<u8>() as u32;
					available_bits_to_embed = 8;
				}
				next_bit_to_embed = (byte_to_embed & 1) as i16;
				byte_to_embed >>= 1;
				available_bits_to_embed -= 1;
				k_bits_to_embed |= next_bit_to_embed << i;
				embedded += 1;
			}
			let mut end_of_n;
			loop {
				let mut j = start_of_N;
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
				let mut i = hash ^ k_bits_to_embed as usize;
				if (i == 0) {
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
			start_of_N = end_of_n;
			if is_last_byte {
				break;
			}
		}
	} else {
		// default code
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
					break;
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

	// Now we embed the secret data in the permutated sequence.
	// System.out.println("Permutation starts");
	// F5Random random = new F5Random(password.getBytes());
	// Permutation permutation = new Permutation(coeffCount, random);
	// int nextBitToEmbed = 0;
	// int byteToEmbed = 0;
	// int availableBitsToEmbed = 0;
	// // We start with the length information.  Well,
	// // the length information it is more than one
	// // byte, so this first "byte" is 32 bits long.
	// try {
	//     byteToEmbed = embeddedData.available();
	// } catch (Exception e) {
	//     e.printStackTrace();
	// }
	// System.out.print("Embedding of " + (byteToEmbed * 8 + 32) + " bits (" + byteToEmbed + "+4 bytes) ");
	// // We use the most significant byte for the 1 of n
	// // code, and reserve one extra bit for future use.
	// if (byteToEmbed > 0x007fffff)
	//     byteToEmbed = 0x007fffff;
	// // We calculate n now
	// for (i = 1; i < 8; i++) {
	//     int usable, changed;
	//     n = (1 << i) - 1;
	//     usable = _expected * i / n - _expected * i / n % n;
	//     usable /= 8;
	//     if (usable == 0)
	//         break;
	//     if (usable < byteToEmbed + 4)
	//         break;
	// }
	// int k = i - 1;
	// n = (1 << k) - 1;
	// switch (n) {
	// case 0:
	//     System.out.println("using default code, file will not fit");
	//     n++;
	//     break;
	// case 1:
	//     System.out.println("using default code");
	//     break;
	// default:
	//     System.out.println("using (1, " + n + ", " + k + ") code");
	// }
	// byteToEmbed |= k << 24; // store k in the status word
	// // Since shuffling cannot hide the distribution, the
	// // distribution of all bits to embed is unified by
	// // adding a pseudo random bit-string. We continue the random
	// // we used for Permutation, initially seeked with password.
	// byteToEmbed ^= random.getNextByte();
	// byteToEmbed ^= random.getNextByte() << 8;
	// byteToEmbed ^= random.getNextByte() << 16;
	// byteToEmbed ^= random.getNextByte() << 24;
	// nextBitToEmbed = byteToEmbed & 1;
	// byteToEmbed >>= 1;
	// availableBitsToEmbed = 31;
	// _embedded++;
	// if (n > 1) { // use 1 of n code
	//     int kBitsToEmbed;
	//     int extractedBit;
	//     int[] codeWord = new int[n];
	//     int hash;
	//     int startOfN = 0;
	//     int endOfN = 0;
	//     boolean isLastByte = false;
	//     // embed status word first
	//     for (i = 0; i < coeffCount; i++) {
	//         shuffledIndex = permutation.getShuffled(i);
	//         if (shuffledIndex % 64 == 0)
	//             continue; // skip DC coefficients
	//         if (coeff[shuffledIndex] == 0)
	//             continue; // skip zeroes
	//         if (coeff[shuffledIndex] > 0) {
	//             if ((coeff[shuffledIndex] & 1) != nextBitToEmbed) {
	//                 coeff[shuffledIndex]--; // decrease absolute value
	//                 _changed++;
	//             }
	//         } else {
	//             if ((coeff[shuffledIndex] & 1) == nextBitToEmbed) {
	//                 coeff[shuffledIndex]++; // decrease absolute value
	//                 _changed++;
	//             }
	//         }
	//         if (coeff[shuffledIndex] != 0) {
	//             // The coefficient is still nonzero. We
	//             // successfully embedded "nextBitToEmbed".
	//             // We will read a new bit to embed now.
	//             if (availableBitsToEmbed == 0)
	//                 break; // statusword embedded.
	//             nextBitToEmbed = byteToEmbed & 1;
	//             byteToEmbed >>= 1;
	//             availableBitsToEmbed--;
	//             _embedded++;
	//         } else
	//             _thrown++;
	//     }
	//     startOfN = i + 1;
	//     // now embed the data using 1 of n code
	// embeddingLoop:
	//     do {
	//         kBitsToEmbed = 0;
	//         // get k bits to embed
	//         for (i = 0; i < k; i++) {
	//             if (availableBitsToEmbed == 0) {
	//                 // If the byte of embedded text is
	//                 // empty, we will get a new one.
	//                 try {
	//                     if (embeddedData.available() == 0) {
	//                         isLastByte = true;
	//                         break;
	//                     }
	//                     byteToEmbed = embeddedData.read();
	//                     byteToEmbed ^= random.getNextByte();
	//                 } catch (Exception e) {
	//                     e.printStackTrace();
	//                     break;
	//                 }
	//                 availableBitsToEmbed = 8;
	//             }
	//             nextBitToEmbed = byteToEmbed & 1;
	//             byteToEmbed >>= 1;
	//             availableBitsToEmbed--;
	//             kBitsToEmbed |= nextBitToEmbed << i;
	//             _embedded++;
	//         }
	//         // embed k bits
	//         do {
	//             j = startOfN;
	//             // fill codeWord[] with the indices of the
	//             // next n non-zero coefficients in coeff[]
	//             for (i = 0; i < n; j++) {
	//                 if (j >= coeffCount) {
	//                     // in rare cases the estimated capacity is too small
	//                     System.out.println("Capacity exhausted.");
	//                     break embeddingLoop;
	//                 }
	//                 shuffledIndex = permutation.getShuffled(j);
	//                 if (shuffledIndex % 64 == 0)
	//                     continue; // skip DC coefficients
	//                 if (coeff[shuffledIndex] == 0)
	//                     continue; // skip zeroes
	//                 codeWord[i++] = shuffledIndex;
	//             }
	//             endOfN = j;
	//             hash = 0;
	//             for (i = 0; i < n; i++) {
	//                 if (coeff[codeWord[i]] > 0)
	//                     extractedBit = coeff[codeWord[i]] & 1;
	//                 else
	//                     extractedBit = 1 - (coeff[codeWord[i]] & 1);
	//                 if (extractedBit == 1)
	//                     hash ^= i + 1;
	//             }
	//             i = hash ^ kBitsToEmbed;
	//             if (i == 0)
	//                 break; // embedded without change
	//             i--;
	//             if (coeff[codeWord[i]] > 0)
	//                 coeff[codeWord[i]]--;
	//             else
	//                 coeff[codeWord[i]]++;
	//             _changed++;
	//             if (coeff[codeWord[i]] == 0)
	//                 _thrown++;
	//         } while (coeff[codeWord[i]] == 0);
	//         startOfN = endOfN;
	//     } while (!isLastByte);
	// } else { // default code
	//     // The main embedding loop follows. It works on the
	//     // shuffled stream of coefficients.
	//     for (i = 0; i < coeffCount; i++) {
	//         shuffledIndex = permutation.getShuffled(i);
	//         if (shuffledIndex % 64 == 0)
	//             continue; // skip DC coefficients
	//         if (coeff[shuffledIndex] == 0)
	//             continue; // skip zeroes
	//         _examined++;
	//         if (coeff[shuffledIndex] > 0) {
	//             if ((coeff[shuffledIndex] & 1) != nextBitToEmbed) {
	//                 coeff[shuffledIndex]--; // decrease absolute value
	//                 _changed++;
	//             }
	//         } else {
	//             if ((coeff[shuffledIndex] & 1) == nextBitToEmbed) {
	//                 coeff[shuffledIndex]++; // decrease absolute value
	//                 _changed++;
	//             }
	//         }
	//         if (coeff[shuffledIndex] != 0) {
	//             // The coefficient is still nonzero. We
	//             // successfully embedded "nextBitToEmbed".
	//             // We will read a new bit to embed now.
	//             if (availableBitsToEmbed == 0) {
	//                 // If the byte of embedded text is
	//                 // empty, we will get a new one.
	//                 try {
	//                     if (embeddedData.available() == 0)
	//                         break;
	//                     byteToEmbed = embeddedData.read();
	//                     byteToEmbed ^= random.getNextByte();
	//                 } catch (Exception e) {
	//                     e.printStackaTrace();
	//                     break;
	//                 }
	//                 availableBitsToEmbed = 8;
	//             }
	//             nextBitToEmbed = byteToEmbed & 1;
	//             byteToEmbed >>= 1;
	//             availableBitsToEmbed--;
	//             _embedded++;
	//         } else
	//             _thrown++;
	//     }
	// }
	// if (_examined > 0)
	//     System.out.println(_examined + " coefficients examined");
	// System.out.println(_changed + " coefficients changed (efficiency: " + (_embedded / _changed) + "." +
	//                     (((_embedded * 10) / _changed) % 10) + " bits per change)");
	// System.out.println(_thrown + " coefficients thrown (zeroed)");
	// System.out.println(_embedded + " bits (" + _embedded / 8 + " bytes) embedded");//
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
