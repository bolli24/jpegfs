#![no_main]

use jpegfs::{
	jpeg::OwnedJpeg,
	matrix_strategy::{MatrixMode, MatrixStrategy},
	strategy::EmbeddingStrategy,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (OwnedJpeg, Vec<u8>, u8)| {
	let (mut owned_jpeg, payload, mode_seed) = input;
	let k = 2 + usize::from(mode_seed % 6);
	let mode = MatrixMode::new(k).expect("k is constrained to the valid matrix range");
	let strategy = MatrixStrategy(mode, [0x5au8; 32]);
	let slots = strategy.collect_bit_slots(&owned_jpeg, Default::default());

	if payload.len() > strategy.capacity_bytes(slots.len()) {
		return;
	}

	let written = strategy.write(&mut owned_jpeg, &slots, &payload);
	let read_slots = strategy.collect_bit_slots(&owned_jpeg, Default::default());
	let mut recovered = vec![0u8; written];
	let read = strategy.read(&owned_jpeg, &read_slots, &mut recovered);

	assert_eq!(read, written);
	assert_eq!(recovered, payload);
});
