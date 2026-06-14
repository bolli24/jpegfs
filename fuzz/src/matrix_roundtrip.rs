#![no_main]

use jpegfs::{
	jpeg::OwnedJpeg,
	matrix_strategy::{MatrixMode, matrix_poc_roundtrip},
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (OwnedJpeg, Vec<u8>, u8)| {
	let (owned_jpeg, payload, mode_seed) = input;
	let k = 2 + usize::from(mode_seed % 6);
	let mode = MatrixMode::new(k).expect("k is constrained to the valid matrix range");
	let Some(recovered) = matrix_poc_roundtrip(&owned_jpeg, &payload, mode) else {
		return;
	};

	assert_eq!(recovered, payload);
});
