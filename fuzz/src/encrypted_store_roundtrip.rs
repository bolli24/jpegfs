#![no_main]

mod common;

use jpegfs::crypto::{CryptoError, read_encrypted_with_key, write_encrypted_with_key};
use jpegfs::jpeg_file::JpegFileError;
use jpegfs::strategy::EmbeddingStrategyId;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (Vec<u8>, EmbeddingStrategyId)| {
	let (plaintext, strategy) = input;
	let key = common::key();

	let new_jpeg = match write_encrypted_with_key(common::TEMPLATE_JPEG, key, &plaintext, strategy) {
		Ok(j) => j,
		// Plaintext too large for this cover image — not a bug.
		Err(CryptoError::JpegFile(JpegFileError::WriteOutOfCapacity { .. })) => return,
		Err(e) => panic!("unexpected error: {e}"),
	};

	let recovered = read_encrypted_with_key(&new_jpeg, key).expect("roundtrip must succeed");
	assert_eq!(recovered, plaintext);
});
