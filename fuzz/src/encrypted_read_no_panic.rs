#![no_main]

// Verify that read_encrypted_with_key never panics regardless of what bytes are embedded in the JPEG payload.

mod common;

use jpegfs::crypto::{CryptoError, read_encrypted_with_key, write_encrypted_with_key};
use jpegfs::jpeg_file::{JpegFileError, JpegSession};
use jpegfs::strategy::EmbeddingStrategyId;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (Vec<u8>, EmbeddingStrategyId)| {
	let (payload, strategy) = input;
	let key = common::key();
	let base_jpeg = match write_encrypted_with_key(common::TEMPLATE_JPEG, key, &[], strategy) {
		Ok(jpeg) => jpeg,
		Err(CryptoError::JpegFile(JpegFileError::WriteOutOfCapacity { .. })) => return,
		Err(err) => panic!("unexpected error: {err}"),
	};
	let session = JpegSession::new(base_jpeg).unwrap();
	let mut embedding_session = session.into_embedding_session(strategy, *key);
	let capacity = embedding_session.capacity();
	let to_write: Vec<u8> = payload.into_iter().take(capacity).collect();

	if to_write.is_empty() {
		return;
	}

	embedding_session.write(&to_write).unwrap();
	let corrupted_jpeg = embedding_session.to_jpeg_bytes().unwrap();

	// Must never panic — only Ok(_) or a typed error is acceptable.
	let _ = read_encrypted_with_key(&corrupted_jpeg, key);
});
