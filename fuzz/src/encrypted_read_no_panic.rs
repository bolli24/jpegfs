#![no_main]

// Verify that read_encrypted_with_key never panics regardless of what bytes are embedded in the JPEG's LSB payload.

mod common;

use jpegfs::crypto::{read_encrypted_with_key, write_encrypted_with_key};
use jpegfs::jpeg_file::JpegSession;
use jpegfs::strategy::EmbeddingStrategyId;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|payload: Vec<u8>| {
	let key = common::key();
	let base_jpeg = write_encrypted_with_key(common::TEMPLATE_JPEG, key, &[], EmbeddingStrategyId::Lsb).unwrap();
	let session = JpegSession::new(base_jpeg).unwrap();
	let mut embedding_session = session.into_embedding_session(EmbeddingStrategyId::Lsb, *key);
	let capacity = embedding_session.remaining_bytes();
	let to_write: Vec<u8> = payload.into_iter().take(capacity).collect();

	if to_write.is_empty() {
		return;
	}

	embedding_session.write_data(&to_write).unwrap();
	let corrupted_jpeg = embedding_session.to_jpeg_bytes().unwrap();

	// Must never panic — only Ok(_) or a typed error is acceptable.
	let _ = read_encrypted_with_key(&corrupted_jpeg, key);
});
