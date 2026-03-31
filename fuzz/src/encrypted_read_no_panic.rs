#![no_main]

// Verify that read_encrypted_with_key never panics regardless of what bytes are embedded in the JPEG's LSB payload.

#[path = "common.rs"]
mod common;

use jpegfs::crypto::read_encrypted_with_key;
use jpegfs::jpeg_file::JpegSession;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|payload: Vec<u8>| {
	let mut session = JpegSession::in_memory(common::TEMPLATE_JPEG.to_vec()).unwrap();
	let capacity = session.capacity();
	let to_write: Vec<u8> = payload.into_iter().take(capacity).collect();

	if to_write.is_empty() {
		return;
	}

	session.write_data(&to_write).unwrap();
	let corrupted_jpeg = session.to_jpeg_bytes().unwrap();

	// Must never panic — only Ok(_) or a typed error is acceptable.
	let _ = read_encrypted_with_key(&corrupted_jpeg, common::key());
});
