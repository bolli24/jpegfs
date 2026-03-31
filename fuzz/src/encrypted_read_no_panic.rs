#![no_main]

// Verify that read_encrypted_with_key never panics regardless of what bytes are embedded in the JPEG's LSB payload.

use std::path::PathBuf;
use std::sync::OnceLock;

use jpegfs::crypto::{derive_key_for_jpeg, read_encrypted_with_key};
use jpegfs::jpeg_file::JpegSession;
use libfuzzer_sys::fuzz_target;

const TEMPLATE_JPEG: &[u8] = include_bytes!("../fixtures/small_crw_2609_200x150.jpg");
const PASSPHRASE: &str = "fuzz";

fn key() -> &'static [u8; 32] {
	static KEY: OnceLock<[u8; 32]> = OnceLock::new();
	KEY.get_or_init(|| derive_key_for_jpeg(TEMPLATE_JPEG, PASSPHRASE).expect("template JPEG must be valid"))
}

fuzz_target!(|payload: Vec<u8>| {
	let mut session = JpegSession::new(PathBuf::new(), TEMPLATE_JPEG.to_vec()).unwrap();
	let capacity = session.capacity();
	let to_write: Vec<u8> = payload.into_iter().take(capacity).collect();

	if to_write.is_empty() {
		return;
	}

	session.write_data(&to_write).unwrap();
	let corrupted_jpeg = session.to_jpeg_bytes().unwrap();

	// Must never panic — only Ok(_) or a typed error is acceptable.
	let _ = read_encrypted_with_key(&corrupted_jpeg, key());
});
