#![no_main]

use std::sync::OnceLock;

use jpegfs::crypto::{derive_key_for_jpeg, read_encrypted_with_key, write_encrypted_with_key};
use libfuzzer_sys::fuzz_target;

const TEMPLATE_JPEG: &[u8] = include_bytes!("../fixtures/small_crw_2609_200x150.jpg");
const PASSPHRASE: &str = "fuzz";

fn key() -> &'static [u8; 32] {
	static KEY: OnceLock<[u8; 32]> = OnceLock::new();
	KEY.get_or_init(|| derive_key_for_jpeg(TEMPLATE_JPEG, PASSPHRASE).expect("template JPEG must be valid"))
}

fuzz_target!(|plaintext: Vec<u8>| {
	let key = key();

	let new_jpeg = match write_encrypted_with_key(TEMPLATE_JPEG, key, &plaintext) {
		Ok(j) => j,
		// Plaintext too large for this cover image - not a bug.
		Err(_) => return,
	};

	let recovered = read_encrypted_with_key(&new_jpeg, key).expect("roundtrip must succeed");
	assert_eq!(recovered, plaintext);
});
