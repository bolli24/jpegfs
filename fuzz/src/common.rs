use std::sync::OnceLock;

use jpegfs::crypto::derive_key_for_jpeg;

pub const TEMPLATE_JPEG: &[u8] = include_bytes!("../fixtures/small_crw_2609_200x150.jpg");
pub const PASSPHRASE: &str = "fuzz";

pub fn key() -> &'static [u8; 32] {
	static KEY: OnceLock<[u8; 32]> = OnceLock::new();
	KEY.get_or_init(|| derive_key_for_jpeg(TEMPLATE_JPEG, PASSPHRASE).expect("template JPEG must be valid"))
}
