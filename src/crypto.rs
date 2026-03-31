use argon2::Argon2;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::jpeg::{JpegError, OwnedJpeg, read_owned_jpeg};
use crate::zigzag::{RESERVED_ZIGZAG_COEFFS, ZIGZAG_INDICES};

/// Argon2id memory cost in KiB (19 MiB).
pub const ARGON2_M_COST: u32 = 19 * 1024;
/// Argon2id time cost (iterations).
pub const ARGON2_T_COST: u32 = 2;
/// Argon2id parallelism.
pub const ARGON2_P_COST: u32 = 1;

#[derive(Debug, Error)]
pub enum CryptoError {
	#[error("failed to decode JPEG: {0}")]
	Jpeg(#[from] JpegError),
	#[error("key derivation failed: {0}")]
	KeyDerivation(argon2::Error),
}

/// Derives a deterministic 32-byte salt from the DCT coefficients that are never
/// used for embedding: ondices 0–[`RESERVED_ZIGZAG_COEFFS`] (DC + low-frequency AC)
pub fn derive_salt_from_dct(owned_jpeg: &OwnedJpeg) -> [u8; 32] {
	let mut hasher = Sha256::new();
	for component in &owned_jpeg.components {
		for block in &component.blocks {
			for &zigzag_idx in ZIGZAG_INDICES.iter().take(RESERVED_ZIGZAG_COEFFS) {
				hasher.update(block[zigzag_idx].to_le_bytes());
			}
		}
	}
	hasher.finalize().into()
}

/// Derives a 32-byte encryption key from a passphrase bound to the specific JPEG
/// cover image. The DCT salt ties the key to the image, so the same passphrase
/// produces a different key for each JPEG.
pub fn derive_key_for_jpeg(jpeg_data: &[u8], passphrase: &str) -> Result<[u8; 32], CryptoError> {
	let owned = unsafe { read_owned_jpeg(jpeg_data)? };
	let salt = derive_salt_from_dct(&owned);

	let params =
		argon2::Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32)).expect("valid argon2 params");
	let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

	let mut key = [0u8; 32];
	argon2
		.hash_password_into(passphrase.as_bytes(), &salt, &mut key)
		.map_err(CryptoError::KeyDerivation)?;

	Ok(key)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::jpeg::read_owned_jpeg;

	const TINY_JPEG: &[u8] = include_bytes!("../fuzz/fixtures/tiny_crw_2609_16x8.jpg");
	const OTHER_JPEG: &[u8] = include_bytes!("../test/CRW_2614_(Elsterflutbecken).jpg");

	#[test]
	fn derived_key_is_deterministic() {
		let key_a = derive_key_for_jpeg(TINY_JPEG, "hunter2").unwrap();
		let key_b = derive_key_for_jpeg(TINY_JPEG, "hunter2").unwrap();
		assert_eq!(key_a, key_b);
	}

	#[test]
	fn derived_key_differs_for_different_passphrases() {
		let key_a = derive_key_for_jpeg(TINY_JPEG, "passphrase_a").unwrap();
		let key_b = derive_key_for_jpeg(TINY_JPEG, "passphrase_b").unwrap();
		assert_ne!(key_a, key_b);
	}

	#[test]
	fn derived_key_differs_for_different_images() {
		let key_a = derive_key_for_jpeg(TINY_JPEG, "same_passphrase").unwrap();
		let key_b = derive_key_for_jpeg(OTHER_JPEG, "same_passphrase").unwrap();
		assert_ne!(key_a, key_b);
	}

	#[test]
	fn derived_salt_is_deterministic() {
		let jpeg = unsafe { read_owned_jpeg(TINY_JPEG).unwrap() };
		let salt_a = derive_salt_from_dct(&jpeg);
		let salt_b = derive_salt_from_dct(&jpeg);
		assert_eq!(salt_a, salt_b);
	}

	#[test]
	fn derived_salt_differs_across_images() {
		let jpeg_a = unsafe { read_owned_jpeg(TINY_JPEG).unwrap() };
		let jpeg_b = unsafe { read_owned_jpeg(OTHER_JPEG).unwrap() };
		let salt_a = derive_salt_from_dct(&jpeg_a);
		let salt_b = derive_salt_from_dct(&jpeg_b);
		assert_ne!(salt_a, salt_b);
	}

	#[test]
	fn derived_salt_stable_after_write_roundtrip() {
		use crate::jpeg::write_owned_jpeg;
		let jpeg_a = unsafe { read_owned_jpeg(TINY_JPEG).unwrap() };
		let salt_before = derive_salt_from_dct(&jpeg_a);

		let reencoded = unsafe { write_owned_jpeg(TINY_JPEG, &jpeg_a).unwrap() };
		let jpeg_b = unsafe { read_owned_jpeg(&reencoded).unwrap() };
		let salt_after = derive_salt_from_dct(&jpeg_b);

		assert_eq!(
			salt_before, salt_after,
			"Salt changed after write round-trip - DC/low-freq AC coefficients shifted"
		);
	}
}
