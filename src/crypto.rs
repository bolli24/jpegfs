use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::{fs, io};

use argon2::Argon2;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::jpeg::{JpegError, OwnedJpeg, read_owned_jpeg};
use crate::jpeg_file::{JpegFileError, JpegSession};
use crate::zigzag::{RESERVED_ZIGZAG_COEFFS, ZIGZAG_INDICES};

/// Argon2id memory cost in KiB (19 MiB).
pub const ARGON2_M_COST: u32 = 19 * 1024;
/// Argon2id time cost (iterations).
pub const ARGON2_T_COST: u32 = 2;
/// Argon2id parallelism.
pub const ARGON2_P_COST: u32 = 1;

/// Plaintext of the encrypted header: the per-write data nonce and the payload length.
/// Stored only as AEAD ciphertext - never in plaintext in the JPEG.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
struct EncryptedHeaderPlaintext {
	nonce_data: [u8; 12],
	data_len: u32,
}

/// Size of the encrypted header: [`EncryptedHeaderPlaintext`] + 16-byte AEAD tag.
const ENCRYPTED_HEADER_SIZE: usize = size_of::<EncryptedHeaderPlaintext>() + 16;

const HEADER_NONCE_LABEL: &[u8] = b"jpegfs header nonce v1";

const _: () = assert!(size_of::<EncryptedHeaderPlaintext>() == 16);

#[derive(Debug, Error)]
pub enum CryptoError {
	#[error("failed to decode JPEG: {0}")]
	Jpeg(#[from] JpegError),
	#[error("key derivation failed: {0}")]
	KeyDerivation(argon2::Error),
	#[error("JPEG file error: {0}")]
	JpegFile(#[from] JpegFileError),
	#[error("I/O error: {0}")]
	Io(#[from] io::Error),
	#[error("AEAD encryption/decryption failed")]
	Aead,
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

/// Derives a 12-byte nonce by hashing the key with a domain label.
fn derive_nonce(key: &[u8; 32], label: &[u8]) -> [u8; 12] {
	let mut h = Sha256::new();
	h.update(key);
	h.update(label);
	h.finalize()[..12].try_into().unwrap()
}

/// Encrypts `plaintext` and embeds the ciphertext into the JPEG at `path` via LSB
/// encrypts `plaintext` and embeds the ciphertext into `jpeg_data`
///
/// Nothing written into the JPEG is in plaintext. Layout:
/// ```text
/// [ AEAD(key, nonce_h, rand_nonce_data[12] || len_u32[4]) : 32 bytes ]
/// [ AEAD(key, rand_nonce_data, plaintext)                 : len + 16 bytes ]
/// ```
pub fn write_encrypted_with_key(jpeg_data: &[u8], key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
	let nonce_header = derive_nonce(key, HEADER_NONCE_LABEL);
	let nonce_data: [u8; 12] = rand::random();

	let cipher = ChaCha20Poly1305::new(key.into());

	// Encrypt header: random data nonce + payload length.
	let header_plaintext = EncryptedHeaderPlaintext {
		nonce_data,
		data_len: plaintext.len() as u32,
	};
	let encrypted_header = cipher
		.encrypt(Nonce::from_slice(&nonce_header), header_plaintext.as_bytes())
		.map_err(|_| CryptoError::Aead)?;
	debug_assert_eq!(encrypted_header.len(), ENCRYPTED_HEADER_SIZE);

	// Encrypt payload.
	let encrypted_data = cipher
		.encrypt(Nonce::from_slice(&nonce_data), plaintext)
		.map_err(|_| CryptoError::Aead)?;

	let mut ciphertext = encrypted_header;
	ciphertext.extend_from_slice(&encrypted_data);

	let mut session = JpegSession::new(PathBuf::new(), jpeg_data.to_vec())?;
	session.write_data(&ciphertext)?;
	session.to_jpeg_bytes().map_err(Into::into)
}

/// Core decryption: reads and decrypts ciphertext embedded in `jpeg_data`.
pub fn read_encrypted_with_key(jpeg_data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
	let nonce_h = derive_nonce(key, HEADER_NONCE_LABEL);
	let cipher = ChaCha20Poly1305::new(key.into());

	let mut session = JpegSession::new(PathBuf::new(), jpeg_data.to_vec())?;

	// Read and decrypt header to recover the data nonce and payload length.
	let encrypted_header = session.read_data(ENCRYPTED_HEADER_SIZE)?;
	let header_plaintext_bytes = cipher
		.decrypt(Nonce::from_slice(&nonce_h), encrypted_header.as_ref())
		.map_err(|_| CryptoError::Aead)?;
	let header_plaintext = EncryptedHeaderPlaintext::read_from_bytes(&header_plaintext_bytes).unwrap();

	// Read and decrypt payload.
	let encrypted_data = session.read_data(header_plaintext.data_len as usize + 16)?;
	cipher
		.decrypt(Nonce::from_slice(&header_plaintext.nonce_data), encrypted_data.as_ref())
		.map_err(|_| CryptoError::Aead)
}

/// Encrypts `plaintext` and embeds the ciphertext into the JPEG file at `path`.
pub fn write_encrypted_to_jpeg(path: &Path, passphrase: &str, plaintext: &[u8]) -> Result<(), CryptoError> {
	let jpeg_bytes = fs::read(path)?;
	let key = derive_key_for_jpeg(&jpeg_bytes, passphrase)?;
	let output = write_encrypted_with_key(&jpeg_bytes, &key, plaintext)?;
	fs::write(path, output)?;
	Ok(())
}

/// Reads and decrypts data previously written to the JPEG at `path` by
/// [`write_encrypted_to_jpeg`]. Returns an error if the passphrase is wrong or the
/// JPEG has not been written to with this scheme.
pub fn read_encrypted_from_jpeg(path: &Path, passphrase: &str) -> Result<Vec<u8>, CryptoError> {
	let jpeg_bytes = fs::read(path)?;
	let key = derive_key_for_jpeg(&jpeg_bytes, passphrase)?;
	read_encrypted_with_key(&jpeg_bytes, &key)
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

	#[test]
	fn encrypt_decrypt_roundtrip() {
		let key = derive_key_for_jpeg(OTHER_JPEG, "secret").unwrap();
		let plaintext = b"hello encrypted world";

		let new_jpeg = write_encrypted_with_key(OTHER_JPEG, &key, plaintext).unwrap();
		let recovered = read_encrypted_with_key(&new_jpeg, &key).unwrap();

		assert_eq!(recovered, plaintext);
	}

	#[test]
	fn wrong_key_fails_decryption() {
		let key_correct = derive_key_for_jpeg(OTHER_JPEG, "correct").unwrap();
		let key_wrong = derive_key_for_jpeg(OTHER_JPEG, "wrong").unwrap();

		let new_jpeg = write_encrypted_with_key(OTHER_JPEG, &key_correct, b"data").unwrap();
		let result = read_encrypted_with_key(&new_jpeg, &key_wrong);

		assert!(matches!(result, Err(CryptoError::Aead)));
	}

	#[test]
	fn each_write_produces_different_ciphertext() {
		let key = derive_key_for_jpeg(OTHER_JPEG, "pass").unwrap();

		let jpeg_a = write_encrypted_with_key(OTHER_JPEG, &key, b"same plaintext").unwrap();
		let jpeg_b = write_encrypted_with_key(OTHER_JPEG, &key, b"same plaintext").unwrap();

		assert_ne!(
			jpeg_a, jpeg_b,
			"Two writes with same key should differ due to random nonce"
		);
	}
}
