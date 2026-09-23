use std::mem::size_of;
use std::path::Path;
use std::{fs, io};

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::jpeg::{JpegError, OwnedJpeg, read_owned_jpeg};
use crate::jpeg_file::{JpegFileError, JpegSession};
use crate::strategy::EmbeddingStrategyId;

/// Argon2id memory cost in KiB (19 MiB).
pub const ARGON2_M_COST: u32 = 19 * 1024;
/// Argon2id time cost (iterations).
pub const ARGON2_T_COST: u32 = 2;
/// Argon2id parallelism.
pub const ARGON2_P_COST: u32 = 1;

/// Public per-write nonce and masked little-endian payload length.
/// Authenticated as payload AAD; untrusted until payload verification succeeds.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
struct Header {
	nonce_data: [u8; 12],
	masked_data_len: [u8; 4],
}

const HEADER_SIZE: usize = size_of::<Header>();

pub const STRATEGY_MARKER_SIZE: usize = size_of::<u8>();
pub const STRATEGY_MARKER_SLOTS: usize = STRATEGY_MARKER_SIZE * 8;
const STRATEGY_MARKER_MASK_LABEL: &[u8] = b"jpegfs strategy marker mask v1";

/// Total bytes added by the encryption layer to any plaintext written into a JPEG.
/// Consists of the 1-byte embedding-strategy marker, the 16-byte header,
/// and the 16-byte AEAD tag on the payload.
pub const CRYPTO_OVERHEAD: usize = STRATEGY_MARKER_SIZE + HEADER_SIZE + 16;
const _: () = assert!(CRYPTO_OVERHEAD == 33);

const LENGTH_MASK_LABEL: &[u8] = b"jpegfs length masking v1";

const _: () = assert!(HEADER_SIZE == 16);

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
	#[error("payload length exceeds the u32 format limit")]
	PayloadTooLarge,
	#[error("unsupported embedding strategy id {id}")]
	UnsupportedEmbeddingStrategy { id: u8 },
}

/// Derives a deterministic 32-byte salt from the DC coefficients which are never
pub fn derive_salt_from_dct(owned_jpeg: &OwnedJpeg) -> [u8; 32] {
	let mut hasher = Sha256::new();
	for component in &owned_jpeg.components {
		for block in &component.blocks {
			hasher.update(block[0].to_le_bytes());
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

/// XOR is symmetric: apply to either the encoded length or its masked bytes.
fn mask_data_len(key: &[u8; 32], nonce: &[u8; 12], mut bytes: [u8; 4]) -> [u8; 4] {
	let mut masking_key = [0u8; 32];
	Hkdf::<Sha256>::new(None, key)
		.expand(LENGTH_MASK_LABEL, &mut masking_key)
		.expect("32 bytes is a valid HKDF-SHA256 output length");
	let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&masking_key).expect("HMAC accepts a 32-byte key");
	mac.update(nonce);
	let mask = mac.finalize().into_bytes();
	for (byte, mask_byte) in bytes.iter_mut().zip(mask.iter()) {
		*byte ^= mask_byte;
	}
	bytes
}

fn derive_strategy_marker_mask(key: &[u8; 32]) -> u8 {
	let mut h = Sha256::new();
	h.update(key);
	h.update(STRATEGY_MARKER_MASK_LABEL);
	h.finalize()[0]
}

/// Masks the strategy ID with the embedding key for storage in the JPEG.
pub fn encode_strategy_marker(key: &[u8; 32], strategy_id: EmbeddingStrategyId) -> u8 {
	(u8::from(strategy_id)) ^ derive_strategy_marker_mask(key)
}

fn decode_strategy_marker(key: &[u8; 32], encoded: u8) -> Result<EmbeddingStrategyId, CryptoError> {
	let id = encoded ^ derive_strategy_marker_mask(key);
	id.try_into()
}

/// Encrypts `plaintext` and embeds the ciphertext into `jpeg_data`
///
/// Layout (incompatible with the former separately encrypted header):
/// ```text
/// [ embedding strategy marker : 1 byte ]
/// [ header = rand_nonce_data[12] || masked_len_le[4] : 16 bytes ]
/// [ AEAD(key, rand_nonce_data, plaintext, AAD=header) : len + 16 bytes ]
/// ```
pub fn write_encrypted_with_key(
	jpeg_data: &[u8],
	key: &[u8; 32],
	plaintext: &[u8],
	embedding_strategy_id: EmbeddingStrategyId,
) -> Result<Vec<u8>, CryptoError> {
	let data_len = u32::try_from(plaintext.len()).map_err(|_| CryptoError::PayloadTooLarge)?;
	let nonce_data: [u8; 12] = rand::random();

	let cipher = ChaCha20Poly1305::new(key.into());

	let header = Header {
		nonce_data,
		masked_data_len: mask_data_len(key, &nonce_data, data_len.to_le_bytes()),
	};

	// Authenticate the exact stored header along with the encrypted payload.
	let encrypted_data = cipher
		.encrypt(
			Nonce::from_slice(&nonce_data),
			Payload {
				msg: plaintext,
				aad: header.as_bytes(),
			},
		)
		.map_err(|_| CryptoError::Aead)?;

	let mut ciphertext = header.as_bytes().to_vec();
	ciphertext.extend_from_slice(&encrypted_data);

	let mut session = JpegSession::new(jpeg_data.to_vec())?;
	session.write_strategy_marker_lsb(encode_strategy_marker(key, embedding_strategy_id));
	let mut embedding_session = session.into_embedding_session(embedding_strategy_id, *key);
	embedding_session.write(&ciphertext)?;
	embedding_session.to_jpeg_bytes().map_err(Into::into)
}

/// Core decryption: reads and decrypts ciphertext embedded in `jpeg_data`.
pub fn read_encrypted_with_key_and_strategy(
	jpeg_data: &[u8],
	key: &[u8; 32],
) -> Result<(Vec<u8>, EmbeddingStrategyId), CryptoError> {
	let cipher = ChaCha20Poly1305::new(key.into());

	let session = JpegSession::new(jpeg_data.to_vec())?;
	let strategy_marker = session.read_strategy_marker_lsb();
	let strategy_id = decode_strategy_marker(key, strategy_marker)?;
	let embedding_session = session.into_embedding_session(strategy_id, *key);

	let header_bytes = embedding_session.read(HEADER_SIZE)?;
	let header = Header::read_from_bytes(&header_bytes).expect("size is checked");
	let data_len = u32::from_le_bytes(mask_data_len(key, &header.nonce_data, header.masked_data_len));
	// The header is not authenticated yet. Reject impossible lengths before allocation,
	// using the same error as authentication failure (including for wrong keys).
	let total_len = usize::try_from(data_len)
		.ok()
		.and_then(|len| len.checked_add(HEADER_SIZE + 16))
		.filter(|&len| len <= embedding_session.capacity())
		.ok_or(CryptoError::Aead)?;
	let ciphertext = embedding_session.read(total_len)?;
	let encrypted_data = &ciphertext[HEADER_SIZE..];
	let plaintext = cipher
		.decrypt(
			Nonce::from_slice(&header.nonce_data),
			Payload {
				msg: encrypted_data,
				aad: &header_bytes,
			},
		)
		.map_err(|_| CryptoError::Aead)?;
	Ok((plaintext, strategy_id))
}

pub fn read_encrypted_with_key(jpeg_data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
	read_encrypted_with_key_and_strategy(jpeg_data, key).map(|(plaintext, _)| plaintext)
}

/// Encrypts `plaintext` and embeds the ciphertext into the JPEG file at `path`.
pub fn write_encrypted_to_jpeg(
	path: &Path,
	passphrase: &str,
	plaintext: &[u8],
	embedding_strategy_id: EmbeddingStrategyId,
) -> Result<(), CryptoError> {
	let jpeg_bytes = fs::read(path)?;
	let key = derive_key_for_jpeg(&jpeg_bytes, passphrase)?;
	let output = write_encrypted_with_key(&jpeg_bytes, &key, plaintext, embedding_strategy_id)?;
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

	const GRAYSCALE_JPEG: &[u8] = include_bytes!("../test/CRW_2614_grayscale_384x287.jpg");
	const TINY_JPEG: &[u8] = include_bytes!("../fuzz/fixtures/tiny_crw_2609_16x8.jpg");
	const OTHER_JPEG: &[u8] = include_bytes!("../test/CRW_2614_(Elsterflutbecken).jpg");

	#[test]
	fn empty_payload_roundtrip_all_strategies() {
		for strategy in EmbeddingStrategyId::ALL {
			let encoded = write_encrypted_with_key(GRAYSCALE_JPEG, &[42; 32], b"", strategy).unwrap();
			assert!(read_encrypted_with_key(&encoded, &[42; 32]).unwrap().is_empty());
		}
	}

	#[test]
	fn tampered_header_and_payload_are_rejected() {
		let key = [42; 32];
		let data = b"authenticated payload";
		for strategy in EmbeddingStrategyId::ALL {
			let encoded = write_encrypted_with_key(GRAYSCALE_JPEG, &key, data, strategy).unwrap();
			// Flip each nonce/length byte, a payload byte, and a tag byte.
			for offset in (0..HEADER_SIZE).chain([HEADER_SIZE, HEADER_SIZE + data.len()]) {
				let mut session = JpegSession::new(encoded.clone())
					.unwrap()
					.into_embedding_session(strategy, key);
				let mut bytes = session.read(HEADER_SIZE + data.len() + 16).unwrap();
				bytes[offset] ^= 1;
				session.write(&bytes).unwrap();
				let tampered = session.to_jpeg_bytes().unwrap();
				assert!(
					matches!(read_encrypted_with_key(&tampered, &key), Err(CryptoError::Aead)),
					"strategy {strategy}, offset {offset}"
				);
			}
		}
	}

	#[test]
	fn oversized_header_length_is_rejected() {
		let key = [42; 32];
		let header = Header {
			nonce_data: [0; 12],
			masked_data_len: mask_data_len(&key, &[0; 12], u32::MAX.to_le_bytes()),
		};
		let mut session = JpegSession::new(GRAYSCALE_JPEG.to_vec()).unwrap();
		session.write_strategy_marker_lsb(encode_strategy_marker(&key, EmbeddingStrategyId::Lsb));
		let mut session = session.into_embedding_session(EmbeddingStrategyId::Lsb, key);
		session.write(header.as_bytes()).unwrap();
		assert!(matches!(
			read_encrypted_with_key(&session.to_jpeg_bytes().unwrap(), &key),
			Err(CryptoError::Aead)
		));
	}

	#[test]
	fn payload_tag_must_authenticate_stored_header() {
		let key = [42; 32];
		let data = b"payload";
		let header = Header {
			nonce_data: [0; 12],
			masked_data_len: mask_data_len(&key, &[0; 12], (data.len() as u32).to_le_bytes()),
		};
		let cipher = ChaCha20Poly1305::new((&key).into());
		// Valid nonce, length, and payload tag, but missing the header binding.
		let encrypted = cipher
			.encrypt(Nonce::from_slice(&header.nonce_data), data.as_slice())
			.unwrap();
		let mut bytes = header.as_bytes().to_vec();
		bytes.extend_from_slice(&encrypted);
		let mut session = JpegSession::new(GRAYSCALE_JPEG.to_vec()).unwrap();
		session.write_strategy_marker_lsb(encode_strategy_marker(&key, EmbeddingStrategyId::Lsb));
		let mut session = session.into_embedding_session(EmbeddingStrategyId::Lsb, key);
		session.write(&bytes).unwrap();
		assert!(matches!(
			read_encrypted_with_key(&session.to_jpeg_bytes().unwrap(), &key),
			Err(CryptoError::Aead)
		));
	}

	#[test]
	fn grayscale_encrypt_decrypt_roundtrip_all_strategies() {
		let key = [42; 32];
		let plaintext = b"grayscale encrypted roundtrip";

		for strategy in EmbeddingStrategyId::ALL {
			let encoded = write_encrypted_with_key(GRAYSCALE_JPEG, &key, plaintext, strategy).unwrap();
			let encoded_jpeg = unsafe { read_owned_jpeg(&encoded) }.unwrap();
			assert_eq!(encoded_jpeg.components.len(), 1);

			let recovered = read_encrypted_with_key(&encoded, &key)
				.unwrap_or_else(|err| panic!("failed to decrypt with strategy {strategy}: {err}"));
			assert_eq!(recovered, plaintext, "failed with strategy {strategy}");
		}
	}

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

		let new_jpeg = write_encrypted_with_key(OTHER_JPEG, &key, plaintext, EmbeddingStrategyId::Lsb).unwrap();
		let recovered = read_encrypted_with_key(&new_jpeg, &key).unwrap();

		assert_eq!(recovered, plaintext);
	}

	#[test]
	fn wrong_key_fails_decryption() {
		let key_correct = derive_key_for_jpeg(OTHER_JPEG, "correct").unwrap();
		let key_wrong = derive_key_for_jpeg(OTHER_JPEG, "wrong").unwrap();

		let new_jpeg = write_encrypted_with_key(OTHER_JPEG, &key_correct, b"data", EmbeddingStrategyId::Lsb).unwrap();
		let result = read_encrypted_with_key(&new_jpeg, &key_wrong);

		assert!(matches!(
			result,
			Err(CryptoError::UnsupportedEmbeddingStrategy { .. } | CryptoError::Aead)
		));
	}

	#[test]
	fn each_write_produces_different_ciphertext() {
		let key = derive_key_for_jpeg(OTHER_JPEG, "pass").unwrap();

		let jpeg_a = write_encrypted_with_key(OTHER_JPEG, &key, b"same plaintext", EmbeddingStrategyId::Lsb).unwrap();
		let jpeg_b = write_encrypted_with_key(OTHER_JPEG, &key, b"same plaintext", EmbeddingStrategyId::Lsb).unwrap();

		assert_ne!(
			jpeg_a, jpeg_b,
			"Two writes with same key should differ due to random nonce"
		);
	}

	#[test]
	fn strategy_marker_roundtrip_encodes_strategy() {
		let key = derive_key_for_jpeg(OTHER_JPEG, "secret").unwrap();

		for strategy in EmbeddingStrategyId::ALL {
			let encoded = encode_strategy_marker(&key, strategy);

			assert_ne!(encoded, u8::from(strategy));
			assert_eq!(decode_strategy_marker(&key, encoded).unwrap(), strategy);
		}
	}
}
