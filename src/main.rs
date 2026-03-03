use std::path::PathBuf;

use anyhow::Context;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crc::{CRC_32_ISCSI, Crc};

use jpegfs::{Header, file::init_file};

const INPUT_PATH: &str = "./test/CRW_2614_(Elsterflutbecken).jpg";
const OUTPUT_PATH: &str = "./test/output.jpg";

fn main() -> anyhow::Result<()> {
	let crc = Crc::<u32>::new(&CRC_32_ISCSI);

	let file_info = init_file(PathBuf::from(INPUT_PATH).as_path())?;
	let mut output_file_info = file_info.copy_to(PathBuf::from(OUTPUT_PATH).as_path())?;

	let header = Header {
		id: 123,
		capacity: file_info.capacity() as usize,
	};

	let data = postcard::to_stdvec_crc32(&header, crc.digest()).context("Error serializing header.")?;

	println!("{data:?}");

	output_file_info.write_data(&data)?;

	let read_data = output_file_info.read_data(data.len())?;
	let decoded_header: Header =
		postcard::from_bytes_crc32(&read_data, crc.digest()).context("Error deserializing header.")?;
	println!("Read header: {decoded_header:?}");

	Ok(())
}

pub fn rng_from_passphrase(passphrase: &str, salt: &[u8]) -> anyhow::Result<ChaCha20Rng> {
	let params = argon2::Params::new(
		19 * 1024, // m_cost in KiB (19 MiB)
		2,         // t_cost iterations
		1,         // p_cost parallelism
		Some(32),  // output length (seed size)
	)
	.expect("valid params");

	let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

	let mut seed = [0u8; 32];
	argon2
		.hash_password_into(passphrase.as_bytes(), salt, &mut seed)
		.context("Argon2 failed")?;

	Ok(ChaCha20Rng::from_seed(seed))
}
