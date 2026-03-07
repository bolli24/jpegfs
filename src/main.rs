use anyhow::Context;
use std::path::PathBuf;
use std::sync::mpsc;

use fuser::{Config as FuseConfig, MountOption, spawn_mount2};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use simplelog::{ColorChoice, Config as LogConfig, LevelFilter, TermLogger, TerminalMode};

use jpegfs::filesystem::FileSystem;

const INPUT_PATH: &str = "./test/CRW_2614_(Elsterflutbecken).jpg";
const OUTPUT_PATH: &str = "./test/output.jpg";
const DEFAULT_MOUNT_PATH: &str = "/tmp/jpegfs";

fn main() -> anyhow::Result<()> {
	TermLogger::init(
		LevelFilter::Info,
		LogConfig::default(),
		TerminalMode::Mixed,
		ColorChoice::Auto,
	)
	.context("failed to initialize terminal logger")?;

	let fs = FileSystem::new();
	let mut config = FuseConfig::default();
	config.mount_options = vec![
		MountOption::FSName("jpegfs".to_string()),
		MountOption::Subtype("jpegfs".to_string()),
		MountOption::RW,
		MountOption::DefaultPermissions,
	];

	let mount_path =
		PathBuf::from(std::env::var("JPEGFS_MOUNT_PATH").unwrap_or_else(|_| DEFAULT_MOUNT_PATH.to_string()));
	match std::fs::create_dir_all(&mount_path) {
		Ok(()) => {}
		Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
		Err(e) => {
			return Err(e).with_context(|| format!("failed to create mount directory at {}", mount_path.display()));
		}
	}
	anyhow::ensure!(
		mount_path.is_dir(),
		"mount path exists but is not a directory: {}",
		mount_path.display()
	);

	let session = spawn_mount2(fs, &mount_path, &config).context("failed to mount file system")?;
	let (shutdown_tx, shutdown_rx) = mpsc::channel();
	ctrlc::set_handler(move || {
		let _ = shutdown_tx.send(());
	})
	.context("failed to set shutdown signal handler")?;

	shutdown_rx.recv().context("failed to wait for shutdown signal")?;
	drop(session);

	Ok(())
}

/* fn main() -> anyhow::Result<()> {
	let crc = Crc::<u32>::new(&CRC_32_ISCSI);

	let file_info = init_file(PathBuf::from(INPUT_PATH).as_path())?;
	let mut output_file_info = file_info.copy_to(PathBuf::from(OUTPUT_PATH).as_path())?;

	let header = Header {
		id: 123,
		capacity: file_info.capacity() as usize,
	};

	let data = postcard::to_stdvec_crc32(&header, crc.digest()).context("failed to serialize header")?;

	println!("{data:?}");

	output_file_info.write_data(&data)?;

	let read_data = output_file_info.read_data(data.len())?;
	let decoded_header: Header =
		postcard::from_bytes_crc32(&read_data, crc.digest()).context("failed to deserialize header")?;
	println!("Read header: {decoded_header:?}");

	Ok(())
} */

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
		.context("argon2 failed")?;

	Ok(ChaCha20Rng::from_seed(seed))
}
