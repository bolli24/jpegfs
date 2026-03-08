use anyhow::{Context, bail};
use std::path::{Path, PathBuf};
use std::sync::mpsc;

use fuser::{Config as FuseConfig, MountOption, spawn_mount2};
use log::{error, info};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use jpegfs::filesystem::{BLOCK_SIZE, FileSystem};
use jpegfs::jpeg_file::init_file;
use jpegfs::pager::{Pager, ValidatedPages};
use jpegfs::persistence::JpegBlockStore;

mod tui;

const DEFAULT_MOUNT_PATH: &str = "/tmp/jpegfs";
const MIN_BOOTSTRAP_PAGES: usize = 2;

struct PersistOnDrop {
	fs: FileSystem,
	stores: Vec<JpegBlockStore>,
	total_page_capacity: usize,
	persisted: bool,
}

impl PersistOnDrop {
	fn new(fs: FileSystem, stores: Vec<JpegBlockStore>, total_page_capacity: usize) -> Self {
		Self {
			fs,
			stores,
			total_page_capacity,
			persisted: false,
		}
	}

	fn persist_once(&mut self) -> anyhow::Result<()> {
		if self.persisted {
			return Ok(());
		}
		persist_filesystem(&mut self.stores, &self.fs, self.total_page_capacity)?;
		self.persisted = true;
		Ok(())
	}
}

impl Drop for PersistOnDrop {
	fn drop(&mut self) {
		if self.persisted {
			return;
		}
		if let Err(err) = persist_filesystem(&mut self.stores, &self.fs, self.total_page_capacity) {
			error!("failed to persist filesystem during drop: {err:#}");
		}
	}
}

fn main() -> anyhow::Result<()> {
	let (log_tx, log_rx) = mpsc::sync_channel(8_192);
	tui::init_tui_logger(log_tx).context("failed to initialize tui logger")?;

	let jpeg_dir = parse_jpeg_dir_arg()?;
	let jpeg_paths = discover_jpeg_paths(&jpeg_dir)?;

	let (stores, decoded_pages, total_page_capacity) = load_or_init_stores(&jpeg_paths)?;
	let fs = init_filesystem(decoded_pages, total_page_capacity)?;
	let mut persistence = PersistOnDrop::new(fs, stores, total_page_capacity);

	let mut config = FuseConfig::default();
	config.mount_options = vec![
		MountOption::FSName("jpegfs".to_string()),
		MountOption::Subtype("jpegfs".to_string()),
		MountOption::RW,
		MountOption::DefaultPermissions,
	];

	let mount_path = PathBuf::from(DEFAULT_MOUNT_PATH);
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

	let session = spawn_mount2(persistence.fs.clone(), &mount_path, &config).context("failed to mount file system")?;
	let (shutdown_tx, shutdown_rx) = mpsc::channel();
	ctrlc::set_handler(move || {
		let _ = shutdown_tx.send(());
	})
	.context("failed to set shutdown signal handler")?;

	tui::run_tui(&persistence.fs, &mount_path, &log_rx, &shutdown_rx)?;
	drop(session);
	log_filesystem_capacity("before exit", &persistence.fs, total_page_capacity);
	persistence.persist_once()?;

	Ok(())
}

fn parse_jpeg_dir_arg() -> anyhow::Result<PathBuf> {
	let mut args = std::env::args_os();
	let program = args.next().unwrap_or_default();
	let Some(jpeg_dir) = args.next() else {
		bail!("usage: {} <jpeg_dir>", Path::new(&program).display());
	};
	if args.next().is_some() {
		bail!("usage: {} <jpeg_dir>", Path::new(&program).display());
	}
	let jpeg_dir = PathBuf::from(jpeg_dir);
	anyhow::ensure!(
		jpeg_dir.is_dir(),
		"jpeg directory does not exist or is not a directory: {}",
		jpeg_dir.display()
	);
	Ok(jpeg_dir)
}

fn discover_jpeg_paths(jpeg_dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
	let mut paths = Vec::new();
	for entry in std::fs::read_dir(jpeg_dir)
		.with_context(|| format!("failed to read jpeg directory at {}", jpeg_dir.display()))?
	{
		let entry = entry.with_context(|| format!("failed to read entry in {}", jpeg_dir.display()))?;
		if !entry
			.file_type()
			.with_context(|| format!("failed to inspect file type for {}", entry.path().display()))?
			.is_file()
		{
			continue;
		}
		let path = entry.path();
		let is_jpeg = path
			.extension()
			.and_then(|ext| ext.to_str())
			.map(|ext| matches!(ext.to_ascii_lowercase().as_str(), "jpg" | "jpeg"))
			.unwrap_or(false);
		if is_jpeg {
			paths.push(path);
		}
	}

	paths.sort();
	anyhow::ensure!(
		!paths.is_empty(),
		"no JPEG files found in directory {}; expected at least one *.jpg or *.jpeg file",
		jpeg_dir.display()
	);
	Ok(paths)
}

fn load_or_init_stores(paths: &[PathBuf]) -> anyhow::Result<(Vec<JpegBlockStore>, ValidatedPages, usize)> {
	let mut stores = Vec::with_capacity(paths.len());
	let mut decoded_pages = ValidatedPages::empty();
	let mut total_page_capacity = 0usize;

	for path in paths {
		let mut file =
			init_file(path.as_path()).with_context(|| format!("failed to open JPEG store at {}", path.display()))?;
		let data = file
			.read_data(file.capacity())
			.with_context(|| format!("failed to read JPEG store data from {}", path.display()))?;
		let (store, pages) = JpegBlockStore::from_bytes_or_init_strict(file, &data)
			.with_context(|| format!("failed to load persisted pages from {}", path.display()))?;

		total_page_capacity = total_page_capacity
			.checked_add(store.page_capacity())
			.context("total page capacity overflow while loading JPEG stores")?;
		decoded_pages.append(pages);
		stores.push(store);
	}

	let decoded_pages = decoded_pages
		.validate(total_page_capacity)
		.context("combined persisted pages are invalid")?;

	Ok((stores, decoded_pages, total_page_capacity))
}

fn init_filesystem(decoded_pages: ValidatedPages, total_page_capacity: usize) -> anyhow::Result<FileSystem> {
	anyhow::ensure!(
		total_page_capacity >= MIN_BOOTSTRAP_PAGES,
		"insufficient total JPEG capacity: {total_page_capacity} pages available, at least {MIN_BOOTSTRAP_PAGES} are required"
	);

	let total_bytes_limit = total_page_capacity.saturating_mul(BLOCK_SIZE);
	let fs = if decoded_pages.is_empty() {
		FileSystem::new_with_limits(total_page_capacity, total_bytes_limit)
			.map_err(anyhow::Error::msg)
			.context("failed to initialize fresh filesystem from JPEG capacity")?
	} else {
		let pager = Pager::from_validated_pages(decoded_pages, total_page_capacity)
			.context("failed to decode persisted pager state from JPEG stores")?;
		FileSystem::from_pager(pager, total_bytes_limit)
			.map_err(anyhow::Error::msg)
			.context("persisted filesystem state is invalid")?
	};

	log_filesystem_capacity("initialized", &fs, total_page_capacity);
	Ok(fs)
}

fn log_filesystem_capacity(stage: &str, fs: &FileSystem, total_page_capacity: usize) {
	let (counts, used_bytes) = {
		let state = fs.state.read();
		(state.pager.block_counts(), state.used_bytes())
	};
	info!(
		"{stage} filesystem capacity: {total_page_capacity} blocks ({} bytes), used: {} blocks ({} bytes) [inodes: {}, dir_entries: {}, data_bytes: {}]",
		total_page_capacity.saturating_mul(BLOCK_SIZE),
		counts.total(),
		used_bytes,
		counts.inodes,
		counts.dir_entries,
		counts.data_bytes
	);
}

fn persist_filesystem(
	stores: &mut [JpegBlockStore],
	fs: &FileSystem,
	total_page_capacity: usize,
) -> anyhow::Result<()> {
	let encoded_pages = {
		let state = fs.state.read();
		state
			.check_invariants()
			.map_err(anyhow::Error::msg)
			.context("filesystem invariants failed before persistence")?;
		state
			.pager
			.encode_blocks()
			.context("failed to encode pager blocks for persistence")?
	};

	anyhow::ensure!(
		encoded_pages.len() <= total_page_capacity,
		"encoded pager needs {} pages but only {} pages are available across JPEG stores",
		encoded_pages.len(),
		total_page_capacity
	);

	let mut cursor = 0usize;
	for store in stores {
		let end = (cursor + store.page_capacity()).min(encoded_pages.len());
		store
			.persist_blocks(&encoded_pages[cursor..end])
			.context("failed to persist encoded pages to JPEG store")?;
		cursor = end;
	}

	anyhow::ensure!(
		cursor == encoded_pages.len(),
		"internal error: {} encoded pages were not persisted",
		encoded_pages.len().saturating_sub(cursor)
	);
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
		.context("argon2 failed")?;

	Ok(ChaCha20Rng::from_seed(seed))
}
