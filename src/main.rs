use anyhow::Context;
use clap::{Parser, Subcommand};
use rand::Rng;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[cfg(unix)]
use std::collections::{HashMap, HashSet};
#[cfg(unix)]
use std::io::BufRead;
#[cfg(unix)]
use std::sync::mpsc;
#[cfg(unix)]
use std::time::Instant;

#[cfg(unix)]
use fuser::{Config as FuseConfig, MountOption, spawn_mount2};
use indicatif::{ProgressBar, ProgressStyle};
use log::{error, info, warn};
use rayon::ThreadPool;
use rayon::prelude::*;

#[cfg(unix)]
use jpegfs::crypto::{CryptoError, derive_key_for_jpeg, read_encrypted_with_key};
#[cfg(unix)]
use jpegfs::filesystem::FileSystem;
use jpegfs::jpeg::{get_capacity, read_owned_jpeg, write_owned_jpeg};
use jpegfs::jpeg_file::JpegSession;
#[cfg(unix)]
use jpegfs::pager::{BLOCK_SIZE, DecodedPages, PageId, Pager};
use jpegfs::persistence::JpegBlockStore;

#[cfg(unix)]
mod tui;

#[cfg(unix)]
const MIN_BOOTSTRAP_PAGES: usize = 2;

#[derive(Debug, Eq, Parser, PartialEq)]
#[command(name = "jpegfs", about = "JPEG-backed steganographic filesystem")]
struct CliArgs {
	#[command(subcommand)]
	command: CliCommand,
}

#[derive(Debug, Eq, PartialEq, Subcommand)]
enum CliCommand {
	#[cfg(unix)]
	#[command(
		about = "Mount the filesystem",
		long_about = "Mount the filesystem and open the TUI. If the mount directory does not exist, \
		jpegfs creates it and removes it again on shutdown. Pre-existing mount directories are left in place."
	)]
	Mount {
		#[arg(help = "Directory containing JPEG storage files")]
		jpeg_dir: PathBuf,
		#[arg(help = "Mount point for the filesystem; created if missing")]
		mount_dir: PathBuf,
	},
	#[cfg(unix)]
	#[command(about = "Print filesystem statistics")]
	Stat {
		#[arg(help = "Directory containing JPEG storage files")]
		jpeg_dir: PathBuf,
	},
	#[command(about = "Re-encode JPEGs without embedding")]
	Reencode {
		#[arg(help = "Directory containing input JPEG files")]
		input_dir: PathBuf,
		#[arg(help = "Directory to write re-encoded JPEG files")]
		output_dir: PathBuf,
	},
	#[command(about = "Simulate a real persist by embedding random bytes of the correct length (skips encryption).")]
	Simulate {
		#[arg(help = "Directory containing input JPEG files")]
		input_dir: PathBuf,
		#[arg(help = "Directory to write encoded JPEG files")]
		output_dir: PathBuf,
	},
}

#[cfg(unix)]
#[derive(Debug, Eq, PartialEq)]
struct MountDirState {
	mount_dir: PathBuf,
	created_by_process: bool,
}

#[cfg(unix)]
impl Drop for MountDirState {
	fn drop(&mut self) {
		if let Err(err) = cleanup_mount_dir(&self.mount_dir, self.created_by_process) {
			warn!("failed to remove mount directory {}: {err:#}", self.mount_dir.display());
		}
	}
}

#[cfg(unix)]
struct PersistOnDrop {
	fs: FileSystem,
	stores: Vec<JpegBlockStore>,
	total_page_capacity: usize,
	persisted: bool,
}

#[cfg(unix)]
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

#[cfg(unix)]
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
	let cli_args = parse_cli_args()?;

	if let CliCommand::Reencode { input_dir, output_dir } = cli_args.command {
		return run_reencode(&input_dir, &output_dir);
	}
	if let CliCommand::Simulate { input_dir, output_dir } = cli_args.command {
		return run_simulate(&input_dir, &output_dir);
	}

	#[cfg(unix)]
	return run_mount_or_stat(cli_args);

	#[cfg(not(unix))]
	unreachable!("only reencode and simulate are available on non-unix platforms")
}

#[cfg(unix)]
fn run_mount_or_stat(cli_args: CliArgs) -> anyhow::Result<()> {
	let (log_tx, log_rx) = mpsc::sync_channel(8_192);
	tui::init_tui_logger(log_tx).context("failed to initialize tui logger")?;

	let passphrase = resolve_passphrase()?;

	let jpeg_dir = match &cli_args.command {
		CliCommand::Mount { jpeg_dir, .. } | CliCommand::Stat { jpeg_dir } => jpeg_dir,
		CliCommand::Reencode { .. } | CliCommand::Simulate { .. } => unreachable!(),
	};
	let jpeg_paths = discover_jpeg_paths(jpeg_dir)?;
	let probed_stores = probe_stores(&jpeg_paths, &passphrase)?;

	let mount_dir = match cli_args.command {
		CliCommand::Mount { mount_dir, .. } => mount_dir,
		CliCommand::Stat { .. } => return run_stat(probed_stores),
		CliCommand::Reencode { .. } | CliCommand::Simulate { .. } => unreachable!(),
	};
	let (stores, decoded_pages, total_page_capacity) = load_or_init_stores(probed_stores, &passphrase)?;
	let fs = init_filesystem(decoded_pages, total_page_capacity)?;
	let mut persistence = PersistOnDrop::new(fs, stores, total_page_capacity);

	let mut config = FuseConfig::default();
	config.mount_options = vec![
		MountOption::FSName("jpegfs".to_string()),
		MountOption::Subtype("jpegfs".to_string()),
		MountOption::RW,
		MountOption::DefaultPermissions,
	];

	let _mount_dir_state = prepare_mount_dir(&mount_dir)?;

	let session = spawn_mount2(persistence.fs.clone(), &mount_dir, &config).context("failed to mount file system")?;
	let (shutdown_tx, shutdown_rx) = mpsc::channel();
	ctrlc::set_handler(move || {
		let _ = shutdown_tx.send(());
	})
	.context("failed to set shutdown signal handler")?;

	tui::run_tui(&persistence.fs, &mount_dir, &log_rx, &shutdown_rx)?;
	drop(session);
	log_filesystem_capacity("before exit", &persistence.fs, total_page_capacity);
	let shutdown_persist_started_at = Instant::now();
	persistence.persist_once()?;
	println!(
		"Shutdown persistence completed in {:?}",
		shutdown_persist_started_at.elapsed()
	);

	Ok(())
}

#[cfg(unix)]
fn resolve_passphrase() -> anyhow::Result<String> {
	if let Ok(p) = std::env::var("JPEGFS_PASSPHRASE") {
		return Ok(p);
	}
	rpassword::prompt_password("jpegfs passphrase: ").context("failed to read passphrase from terminal")
}

fn parse_cli_args() -> anyhow::Result<CliArgs> {
	validate_cli_args(CliArgs::parse())
}

fn validate_cli_args(cli_args: CliArgs) -> anyhow::Result<CliArgs> {
	let jpeg_dir = match &cli_args.command {
		#[cfg(unix)]
		CliCommand::Mount { jpeg_dir, .. } => jpeg_dir,
		#[cfg(unix)]
		CliCommand::Stat { jpeg_dir } => jpeg_dir,
		CliCommand::Reencode { input_dir, .. } | CliCommand::Simulate { input_dir, .. } => input_dir,
	};
	anyhow::ensure!(
		jpeg_dir.is_dir(),
		"jpeg directory does not exist or is not a directory: {}",
		jpeg_dir.display()
	);
	Ok(cli_args)
}

#[cfg(unix)]
fn prepare_mount_dir(mount_dir: &Path) -> anyhow::Result<MountDirState> {
	if mount_dir.exists() {
		anyhow::ensure!(
			mount_dir.is_dir(),
			"mount path exists but is not a directory: {}",
			mount_dir.display()
		);
		return Ok(MountDirState {
			mount_dir: mount_dir.to_path_buf(),
			created_by_process: false,
		});
	}

	std::fs::create_dir_all(mount_dir)
		.with_context(|| format!("failed to create mount directory at {}", mount_dir.display()))?;
	Ok(MountDirState {
		mount_dir: mount_dir.to_path_buf(),
		created_by_process: true,
	})
}

#[cfg(unix)]
fn cleanup_mount_dir(mount_dir: &Path, created_by_process: bool) -> anyhow::Result<bool> {
	if !created_by_process || !mount_dir.exists() {
		return Ok(false);
	}

	anyhow::ensure!(
		mount_dir.is_dir(),
		"mount path is no longer a directory: {}",
		mount_dir.display()
	);
	std::fs::remove_dir(mount_dir)
		.with_context(|| format!("failed to remove mount directory at {}", mount_dir.display()))?;
	Ok(true)
}

#[cfg(unix)]
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

fn discover_jpeg_paths_recursive(input_dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
	let mut paths = Vec::new();
	for entry in WalkDir::new(input_dir).sort_by_file_name() {
		let entry = entry.with_context(|| format!("failed to read directory entry under {}", input_dir.display()))?;
		if !entry.file_type().is_file() {
			continue;
		}
		let path = entry.into_path();
		let is_jpeg = path
			.extension()
			.and_then(|ext| ext.to_str())
			.map(|ext| matches!(ext.to_ascii_lowercase().as_str(), "jpg" | "jpeg"))
			.unwrap_or(false);
		if is_jpeg {
			paths.push(path);
		}
	}
	anyhow::ensure!(!paths.is_empty(), "no JPEG files found under {}", input_dir.display());
	Ok(paths)
}

#[cfg(unix)]
struct LoadedStore {
	store: JpegBlockStore,
	pages: DecodedPages,
}

#[cfg(unix)]
struct ProbedStore {
	index: usize,
	path: PathBuf,
	jpeg_capacity: usize,
	theoretical_page_capacity: usize,
	jpeg_bytes: Vec<u8>,
	key: [u8; 32],
	decrypted_data: Option<Vec<u8>>,
}

#[cfg(unix)]
#[derive(Debug, Eq, PartialEq)]
enum StatProbeSummary {
	FilesystemStats,
	CapacityOnly {
		failed_paths: Vec<PathBuf>,
		total_theoretical_page_capacity: usize,
	},
}

#[cfg(unix)]
fn probe_stores(paths: &[PathBuf], passphrase: &str) -> anyhow::Result<Vec<ProbedStore>> {
	let decode_started_at = Instant::now();
	let (pool, pb, label) = jpeg_operation_setup("probe", paths.len())?;
	let probed: Vec<anyhow::Result<ProbedStore>> = pool.install(|| {
		paths
			.par_iter()
			.enumerate()
			.map(|(index, path)| {
				let result = probe_one_store(index, path.as_path(), passphrase);
				pb.inc(1);
				result
			})
			.collect()
	});
	eprintln!("[{label}] done in {:.1?}", pb.elapsed());
	pb.finish_and_clear();

	let mut probed = probed.into_iter().collect::<anyhow::Result<Vec<_>>>()?;
	probed.sort_by_key(|store| store.index);

	info!(
		"Probed {} JPEG stores in {:?}",
		paths.len(),
		decode_started_at.elapsed()
	);

	Ok(probed)
}

#[cfg(unix)]
fn load_or_init_stores(
	probed_stores: Vec<ProbedStore>,
	passphrase: &str,
) -> anyhow::Result<(Vec<JpegBlockStore>, DecodedPages, usize)> {
	// Collect stores whose decryption failed (wrong passphrase or fresh JPEG).
	let failed_paths: Vec<&PathBuf> = probed_stores
		.iter()
		.filter(|store| store.decrypted_data.is_none())
		.map(|store| &store.path)
		.collect();

	if !failed_paths.is_empty() {
		eprintln!("{} JPEG store(s) could not be decrypted:", failed_paths.len());
		for path in &failed_paths {
			eprintln!("  {}", path.display());
		}
		eprintln!("Passphrase wrong or stores not initialized.");
		eprint!("Type OVERWRITE to initialize empty (possible existing data will be lost), or press Enter to abort: ");

		let stdin = std::io::stdin();
		let mut input = String::new();
		stdin
			.lock()
			.read_line(&mut input)
			.context("failed to read confirmation from stdin")?;
		anyhow::ensure!(
			input.trim() == "OVERWRITE",
			"aborted: encrypted JPEG stores could not be decrypted"
		);

		// Re-prompt for the passphrase so the user confirms their intended key
		// before irreversibly overwriting data.
		let confirmed = rpassword::prompt_password("confirm passphrase: ")
			.context("failed to read passphrase confirmation from terminal")?;
		anyhow::ensure!(
			confirmed == passphrase,
			"passphrase confirmation did not match - aborting to avoid data loss"
		);
	}

	let mut stores = Vec::with_capacity(probed_stores.len());
	let mut decoded_pages = DecodedPages::empty();
	let mut total_page_capacity = 0usize;

	for probed_store in probed_stores {
		let ProbedStore {
			path,
			jpeg_capacity,
			jpeg_bytes,
			key,
			decrypted_data,
			..
		} = probed_store;
		let decrypted_data = decrypted_data.unwrap_or_default();
		let (store, pages) =
			JpegBlockStore::from_bytes_or_init_strict(path.clone(), &decrypted_data, jpeg_capacity, key, jpeg_bytes)
				.with_context(|| format!("failed to load persisted pages from {}", path.display()))?;
		let loaded_store = LoadedStore { pages, store };
		total_page_capacity = total_page_capacity
			.checked_add(loaded_store.store.page_capacity())
			.context("total page capacity overflow while loading JPEG stores")?;
		decoded_pages.append(loaded_store.pages);
		stores.push(loaded_store.store);
	}

	Ok((stores, decoded_pages, total_page_capacity))
}

#[cfg(unix)]
fn probe_one_store(index: usize, path: &Path, passphrase: &str) -> anyhow::Result<ProbedStore> {
	let jpeg_bytes =
		std::fs::read(path).with_context(|| format!("failed to read JPEG bytes from {}", path.display()))?;

	let jpeg_capacity =
		get_capacity(&jpeg_bytes).with_context(|| format!("failed to compute JPEG capacity for {}", path.display()))?;
	let theoretical_page_capacity = JpegBlockStore::page_capacity_for_jpeg_capacity(jpeg_capacity)
		.with_context(|| format!("failed to compute theoretical store capacity for {}", path.display()))?;

	let key = derive_key_for_jpeg(&jpeg_bytes, passphrase)
		.with_context(|| format!("failed to derive encryption key for {}", path.display()))?;

	let decrypted_data = match read_encrypted_with_key(&jpeg_bytes, &key) {
		Ok(data) => Some(data),
		Err(CryptoError::Aead) => None,
		Err(e) => return Err(e).context(format!("unexpected error decrypting {}", path.display())),
	};

	Ok(ProbedStore {
		index,
		path: path.to_path_buf(),
		jpeg_capacity,
		theoretical_page_capacity,
		jpeg_bytes,
		key,
		decrypted_data,
	})
}

#[cfg(unix)]
fn run_stat(probed_stores: Vec<ProbedStore>) -> anyhow::Result<()> {
	match summarize_stat_probes(&probed_stores)? {
		StatProbeSummary::FilesystemStats => {}
		StatProbeSummary::CapacityOnly {
			failed_paths,
			total_theoretical_page_capacity,
		} => {
			eprintln!("{} JPEG store(s) could not be decrypted:", failed_paths.len());
			for path in &failed_paths {
				eprintln!("  {}", path.display());
			}
			eprintln!("Usage cannot be verified without decrypting every JPEG store.");
			print_theoretical_capacity(total_theoretical_page_capacity);
			return Ok(());
		}
	}

	let mut decoded_pages = DecodedPages::empty();
	let mut total_page_capacity = 0usize;
	for probed_store in probed_stores {
		let ProbedStore {
			path, decrypted_data, ..
		} = probed_store;
		let decrypted_data = decrypted_data.context("internal error: stat expected decrypted store data")?;
		let (page_capacity, pages) = JpegBlockStore::decode_stat(&decrypted_data)
			.with_context(|| format!("failed to load persisted pages from {}", path.display()))?;
		total_page_capacity = total_page_capacity
			.checked_add(page_capacity)
			.context("total page capacity overflow while loading JPEG stores")?;
		decoded_pages.append(pages);
	}

	let fs = init_filesystem(decoded_pages, total_page_capacity)?;
	let stats = {
		let state = fs.state.read();
		state.dashboard_stats()
	};
	println!();
	for line in stats.format(false) {
		println!("{line}");
	}
	Ok(())
}

fn run_reencode(input_dir: &Path, output_dir: &Path) -> anyhow::Result<()> {
	let jpeg_paths = discover_jpeg_paths_recursive(input_dir)?;
	std::fs::create_dir_all(output_dir)
		.with_context(|| format!("failed to create output directory {}", output_dir.display()))?;

	let (pool, pb, label) = jpeg_operation_setup("reencode", jpeg_paths.len())?;
	let results: Vec<anyhow::Result<()>> = pool.install(|| {
		jpeg_paths
			.par_iter()
			.map(|input_path| {
				let result = reencode_one(input_path, input_dir, output_dir, &pb);
				pb.inc(1);
				result
			})
			.collect()
	});
	eprintln!("[{label}] done in {:.1?}", pb.elapsed());
	pb.finish_and_clear();

	for result in results {
		result?;
	}
	Ok(())
}

fn reencode_one(input_path: &Path, input_dir: &Path, output_dir: &Path, pb: &ProgressBar) -> anyhow::Result<()> {
	let jpeg_bytes = std::fs::read(input_path).with_context(|| format!("failed to read {}", input_path.display()))?;

	let owned = unsafe { read_owned_jpeg(&jpeg_bytes) }
		.with_context(|| format!("failed to decode JPEG {}", input_path.display()))?;

	let output_bytes = unsafe { write_owned_jpeg(&jpeg_bytes, &owned) }
		.with_context(|| format!("failed to re-encode JPEG {}", input_path.display()))?;

	let rel = input_path
		.strip_prefix(input_dir)
		.with_context(|| format!("path {} is not under {}", input_path.display(), input_dir.display()))?;
	let output_path = output_dir.join(rel);
	if let Some(parent) = output_path.parent() {
		std::fs::create_dir_all(parent).with_context(|| format!("failed to create directory {}", parent.display()))?;
	}

	std::fs::write(&output_path, &output_bytes)
		.with_context(|| format!("failed to write {}", output_path.display()))?;

	pb.println(format!(
		"Reencoded '{}' -> '{}' ({}KiB)",
		input_path.display(),
		output_path.display(),
		output_bytes.len() / 1024
	));
	Ok(())
}

fn run_simulate(input_dir: &Path, output_dir: &Path) -> anyhow::Result<()> {
	let jpeg_paths = discover_jpeg_paths_recursive(input_dir)?;
	std::fs::create_dir_all(output_dir)
		.with_context(|| format!("failed to create output directory {}", output_dir.display()))?;

	let (pool, pb, label) = jpeg_operation_setup("simulate", jpeg_paths.len())?;
	let results: Vec<anyhow::Result<()>> = pool.install(|| {
		jpeg_paths
			.par_iter()
			.map(|input_path| {
				let result = simulate_one(input_path, input_dir, output_dir, &pb);
				pb.inc(1);
				result
			})
			.collect()
	});
	eprintln!("[{label}] done in {:.1?}", pb.elapsed());
	pb.finish_and_clear();

	for result in results {
		result?;
	}
	Ok(())
}

fn simulate_one(input_path: &Path, input_dir: &Path, output_dir: &Path, pb: &ProgressBar) -> anyhow::Result<()> {
	let rel = input_path
		.strip_prefix(input_dir)
		.with_context(|| format!("path {} is not under {}", input_path.display(), input_dir.display()))?;
	let output_path = output_dir.join(rel);
	if let Some(parent) = output_path.parent() {
		std::fs::create_dir_all(parent).with_context(|| format!("failed to create directory {}", parent.display()))?;
	}

	let jpeg_bytes = std::fs::read(input_path).with_context(|| format!("failed to read {}", input_path.display()))?;

	let jpeg_capacity = get_capacity(&jpeg_bytes)
		.with_context(|| format!("failed to compute JPEG capacity for {}", input_path.display()))?;
	let embed_len = JpegBlockStore::persisted_embed_len(jpeg_capacity)
		.with_context(|| format!("failed to compute embed length for {}", input_path.display()))?;

	let mut random_bytes = vec![0u8; embed_len];
	rand::rng().fill_bytes(&mut random_bytes);

	let mut session = JpegSession::in_memory(jpeg_bytes)
		.with_context(|| format!("failed to open JPEG session for {}", input_path.display()))?;
	session
		.write_data(&random_bytes)
		.with_context(|| format!("failed to embed random bytes into {}", input_path.display()))?;
	let output_bytes = session
		.to_jpeg_bytes()
		.with_context(|| format!("failed to re-encode JPEG {}", input_path.display()))?;

	std::fs::write(&output_path, &output_bytes)
		.with_context(|| format!("failed to write {}", output_path.display()))?;

	pb.println(format!(
		"Simulated '{}' -> '{}' ({}KiB)",
		input_path.display(),
		output_path.display(),
		output_bytes.len() / 1024
	));
	Ok(())
}

#[cfg(unix)]
fn summarize_stat_probes(probed_stores: &[ProbedStore]) -> anyhow::Result<StatProbeSummary> {
	let total_theoretical_page_capacity = probed_stores.iter().try_fold(0usize, |sum, store| {
		sum.checked_add(store.theoretical_page_capacity)
			.context("total theoretical page capacity overflow while probing JPEG stores")
	})?;
	let failed_paths: Vec<PathBuf> = probed_stores
		.iter()
		.filter(|store| store.decrypted_data.is_none())
		.map(|store| store.path.clone())
		.collect();

	if failed_paths.is_empty() {
		return Ok(StatProbeSummary::FilesystemStats);
	}

	Ok(StatProbeSummary::CapacityOnly {
		failed_paths,
		total_theoretical_page_capacity,
	})
}

#[cfg(unix)]
fn print_theoretical_capacity(total_page_capacity: usize) {
	println!();
	println!("Usage: unavailable");
	println!(
		"Theoretical capacity: {} blocks ({} KiB)",
		total_page_capacity,
		total_page_capacity.saturating_mul(BLOCK_SIZE) / 1024
	);
}

#[cfg(unix)]
fn init_filesystem(decoded_pages: DecodedPages, total_page_capacity: usize) -> anyhow::Result<FileSystem> {
	anyhow::ensure!(
		total_page_capacity >= MIN_BOOTSTRAP_PAGES,
		"insufficient total JPEG capacity: {total_page_capacity} pages available, at least {MIN_BOOTSTRAP_PAGES} are required"
	);

	let fs = if decoded_pages.is_empty() {
		FileSystem::new_with_limits(total_page_capacity)
			.map_err(anyhow::Error::msg)
			.context("failed to initialize fresh filesystem from JPEG capacity")?
	} else {
		let pager = Pager::from_decoded_pages(decoded_pages, total_page_capacity)
			.context("failed to decode persisted pager state from JPEG stores")?;
		FileSystem::from_pager(pager).context("persisted filesystem state is invalid")?
	};

	log_filesystem_capacity("initialized", &fs, total_page_capacity);
	Ok(fs)
}

#[cfg(unix)]
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

#[cfg(unix)]
fn persist_filesystem(
	stores: &mut [JpegBlockStore],
	fs: &FileSystem,
	total_page_capacity: usize,
) -> anyhow::Result<()> {
	let encode_started_at = Instant::now();
	let encoded_by_id = {
		let state = fs.state.read();
		state
			.check_invariants()
			.map_err(anyhow::Error::msg)
			.context("filesystem invariants failed before persistence")?;
		state
			.pager
			.encode_blocks_by_id()
			.context("failed to encode pager blocks for persistence")?
	};

	anyhow::ensure!(
		encoded_by_id.len() <= total_page_capacity,
		"encoded pager needs {} pages but only {} pages are available across JPEG stores",
		encoded_by_id.len(),
		total_page_capacity
	);

	let mut store_page_ids: Vec<Vec<PageId>> = Vec::with_capacity(stores.len());
	let mut page_owner_store: HashMap<PageId, usize> = HashMap::new();
	for (store_index, store) in stores.iter().enumerate() {
		let page_ids = store.ordered_page_ids();
		for &page_id in &page_ids {
			anyhow::ensure!(
				page_owner_store.insert(page_id, store_index).is_none(),
				"internal error: page id {page_id:?} is assigned to multiple JPEG stores"
			);
		}
		store_page_ids.push(page_ids);
	}

	let encoded_ids: HashSet<PageId> = encoded_by_id.keys().copied().collect();
	let owned_ids: HashSet<PageId> = page_owner_store.keys().copied().collect();
	let removed_ids: HashSet<PageId> = owned_ids.difference(&encoded_ids).copied().collect();

	let mut dirty_store_indices: HashSet<usize> = HashSet::new();
	for (store_index, page_ids) in store_page_ids.iter().enumerate() {
		let mut store_dirty = false;
		for &page_id in page_ids {
			if removed_ids.contains(&page_id) {
				store_dirty = true;
				break;
			}
			if let Some(new_block) = encoded_by_id.get(&page_id) {
				let old_block = stores[store_index]
					.persisted_block(page_id)
					.context("internal error: missing stored block for known page id")?;
				if old_block != new_block {
					store_dirty = true;
					break;
				}
			}
		}
		if store_dirty {
			dirty_store_indices.insert(store_index);
		}
	}

	let retained_page_ids_per_store: Vec<Vec<PageId>> = store_page_ids
		.iter()
		.map(|page_ids| {
			page_ids
				.iter()
				.copied()
				.filter(|id| encoded_by_id.contains_key(id))
				.collect()
		})
		.collect();

	let mut new_page_ids: Vec<PageId> = encoded_ids.difference(&owned_ids).copied().collect();
	let retained_page_counts: Vec<usize> = retained_page_ids_per_store.iter().map(Vec::len).collect();
	let store_capacities: Vec<usize> = stores.iter().map(JpegBlockStore::page_capacity).collect();
	let assigned_new_pages = assign_new_pages_first_fit(&retained_page_counts, &store_capacities, &mut new_page_ids)?;
	for (store_index, assigned_pages) in assigned_new_pages.iter().enumerate() {
		if assigned_pages.is_empty() {
			continue;
		}
		dirty_store_indices.insert(store_index);
	}

	// Fresh stores (newly initialized this session) must be written even if they
	// receive no pages, so that subsequent mounts can decrypt the empty header
	// rather than triggering the OVERWRITE prompt.
	for (store_index, store) in stores.iter().enumerate() {
		if store.needs_initial_write() {
			dirty_store_indices.insert(store_index);
		}
	}

	if dirty_store_indices.is_empty() {
		info!(
			"Encoded {} pages across {} JPEG stores in {:?} (written: 0, skipped: {})",
			encoded_ids.len(),
			stores.len(),
			encode_started_at.elapsed(),
			stores.len()
		);
		return Ok(());
	}

	let mut target_page_ids_per_store: Vec<Option<Vec<PageId>>> = vec![None; stores.len()];
	for store_index in 0..stores.len() {
		if !dirty_store_indices.contains(&store_index) {
			continue;
		}

		let mut desired_page_ids = retained_page_ids_per_store[store_index].clone();
		desired_page_ids.extend(assigned_new_pages[store_index].iter().copied());
		anyhow::ensure!(
			desired_page_ids.len() <= stores[store_index].page_capacity(),
			"internal error: page assignment exceeds capacity for store index {store_index}"
		);
		target_page_ids_per_store[store_index] = Some(desired_page_ids);
	}

	let (pool, pb, label) = jpeg_operation_setup("persist", stores.len())?;
	let persist_results: Vec<anyhow::Result<bool>> = pool.install(|| {
		stores
			.par_iter_mut()
			.enumerate()
			.map(|(store_index, store)| {
				let Some(target_page_ids) = target_page_ids_per_store[store_index].as_ref() else {
					pb.inc(1);
					return Ok(false);
				};
				let mut blocks = Vec::with_capacity(target_page_ids.len());
				for page_id in target_page_ids {
					let block = encoded_by_id
						.get(page_id)
						.with_context(|| format!("missing encoded block for page {page_id:?}"))?;
					blocks.push(*block);
				}
				let result = store
					.persist_blocks(&blocks)
					.with_context(|| format!("failed to persist encoded pages to JPEG store index {}", store_index));
				pb.inc(1);
				result
			})
			.collect()
	});
	eprintln!("[{label}] done in {:.1?}", pb.elapsed());
	pb.finish_and_clear();
	let written_stores = persist_results
		.into_iter()
		.collect::<anyhow::Result<Vec<_>>>()?
		.into_iter()
		.filter(|wrote| *wrote)
		.count();
	let skipped_stores = stores.len().saturating_sub(written_stores);
	info!(
		"Encoded and persisted {} pages across {} JPEG stores in {:?} (written: {}, skipped: {})",
		encoded_ids.len(),
		stores.len(),
		encode_started_at.elapsed(),
		written_stores,
		skipped_stores
	);
	Ok(())
}

#[cfg(unix)]
fn assign_new_pages_first_fit(
	retained_page_counts: &[usize],
	store_capacities: &[usize],
	new_page_ids: &mut Vec<PageId>,
) -> anyhow::Result<Vec<Vec<PageId>>> {
	anyhow::ensure!(
		retained_page_counts.len() == store_capacities.len(),
		"internal error: retained-page and store-capacity lengths differ"
	);

	new_page_ids.sort_by_key(|id| id.0);
	let mut assigned_new_pages: Vec<Vec<PageId>> = vec![Vec::new(); store_capacities.len()];
	let mut next_store_index = 0usize;
	for page_id in new_page_ids.iter().copied() {
		while next_store_index < store_capacities.len()
			&& (retained_page_counts[next_store_index] + assigned_new_pages[next_store_index].len())
				>= store_capacities[next_store_index]
		{
			next_store_index += 1;
		}
		anyhow::ensure!(
			next_store_index < store_capacities.len(),
			"not enough JPEG store capacity to assign new page {page_id:?}"
		);
		assigned_new_pages[next_store_index].push(page_id);
	}

	Ok(assigned_new_pages)
}

fn jpeg_operation_setup(label: &'static str, count: usize) -> anyhow::Result<(ThreadPool, ProgressBar, &'static str)> {
	let threads = configured_jpeg_threads();
	eprintln!("[{label}] {count} file(s), {threads} worker thread(s)");
	let pool = rayon::ThreadPoolBuilder::new()
		.num_threads(threads)
		.build()
		.context("failed to build JPEG worker thread pool")?;
	let pb = ProgressBar::new(count as u64);
	pb.set_style(
		ProgressStyle::with_template("{spinner:.cyan} [{bar:40.cyan/blue}] {pos}/{len} elapsed:{elapsed} eta:{eta}")
			.unwrap()
			.progress_chars("=>-"),
	);
	Ok((pool, pb, label))
}

fn configured_jpeg_threads() -> usize {
	let auto_threads = std::thread::available_parallelism()
		.map(std::num::NonZeroUsize::get)
		.unwrap_or(1);
	let max_threads = auto_threads.max(1);

	match std::env::var("JPEGFS_JPEG_THREADS") {
		Ok(raw) => match raw.parse::<usize>() {
			Ok(parsed) if parsed > 0 => parsed,
			_ => {
				warn!(
					"invalid JPEGFS_JPEG_THREADS='{}'; using auto thread count ({})",
					raw, max_threads
				);
				max_threads
			}
		},
		Err(std::env::VarError::NotPresent) => max_threads,
		Err(err) => {
			warn!("failed reading JPEGFS_JPEG_THREADS ({err}); using auto thread count ({max_threads})");
			max_threads
		}
	}
}

#[cfg(all(test, unix))]
mod tests {
	use super::*;

	fn probed_store(path: &str, theoretical_page_capacity: usize, decrypted_data: Option<Vec<u8>>) -> ProbedStore {
		ProbedStore {
			index: 0,
			path: PathBuf::from(path),
			jpeg_capacity: 0,
			theoretical_page_capacity,
			jpeg_bytes: Vec::new(),
			key: [0; 32],
			decrypted_data,
		}
	}

	#[test]
	fn assign_new_pages_first_fit_uses_slots_freed_by_removals() {
		let retained_page_counts = vec![1usize, 0usize];
		let store_capacities = vec![2usize, 1usize];
		let mut new_page_ids = vec![PageId(11), PageId(10)];

		let assigned = assign_new_pages_first_fit(&retained_page_counts, &store_capacities, &mut new_page_ids)
			.expect("assignment should succeed by using freed slot in first store");

		assert_eq!(new_page_ids, vec![PageId(10), PageId(11)]);
		assert_eq!(assigned, vec![vec![PageId(10)], vec![PageId(11)]]);
	}

	#[test]
	fn assign_new_pages_first_fit_returns_capacity_error_when_full() {
		let retained_page_counts = vec![1usize];
		let store_capacities = vec![1usize];
		let mut new_page_ids = vec![PageId(42)];

		let err = assign_new_pages_first_fit(&retained_page_counts, &store_capacities, &mut new_page_ids)
			.expect_err("assignment should fail when all stores are full");

		assert!(
			err.to_string().contains("not enough JPEG store capacity"),
			"unexpected error: {err:#}"
		);
	}

	#[test]
	fn summarize_stat_probes_returns_capacity_only_when_any_store_fails_decryption() {
		let summary = summarize_stat_probes(&[
			probed_store("a.jpg", 3, Some(vec![1, 2, 3])),
			probed_store("b.jpg", 5, None),
		])
		.expect("summary should succeed");

		assert_eq!(
			summary,
			StatProbeSummary::CapacityOnly {
				failed_paths: vec![PathBuf::from("b.jpg")],
				total_theoretical_page_capacity: 8,
			}
		);
	}

	#[test]
	fn summarize_stat_probes_returns_filesystem_stats_when_all_stores_decrypt() {
		let summary = summarize_stat_probes(&[
			probed_store("a.jpg", 3, Some(vec![1])),
			probed_store("b.jpg", 5, Some(vec![2])),
		])
		.expect("summary should succeed");

		assert_eq!(summary, StatProbeSummary::FilesystemStats);
	}
}
