use anyhow::{Context, bail};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Instant;

use fuser::{Config as FuseConfig, MountOption, spawn_mount2};
use log::{error, info, warn};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rayon::ThreadPool;
use rayon::prelude::*;

use jpegfs::filesystem::{BLOCK_SIZE, FileSystem};
use jpegfs::jpeg_file::init_file;
use jpegfs::pager::{DecodedPages, PageId, Pager};
use jpegfs::persistence::JpegBlockStore;

mod tui;

const DEFAULT_MOUNT_PATH: &str = "/tmp/jpegfs";

/// A filesystem requires at least 2 pages: 1 dir inodes pages, 1 dir entries page
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
	let jpeg_threads = configured_jpeg_threads(jpeg_paths.len())?;
	info!(
		"JPEG worker threads configured: {} (stores: {})",
		jpeg_threads,
		jpeg_paths.len()
	);

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
	let shutdown_persist_started_at = Instant::now();
	persistence.persist_once()?;
	println!(
		"Shutdown persistence completed in {:?}",
		shutdown_persist_started_at.elapsed()
	);

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

fn load_or_init_stores(paths: &[PathBuf]) -> anyhow::Result<(Vec<JpegBlockStore>, DecodedPages, usize)> {
	let decode_started_at = Instant::now();
	let pool = jpeg_thread_pool(paths.len())?;
	let loaded: Vec<anyhow::Result<(usize, JpegBlockStore, DecodedPages, usize)>> = pool.install(|| {
		paths
			.par_iter()
			.enumerate()
			.map(|(index, path)| load_one_store(index, path.as_path()))
			.collect()
	});

	let mut loaded = loaded.into_iter().collect::<anyhow::Result<Vec<_>>>()?;
	loaded.sort_by_key(|(index, _, _, _)| *index);

	let mut stores = Vec::with_capacity(paths.len());
	let mut decoded_pages = DecodedPages::empty();
	let mut total_page_capacity = 0usize;

	for (_, store, pages, page_capacity) in loaded {
		total_page_capacity = total_page_capacity
			.checked_add(page_capacity)
			.context("total page capacity overflow while loading JPEG stores")?;
		decoded_pages.append(pages);
		stores.push(store);
	}

	info!(
		"Decoded {} JPEG stores in {:?}",
		paths.len(),
		decode_started_at.elapsed()
	);

	Ok((stores, decoded_pages, total_page_capacity))
}

fn load_one_store(index: usize, path: &Path) -> anyhow::Result<(usize, JpegBlockStore, DecodedPages, usize)> {
	let mut file = init_file(path).with_context(|| format!("failed to open JPEG store at {}", path.display()))?;
	let data = file
		.read_data(file.capacity())
		.with_context(|| format!("failed to read JPEG store data from {}", path.display()))?;
	let (store, pages) = JpegBlockStore::from_bytes_or_init_strict(file, &data)
		.with_context(|| format!("failed to load persisted pages from {}", path.display()))?;
	let page_capacity = store.page_capacity();
	Ok((index, store, pages, page_capacity))
}

fn init_filesystem(decoded_pages: DecodedPages, total_page_capacity: usize) -> anyhow::Result<FileSystem> {
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
		let pager = Pager::from_decoded_pages(decoded_pages, total_page_capacity)
			.context("failed to decode persisted pager state from JPEG stores")?;
		FileSystem::from_pager(pager, total_bytes_limit).context("persisted filesystem state is invalid")?
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

	let pool = jpeg_thread_pool(stores.len())?;
	let persist_results: Vec<anyhow::Result<bool>> = pool.install(|| {
		stores
			.par_iter_mut()
			.enumerate()
			.map(|(store_index, store)| {
				let Some(target_page_ids) = target_page_ids_per_store[store_index].as_ref() else {
					return Ok(false);
				};
				let mut blocks = Vec::with_capacity(target_page_ids.len());
				for page_id in target_page_ids {
					let block = encoded_by_id
						.get(page_id)
						.with_context(|| format!("missing encoded block for page {page_id:?}"))?;
					blocks.push(*block);
				}
				store
					.persist_blocks(&blocks)
					.with_context(|| format!("failed to persist encoded pages to JPEG store index {}", store_index))
			})
			.collect()
	});
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

fn jpeg_thread_pool(job_count: usize) -> anyhow::Result<ThreadPool> {
	let threads = configured_jpeg_threads(job_count)?;
	rayon::ThreadPoolBuilder::new()
		.num_threads(threads)
		.build()
		.context("failed to build JPEG worker thread pool")
}

fn configured_jpeg_threads(job_count: usize) -> anyhow::Result<usize> {
	if job_count == 0 {
		return Ok(1);
	}

	let auto_threads = std::thread::available_parallelism()
		.map(std::num::NonZeroUsize::get)
		.unwrap_or(1);
	let max_threads = auto_threads.max(1).min(job_count);

	match std::env::var("JPEGFS_JPEG_THREADS") {
		Ok(raw) => match raw.parse::<usize>() {
			Ok(parsed) if parsed > 0 => Ok(parsed.min(job_count)),
			_ => {
				warn!(
					"invalid JPEGFS_JPEG_THREADS='{}'; using auto thread count ({})",
					raw, max_threads
				);
				Ok(max_threads)
			}
		},
		Err(std::env::VarError::NotPresent) => Ok(max_threads),
		Err(err) => {
			warn!("failed reading JPEGFS_JPEG_THREADS ({err}); using auto thread count ({max_threads})");
			Ok(max_threads)
		}
	}
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

#[cfg(test)]
mod tests {
	use super::*;

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
}
