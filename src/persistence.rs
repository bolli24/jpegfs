use crate::file::FileHandle;
use crate::filesystem::{BLOCK_SIZE, FileSystem};
use crate::pager::{PageId, PagerCodecError, ValidatedPages};
use crc::Crc;
use log::error;
use std::collections::HashMap;
use std::mem::size_of;
use thiserror::Error;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(Debug, Error)]
pub enum Error {
	#[error("input buffer too small to decode: {0} bytes")]
	InputBufferTooSmall(usize),
	#[error("unsupported persistence header version {0}")]
	UnsupportedVersion(u16),
	#[error("persistence header requires {required_len} bytes but only {actual_len} are available")]
	HeaderOutOfBounds { required_len: usize, actual_len: usize },
	#[error("persistence header CRC mismatch: expected {expected:#010x}, actual {actual:#010x}")]
	HeaderCrcMismatch { expected: u32, actual: u32 },
	#[error("stored page count {used} exceeds page capacity {capacity}")]
	InvalidPageCount { used: u16, capacity: u16 },
	#[error("stored pages require {required_len} bytes but only {actual_len} are available")]
	StoredPagesOutOfBounds { required_len: usize, actual_len: usize },
	#[error("duplicate page id {0:?}")]
	DuplicatePageId(PageId),
	#[error("pager decode failed: {0}")]
	Pager(#[from] PagerCodecError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct FileId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
struct FileHeaderV1 {
	magic: [u8; 8],
	crc32: u32,
	version: u16,
	page_capacity: u16,
	pages_used: u16,
	_pad0: [u8; 2],
}

const FILE_HEADER_SIZE: usize = size_of::<FileHeaderV1>();
const FILE_CRC: Crc<u32> = Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);
const FILE_VERSION: u16 = 1;
const FILE_MAGIC: [u8; 8] = *b"JPGFhdr1";

pub struct JpegBlockStore {
	header: FileHeaderV1,
	file_id: FileId,
	file: FileHandle,
	pages_map: HashMap<PageId, usize>,
}

impl JpegBlockStore {
	pub fn from_bytes_or_init(file: FileHandle, data: &[u8]) -> Result<(Self, ValidatedPages), Error> {
		if data.len() < FILE_HEADER_SIZE {
			return Err(Error::InputBufferTooSmall(data.len()));
		}

		let header = match Self::try_decode_header(data) {
			Ok(Some(header)) => header,
			Ok(None) => return Self::init_new(file, data),
			Err(err @ Error::UnsupportedVersion(_)) => return Err(err),
			Err(err) => {
				error!("dropping malformed persistence header and reinitializing store: {err}");
				return Self::init_new(file, data);
			}
		};

		if header.pages_used > header.page_capacity {
			return Err(Error::InvalidPageCount {
				used: header.pages_used,
				capacity: header.page_capacity,
			});
		}

		let stored_len = FILE_HEADER_SIZE + usize::from(header.pages_used) * BLOCK_SIZE;
		if data.len() < stored_len {
			return Err(Error::StoredPagesOutOfBounds {
				required_len: stored_len,
				actual_len: data.len(),
			});
		}

		let payload = &data[FILE_HEADER_SIZE..stored_len];
		let (blocks, remainder) = payload.as_chunks::<BLOCK_SIZE>();
		debug_assert!(remainder.is_empty(), "stored pages are block-aligned by construction");

		let decoded_pages = ValidatedPages::decode_blocks(blocks, usize::from(header.page_capacity))?;
		let mut pages_map = HashMap::with_capacity(blocks.len());
		for (slot, page_id) in decoded_pages.page_ids().enumerate() {
			if pages_map.insert(page_id, slot).is_some() {
				return Err(Error::DuplicatePageId(page_id));
			}
		}

		Ok((
			Self {
				header,
				file_id: FileId(0),
				file,
				pages_map,
			},
			decoded_pages,
		))
	}

	pub fn init_new(file: FileHandle, data: &[u8]) -> Result<(Self, ValidatedPages), Error> {
		if data.len() < FILE_HEADER_SIZE {
			return Err(Error::InputBufferTooSmall(data.len()));
		}

		let page_capacity = ((data.len() - FILE_HEADER_SIZE) / BLOCK_SIZE)
			.try_into()
			.unwrap_or(u16::MAX);
		let payload_len = usize::from(page_capacity) * BLOCK_SIZE;
		let payload = &data[FILE_HEADER_SIZE..FILE_HEADER_SIZE + payload_len];

		let mut header = FileHeaderV1 {
			magic: FILE_MAGIC,
			crc32: 0,
			version: FILE_VERSION,
			page_capacity,
			pages_used: 0,
			_pad0: [0; 2],
		};
		header.crc32 = Self::compute_crc(header, payload);

		Ok((
			Self {
				header,
				file_id: FileId(0),
				file,
				pages_map: HashMap::new(),
			},
			ValidatedPages::empty(),
		))
	}

	fn try_decode_header(data: &[u8]) -> Result<Option<FileHeaderV1>, Error> {
		let header = FileHeaderV1::read_from_bytes(&data[0..FILE_HEADER_SIZE]).expect("size must be valid");

		if header.magic != FILE_MAGIC {
			return Ok(None);
		}

		if header.version != FILE_VERSION {
			return Err(Error::UnsupportedVersion(header.version));
		}

		let required_len = FILE_HEADER_SIZE + usize::from(header.page_capacity) * BLOCK_SIZE;
		if data.len() < required_len {
			return Err(Error::HeaderOutOfBounds {
				required_len,
				actual_len: data.len(),
			});
		}

		let payload = &data[FILE_HEADER_SIZE..required_len];

		let actual_crc = Self::compute_crc(header, payload);
		if actual_crc != header.crc32 {
			return Err(Error::HeaderCrcMismatch {
				expected: header.crc32,
				actual: actual_crc,
			});
		}

		Ok(Some(header))
	}

	fn compute_crc(mut header: FileHeaderV1, payload: &[u8]) -> u32 {
		header.crc32 = 0;
		let mut digest = FILE_CRC.digest();
		digest.update(header.as_bytes());
		digest.update(payload);
		digest.finalize()
	}

	fn file_id(&self) -> FileId {
		self.file_id
	}

	pub fn free_pages(&self) -> usize {
		usize::from(self.header.page_capacity.saturating_sub(self.header.pages_used))
	}
}

pub struct JpegStorage {
	files_system: FileSystem,
	jpeg_files: Vec<JpegBlockStore>,
	page_files: HashMap<PageId, FileId>,
}

impl JpegStorage {
	pub fn from_loaded_stores(
		files_system: FileSystem,
		loaded_stores: Vec<(JpegBlockStore, ValidatedPages)>,
	) -> Result<(Self, ValidatedPages), Error> {
		let mut jpeg_files: Vec<JpegBlockStore> = Vec::with_capacity(loaded_stores.len());
		let mut decoded_pages = ValidatedPages::empty();
		let mut total_page_capacity = 0usize;

		for (index, (mut store, store_pages)) in loaded_stores.into_iter().enumerate() {
			let file_id = FileId(index.try_into().expect("number of block stores must fit into u32"));
			store.file_id = file_id;
			total_page_capacity = total_page_capacity
				.checked_add(usize::from(store.header.page_capacity))
				.expect("total page capacity must fit into usize");
			decoded_pages.append(store_pages);
			jpeg_files.push(store);
		}

		let decoded_pages = decoded_pages.validate(total_page_capacity)?;

		let mut page_files = HashMap::new();
		for store in &jpeg_files {
			let file_id = store.file_id();
			for &page_id in store.pages_map.keys() {
				if page_files.insert(page_id, file_id).is_some() {
					return Err(Error::DuplicatePageId(page_id));
				}
			}
		}

		Ok((
			Self {
				files_system,
				jpeg_files,
				page_files,
			},
			decoded_pages,
		))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::inode::Inode;
	use crate::pager::Pager;
	use crc::Crc;
	use fuser::{FileType, INodeNo};
	use std::ffi::OsString;
	use std::fs::File;
	use std::mem::size_of;
	use std::path::PathBuf;
	use std::time::{SystemTime, UNIX_EPOCH};
	use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

	fn temp_file_handle() -> (FileHandle, PathBuf) {
		let unique = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.expect("clock should be after unix epoch")
			.as_nanos();
		let path = std::env::temp_dir().join(format!("jpegfs-persistence-{unique}.tmp"));
		let file = File::options()
			.read(true)
			.write(true)
			.create(true)
			.truncate(true)
			.open(&path)
			.expect("temp file should open");

		(FileHandle::from_parts(file, path.clone(), 0), path)
	}

	fn sample_inode() -> Inode {
		let now = SystemTime::UNIX_EPOCH;
		Inode {
			kind: FileType::RegularFile,
			perm: 0o644,
			uid: 1000,
			gid: 1000,
			size: 0,
			nlink: 1,
			atime: now,
			mtime: now,
			ctime: now,
			crtime: now,
		}
	}

	fn encode_store_bytes(blocks: &[[u8; BLOCK_SIZE]], page_capacity: u16) -> Vec<u8> {
		let payload_len = usize::from(page_capacity) * BLOCK_SIZE;
		let mut payload = vec![0u8; payload_len];
		for (slot, block) in blocks.iter().enumerate() {
			let start = slot * BLOCK_SIZE;
			payload[start..start + BLOCK_SIZE].copy_from_slice(block);
		}

		let mut header = FileHeaderV1 {
			magic: FILE_MAGIC,
			crc32: 0,
			version: FILE_VERSION,
			page_capacity,
			pages_used: blocks.len().try_into().expect("test blocks should fit into u16"),
			_pad0: [0; 2],
		};
		header.crc32 = JpegBlockStore::compute_crc(header, &payload);

		let mut data = Vec::with_capacity(FILE_HEADER_SIZE + payload_len + 3);
		data.extend_from_slice(header.as_bytes());
		data.extend_from_slice(&payload);
		data.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
		data
	}

	#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
	#[repr(C)]
	struct TestPageHeaderV1 {
		magic: [u8; 4],
		page_id: PageId,
		owner_ino: u64,
		file_page_no: u32,
		crc32: u32,
		version: u16,
		page_type: u16,
		payload_len: u16,
		reserved: u16,
	}

	const TEST_PAGE_HEADER_SIZE: usize = size_of::<TestPageHeaderV1>();
	const TEST_PAGE_CRC: Crc<u32> = Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);

	fn rewrite_test_page_header(block: &mut [u8; BLOCK_SIZE], mutate: impl FnOnce(&mut TestPageHeaderV1)) {
		let mut header =
			TestPageHeaderV1::read_from_bytes(&block[..TEST_PAGE_HEADER_SIZE]).expect("header should parse");
		mutate(&mut header);
		header.crc32 = 0;

		let payload_len = usize::from(header.payload_len);
		let payload = &block[TEST_PAGE_HEADER_SIZE..TEST_PAGE_HEADER_SIZE + payload_len];
		let mut digest = TEST_PAGE_CRC.digest();
		digest.update(header.as_bytes());
		digest.update(payload);
		header.crc32 = digest.finalize();
		block[..TEST_PAGE_HEADER_SIZE].copy_from_slice(header.as_bytes());
	}

	fn test_page_id(block: &[u8; BLOCK_SIZE]) -> PageId {
		TestPageHeaderV1::read_from_bytes(&block[..TEST_PAGE_HEADER_SIZE])
			.expect("header should parse")
			.page_id
	}

	#[test]
	fn from_bytes_or_init_rejects_invalid_page_count() {
		let mut data = encode_store_bytes(&[], 1);
		let mut header = FileHeaderV1::read_from_bytes(&data[..FILE_HEADER_SIZE]).expect("header should parse");
		header.pages_used = 2;
		header.crc32 = JpegBlockStore::compute_crc(header, &data[FILE_HEADER_SIZE..FILE_HEADER_SIZE + BLOCK_SIZE]);
		data[..FILE_HEADER_SIZE].copy_from_slice(header.as_bytes());
		let (file, path) = temp_file_handle();

		let err = match JpegBlockStore::from_bytes_or_init(file, &data) {
			Ok(_) => panic!("load should fail"),
			Err(err) => err,
		};

		assert!(matches!(err, Error::InvalidPageCount { used: 2, capacity: 1 }));

		std::fs::remove_file(path).expect("temp file should be removed");
	}

	#[test]
	fn from_bytes_or_init_rejects_invalid_stored_page_block() {
		let mut pager = Pager::new(4);
		let ino = INodeNo(3);
		pager.bytes_write(ino, 0, b"crc-check").expect("write should succeed");
		let mut encoded = pager.encode_blocks().expect("encoding should succeed");
		encoded[0][32] ^= 0xFF;
		let data = encode_store_bytes(&encoded, 2);
		let (file, path) = temp_file_handle();

		let err = match JpegBlockStore::from_bytes_or_init(file, &data) {
			Ok(_) => panic!("load should fail"),
			Err(err) => err,
		};

		assert!(matches!(err, Error::Pager(PagerCodecError::CrcMismatch { .. })));

		std::fs::remove_file(path).expect("temp file should be removed");
	}

	#[test]
	fn from_bytes_or_init_rejects_duplicate_page_ids() {
		let mut pager = Pager::new(4);
		let ino = INodeNo(5);
		pager
			.bytes_write(ino, 0, &vec![0xAB; 5000])
			.expect("write should succeed");
		let mut encoded = pager.encode_blocks().expect("encoding should succeed");
		let page_id = test_page_id(&encoded[0]);
		encoded[1] = encoded[0];
		let data = encode_store_bytes(&encoded, 4);
		let (file, path) = temp_file_handle();

		let err = match JpegBlockStore::from_bytes_or_init(file, &data) {
			Ok(_) => panic!("load should fail"),
			Err(err) => err,
		};

		assert!(matches!(err, Error::Pager(PagerCodecError::DuplicatePageId(id)) if id == page_id));

		std::fs::remove_file(path).expect("temp file should be removed");
	}

	#[test]
	fn from_bytes_or_init_falls_back_to_init_new_when_magic_matches_without_header_sentinel() {
		let mut data = vec![0u8; FILE_HEADER_SIZE + 2 * BLOCK_SIZE];
		data[..4].copy_from_slice(b"JPGF");
		let (file, path) = temp_file_handle();

		let (store, decoded_pages) =
			JpegBlockStore::from_bytes_or_init(file, &data).expect("fallback init should succeed");

		assert_eq!(store.header.magic, FILE_MAGIC);
		assert_eq!(store.header.pages_used, 0);
		assert_eq!(store.header.page_capacity, 2);
		assert!(store.pages_map.is_empty());
		assert!(decoded_pages.is_empty());

		drop(store);
		std::fs::remove_file(path).expect("temp file should be removed");
	}

	#[test]
	fn from_bytes_or_init_reinitializes_on_malformed_recognized_header() {
		let mut data = encode_store_bytes(&[], 2);
		let mut header = FileHeaderV1::read_from_bytes(&data[..FILE_HEADER_SIZE]).expect("header should parse");
		header.crc32 ^= 0xFFFF_FFFF;
		data[..FILE_HEADER_SIZE].copy_from_slice(header.as_bytes());
		let (file, path) = temp_file_handle();

		let (store, decoded_pages) =
			JpegBlockStore::from_bytes_or_init(file, &data).expect("malformed header should reinitialize");

		assert_eq!(store.header.magic, FILE_MAGIC);
		assert_eq!(store.header.pages_used, 0);
		assert_eq!(store.header.page_capacity, 2);
		assert!(store.pages_map.is_empty());
		assert!(decoded_pages.is_empty());

		drop(store);
		std::fs::remove_file(path).expect("temp file should be removed");
	}

	#[test]
	fn from_bytes_or_init_rejects_unsupported_persistence_version() {
		let mut data = encode_store_bytes(&[], 2);
		let mut header = FileHeaderV1::read_from_bytes(&data[..FILE_HEADER_SIZE]).expect("header should parse");
		header.version = FILE_VERSION + 1;
		data[..FILE_HEADER_SIZE].copy_from_slice(header.as_bytes());
		let (file, path) = temp_file_handle();

		let err = match JpegBlockStore::from_bytes_or_init(file, &data) {
			Ok(_) => panic!("load should fail"),
			Err(err) => err,
		};

		assert!(matches!(err, Error::UnsupportedVersion(version) if version == FILE_VERSION + 1));

		std::fs::remove_file(path).expect("temp file should be removed");
	}

	#[test]
	fn successful_load_tracks_page_slots_and_storage_capacity() {
		let data_a = encode_store_bytes(&[], 3);
		let (file_a, path_a) = temp_file_handle();
		let (store_a, decoded_pages_a) =
			JpegBlockStore::from_bytes_or_init(file_a, &data_a).expect("first store should load");

		assert_eq!(store_a.header.pages_used, 0);
		assert!(store_a.pages_map.is_empty());
		assert!(decoded_pages_a.is_empty());

		let mut pager_b = Pager::new(8);
		let ino_b = INodeNo(22);
		pager_b
			.inodes_insert(ino_b, sample_inode())
			.expect("insert should succeed");
		pager_b
			.dir_entries_insert(ino_b, OsString::from("child"), INodeNo(23))
			.expect("dir entry insert should succeed");
		pager_b.bytes_write(ino_b, 0, b"payload").expect("write should succeed");
		let encoded_b = pager_b.encode_blocks().expect("encoding should succeed");
		let data_b = encode_store_bytes(&encoded_b, 4);
		let (file_b, path_b) = temp_file_handle();
		let (store_b, decoded_pages_b) =
			JpegBlockStore::from_bytes_or_init(file_b, &data_b).expect("second store should load");

		assert_eq!(store_b.header.pages_used as usize, encoded_b.len());
		assert_eq!(store_b.pages_map.len(), encoded_b.len());
		assert_eq!(decoded_pages_b.len(), encoded_b.len());
		for (slot, page_id) in decoded_pages_b.page_ids().enumerate() {
			assert_eq!(store_b.pages_map.get(&page_id), Some(&slot));
		}

		let (storage, decoded_pages) = JpegStorage::from_loaded_stores(
			FileSystem::new(),
			vec![(store_a, decoded_pages_a), (store_b, decoded_pages_b)],
		)
		.expect("storage should build");

		assert_eq!(storage.jpeg_files.len(), 2);
		assert_eq!(storage.jpeg_files[0].file_id(), FileId(0));
		assert_eq!(storage.jpeg_files[1].file_id(), FileId(1));
		assert_eq!(storage.jpeg_files[0].free_pages(), 3);
		assert_eq!(storage.jpeg_files[1].free_pages(), 4 - encoded_b.len());
		assert_eq!(decoded_pages.len(), encoded_b.len());

		for page_id in decoded_pages.page_ids() {
			assert_eq!(storage.page_files.get(&page_id), Some(&FileId(1)));
		}

		drop(storage);
		std::fs::remove_file(path_a).expect("temp file should be removed");
		std::fs::remove_file(path_b).expect("temp file should be removed");
	}

	#[test]
	fn jpeg_storage_assigns_unique_file_ids_to_fresh_stores() {
		let mut data_a = vec![0u8; FILE_HEADER_SIZE + 2 * BLOCK_SIZE];
		data_a[..4].copy_from_slice(b"raw!");
		let (file_a, path_a) = temp_file_handle();
		let loaded_a = JpegBlockStore::from_bytes_or_init(file_a, &data_a).expect("first store should load");

		let mut data_b = vec![0u8; FILE_HEADER_SIZE + BLOCK_SIZE];
		data_b[..4].copy_from_slice(b"raw!");
		let (file_b, path_b) = temp_file_handle();
		let loaded_b = JpegBlockStore::from_bytes_or_init(file_b, &data_b).expect("second store should load");

		let (storage, decoded_pages) =
			JpegStorage::from_loaded_stores(FileSystem::new(), vec![loaded_a, loaded_b]).expect("storage should build");

		assert!(decoded_pages.is_empty());
		assert_eq!(storage.jpeg_files.len(), 2);
		assert_eq!(storage.jpeg_files[0].file_id(), FileId(0));
		assert_eq!(storage.jpeg_files[1].file_id(), FileId(1));

		std::fs::remove_file(path_a).expect("temp file should be removed");
		std::fs::remove_file(path_b).expect("temp file should be removed");
	}

	#[test]
	fn from_bytes_or_init_accepts_valid_store_with_extra_capacity_after_header_payload() {
		let data = encode_store_bytes(&[], 2);
		let mut expanded = data[..FILE_HEADER_SIZE + 2 * BLOCK_SIZE].to_vec();
		expanded.extend_from_slice(&[0xCC; BLOCK_SIZE]);
		let (file, path) = temp_file_handle();

		let (store, decoded_pages) = JpegBlockStore::from_bytes_or_init(file, &expanded).expect("load should succeed");

		assert_eq!(store.header.page_capacity, 2);
		assert_eq!(store.header.pages_used, 0);
		assert!(decoded_pages.is_empty());

		drop(store);
		std::fs::remove_file(path).expect("temp file should be removed");
	}

	#[test]
	fn from_bytes_or_init_rejects_duplicate_inodes_across_stored_pages() {
		let mut pager_a = Pager::new(8);
		pager_a
			.inodes_insert(INodeNo(41), sample_inode())
			.expect("insert should succeed");
		let encoded_a = pager_a.encode_blocks().expect("encoding should succeed");

		let mut pager_b = Pager::new(8);
		pager_b
			.inodes_insert(INodeNo(41), sample_inode())
			.expect("insert should succeed");
		let mut encoded_b = pager_b.encode_blocks().expect("encoding should succeed");
		rewrite_test_page_header(&mut encoded_b[0], |header| header.page_id = PageId(1));

		let blocks = vec![encoded_a[0], encoded_b[0]];
		let data = encode_store_bytes(&blocks, 4);
		let (file, path) = temp_file_handle();

		let err = match JpegBlockStore::from_bytes_or_init(file, &data) {
			Ok(_) => panic!("load should fail"),
			Err(err) => err,
		};

		assert!(matches!(
			err,
			Error::Pager(PagerCodecError::DuplicateInode(INodeNo(41)))
		));

		std::fs::remove_file(path).expect("temp file should be removed");
	}

	#[test]
	fn from_bytes_or_init_rejects_non_contiguous_data_pages_in_one_store() {
		let mut pager_a = Pager::new(8);
		pager_a.bytes_write(INodeNo(42), 0, b"a").expect("write should succeed");
		let encoded_a = pager_a.encode_blocks().expect("encoding should succeed");

		let mut pager_b = Pager::new(8);
		pager_b.bytes_write(INodeNo(42), 0, b"b").expect("write should succeed");
		let mut encoded_b = pager_b.encode_blocks().expect("encoding should succeed");
		rewrite_test_page_header(&mut encoded_b[0], |header| header.page_id = PageId(1));

		let blocks = vec![encoded_a[0], encoded_b[0]];
		let data = encode_store_bytes(&blocks, 4);
		let (file, path) = temp_file_handle();

		let err = match JpegBlockStore::from_bytes_or_init(file, &data) {
			Ok(_) => panic!("load should fail"),
			Err(err) => err,
		};

		assert!(matches!(
			err,
			Error::Pager(PagerCodecError::NonContiguousDataPages {
				ino: INodeNo(42),
				expected: 1,
				found: 0,
			})
		));

		std::fs::remove_file(path).expect("temp file should be removed");
	}

	#[test]
	fn jpeg_storage_rejects_duplicate_page_ids_across_files() {
		let mut pager_a = Pager::new(8);
		pager_a.bytes_write(INodeNo(31), 0, b"a").expect("write should succeed");
		let data_a = encode_store_bytes(&pager_a.encode_blocks().expect("encoding should succeed"), 2);
		let (file_a, path_a) = temp_file_handle();
		let loaded_a = JpegBlockStore::from_bytes_or_init(file_a, &data_a).expect("first store should load");

		let mut pager_b = Pager::new(8);
		pager_b.bytes_write(INodeNo(32), 0, b"b").expect("write should succeed");
		let data_b = encode_store_bytes(&pager_b.encode_blocks().expect("encoding should succeed"), 2);
		let (file_b, path_b) = temp_file_handle();
		let loaded_b = JpegBlockStore::from_bytes_or_init(file_b, &data_b).expect("second store should load");

		let err = match JpegStorage::from_loaded_stores(FileSystem::new(), vec![loaded_a, loaded_b]) {
			Ok(_) => panic!("storage should fail"),
			Err(err) => err,
		};

		assert!(matches!(err, Error::Pager(PagerCodecError::DuplicatePageId(PageId(0)))));

		std::fs::remove_file(path_a).expect("temp file should be removed");
		std::fs::remove_file(path_b).expect("temp file should be removed");
	}

	#[test]
	fn jpeg_storage_rejects_duplicate_inodes_across_files() {
		let mut pager_a = Pager::new(8);
		pager_a
			.inodes_insert(INodeNo(51), sample_inode())
			.expect("insert should succeed");
		let data_a = encode_store_bytes(&pager_a.encode_blocks().expect("encoding should succeed"), 2);
		let (file_a, path_a) = temp_file_handle();
		let loaded_a = JpegBlockStore::from_bytes_or_init(file_a, &data_a).expect("first store should load");

		let mut pager_b = Pager::new(8);
		pager_b
			.inodes_insert(INodeNo(51), sample_inode())
			.expect("insert should succeed");
		let mut encoded_b = pager_b.encode_blocks().expect("encoding should succeed");
		rewrite_test_page_header(&mut encoded_b[0], |header| header.page_id = PageId(1));
		let data_b = encode_store_bytes(&encoded_b, 2);
		let (file_b, path_b) = temp_file_handle();
		let loaded_b = JpegBlockStore::from_bytes_or_init(file_b, &data_b).expect("second store should load");

		let err = match JpegStorage::from_loaded_stores(FileSystem::new(), vec![loaded_a, loaded_b]) {
			Ok(_) => panic!("storage should fail"),
			Err(err) => err,
		};

		assert!(matches!(
			err,
			Error::Pager(PagerCodecError::DuplicateInode(INodeNo(51)))
		));

		std::fs::remove_file(path_a).expect("temp file should be removed");
		std::fs::remove_file(path_b).expect("temp file should be removed");
	}

	#[test]
	fn jpeg_storage_rejects_non_contiguous_data_pages_across_files() {
		let mut pager_a = Pager::new(8);
		pager_a.bytes_write(INodeNo(52), 0, b"a").expect("write should succeed");
		let data_a = encode_store_bytes(&pager_a.encode_blocks().expect("encoding should succeed"), 2);
		let (file_a, path_a) = temp_file_handle();
		let loaded_a = JpegBlockStore::from_bytes_or_init(file_a, &data_a).expect("first store should load");

		let mut pager_b = Pager::new(8);
		pager_b.bytes_write(INodeNo(52), 0, b"b").expect("write should succeed");
		let mut encoded_b = pager_b.encode_blocks().expect("encoding should succeed");
		rewrite_test_page_header(&mut encoded_b[0], |header| header.page_id = PageId(1));
		let data_b = encode_store_bytes(&encoded_b, 2);
		let (file_b, path_b) = temp_file_handle();
		let loaded_b = JpegBlockStore::from_bytes_or_init(file_b, &data_b).expect("second store should load");

		let err = match JpegStorage::from_loaded_stores(FileSystem::new(), vec![loaded_a, loaded_b]) {
			Ok(_) => panic!("storage should fail"),
			Err(err) => err,
		};

		assert!(matches!(
			err,
			Error::Pager(PagerCodecError::NonContiguousDataPages {
				ino: INodeNo(52),
				expected: 1,
				found: 0,
			})
		));

		std::fs::remove_file(path_a).expect("temp file should be removed");
		std::fs::remove_file(path_b).expect("temp file should be removed");
	}
}
