use crate::filesystem::BLOCK_SIZE;
use crate::jpeg_file::{JpegFileError, JpegFileHandle};
use crate::pager::{DecodedPages, PageId, Pager};
use crate::pager_error::PagerCodecError;
use crc::Crc;
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
	#[error("failed to write JPEG store data")]
	JpegWrite(#[source] JpegFileError),
}

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
const _: () = {
	assert!(FILE_HEADER_SIZE <= BLOCK_SIZE);
	assert!(FILE_MAGIC.len() == 8);
};

pub struct JpegBlockStore {
	header: FileHeaderV1,
	file: JpegFileHandle,
	pages_map: HashMap<PageId, usize>,
	persisted_blocks: Vec<[u8; BLOCK_SIZE]>,
}

impl JpegBlockStore {
	pub fn from_bytes_or_init_strict(file: JpegFileHandle, data: &[u8]) -> Result<(Self, DecodedPages), Error> {
		if data.len() < FILE_HEADER_SIZE {
			return Err(Error::InputBufferTooSmall(data.len()));
		}

		let header = match Self::try_decode_header(data) {
			Ok(Some(header)) => header,
			Ok(None) => return Self::init_new(file, data),
			Err(err) => return Err(err),
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
		let persisted_blocks = blocks[..usize::from(header.pages_used)].to_vec();

		let pages = Pager::decode_page_blocks(blocks)?;
		let decoded_pages = DecodedPages::from_decoded_pages(pages);
		let mut pages_map = HashMap::with_capacity(blocks.len());
		for (slot, page_id) in decoded_pages.page_ids().enumerate() {
			if pages_map.insert(page_id, slot).is_some() {
				return Err(Error::DuplicatePageId(page_id));
			}
		}

		Ok((
			Self {
				header,
				file,
				pages_map,
				persisted_blocks,
			},
			decoded_pages,
		))
	}

	pub fn init_new(file: JpegFileHandle, data: &[u8]) -> Result<(Self, DecodedPages), Error> {
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
				file,
				pages_map: HashMap::new(),
				persisted_blocks: Vec::new(),
			},
			DecodedPages::empty(),
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

	pub fn page_capacity(&self) -> usize {
		usize::from(self.header.page_capacity)
	}

	pub fn ordered_page_ids(&self) -> Vec<PageId> {
		let mut by_slot: Vec<(usize, PageId)> =
			self.pages_map.iter().map(|(page_id, slot)| (*slot, *page_id)).collect();
		by_slot.sort_by_key(|(slot, _)| *slot);
		by_slot.into_iter().map(|(_, page_id)| page_id).collect()
	}

	pub fn persisted_block(&self, page_id: PageId) -> Option<&[u8; BLOCK_SIZE]> {
		let slot = *self.pages_map.get(&page_id)?;
		self.persisted_blocks.get(slot)
	}

	pub fn persist_blocks(&mut self, blocks: &[[u8; BLOCK_SIZE]]) -> Result<bool, Error> {
		let pages_used = u16::try_from(blocks.len()).unwrap_or(u16::MAX);
		if pages_used > self.header.page_capacity {
			return Err(Error::InvalidPageCount {
				used: pages_used,
				capacity: self.header.page_capacity,
			});
		}

		let decoded_pages = Pager::decode_page_blocks(blocks)?;
		let mut new_pages_map = HashMap::with_capacity(decoded_pages.len());
		for (slot, page) in decoded_pages.into_iter().enumerate() {
			let page_id = page.page_id();
			if new_pages_map.insert(page_id, slot).is_some() {
				return Err(Error::DuplicatePageId(page_id));
			}
		}

		let is_dirty = blocks.len() != self.persisted_blocks.len()
			|| blocks
				.iter()
				.zip(self.persisted_blocks.iter())
				.any(|(new_block, old_block)| new_block != old_block);
		if !is_dirty {
			return Ok(false);
		}

		let payload_len = usize::from(self.header.page_capacity) * BLOCK_SIZE;
		let mut payload = vec![0u8; payload_len];
		for (slot, block) in blocks.iter().enumerate() {
			let start = slot * BLOCK_SIZE;
			payload[start..start + BLOCK_SIZE].copy_from_slice(block);
		}

		let mut next_header = self.header;
		next_header.pages_used = pages_used;
		next_header.crc32 = Self::compute_crc(next_header, &payload);

		let mut encoded = Vec::with_capacity(FILE_HEADER_SIZE + payload_len);
		encoded.extend_from_slice(next_header.as_bytes());
		encoded.extend_from_slice(&payload);
		self.file.write_data(&encoded).map_err(Error::JpegWrite)?;
		self.header = next_header;
		self.pages_map = new_pages_map;
		self.persisted_blocks = blocks.to_vec();

		Ok(true)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::inode::Inode;
	use crate::jpeg_file::init_file;
	use crate::pager::Pager;
	use crc::Crc;
	use fuser::{FileType, INodeNo};
	use std::ffi::OsString;
	use std::fs::File;
	use std::mem::size_of;
	use std::path::PathBuf;
	use std::time::{SystemTime, UNIX_EPOCH};
	use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

	fn temp_file_handle() -> (JpegFileHandle, PathBuf) {
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

		(JpegFileHandle::from_parts(file, path.clone(), 0), path)
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
	fn from_bytes_or_init_strict_rejects_invalid_page_count() {
		let mut data = encode_store_bytes(&[], 1);
		let mut header = FileHeaderV1::read_from_bytes(&data[..FILE_HEADER_SIZE]).expect("header should parse");
		header.pages_used = 2;
		header.crc32 = JpegBlockStore::compute_crc(header, &data[FILE_HEADER_SIZE..FILE_HEADER_SIZE + BLOCK_SIZE]);
		data[..FILE_HEADER_SIZE].copy_from_slice(header.as_bytes());
		let (file, path) = temp_file_handle();

		let err = match JpegBlockStore::from_bytes_or_init_strict(file, &data) {
			Ok(_) => panic!("load should fail"),
			Err(err) => err,
		};

		assert!(matches!(err, Error::InvalidPageCount { used: 2, capacity: 1 }));

		std::fs::remove_file(path).expect("temp file should be removed");
	}

	#[test]
	fn from_bytes_or_init_strict_rejects_invalid_stored_page_block() {
		let mut pager = Pager::new(4);
		let ino = INodeNo(3);
		pager.bytes_write(ino, 0, b"crc-check").expect("write should succeed");
		let mut encoded = pager.encode_blocks().expect("encoding should succeed");
		encoded[0][32] ^= 0xFF;
		let data = encode_store_bytes(&encoded, 2);
		let (file, path) = temp_file_handle();

		let err = match JpegBlockStore::from_bytes_or_init_strict(file, &data) {
			Ok(_) => panic!("load should fail"),
			Err(err) => err,
		};

		assert!(matches!(err, Error::Pager(PagerCodecError::CrcMismatch { .. })));

		std::fs::remove_file(path).expect("temp file should be removed");
	}

	#[test]
	fn from_bytes_or_init_strict_rejects_duplicate_page_ids() {
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

		let err = match JpegBlockStore::from_bytes_or_init_strict(file, &data) {
			Ok(_) => panic!("load should fail"),
			Err(err) => err,
		};

		assert!(matches!(err, Error::DuplicatePageId(id) if id == page_id));

		std::fs::remove_file(path).expect("temp file should be removed");
	}

	#[test]
	fn from_bytes_or_init_strict_rejects_malformed_recognized_header() {
		let mut data = encode_store_bytes(&[], 2);
		let mut header = FileHeaderV1::read_from_bytes(&data[..FILE_HEADER_SIZE]).expect("header should parse");
		header.crc32 ^= 0xFFFF_FFFF;
		data[..FILE_HEADER_SIZE].copy_from_slice(header.as_bytes());
		let (file, path) = temp_file_handle();

		let err = match JpegBlockStore::from_bytes_or_init_strict(file, &data) {
			Ok(_) => panic!("strict load should fail"),
			Err(err) => err,
		};

		assert!(matches!(err, Error::HeaderCrcMismatch { .. }));

		std::fs::remove_file(path).expect("temp file should be removed");
	}

	#[test]
	fn from_bytes_or_init_strict_allows_fragmented_inode_pages_per_store() {
		let mut pager = Pager::new(8);
		pager
			.bytes_write(INodeNo(42), 0, &[0xAB; BLOCK_SIZE * 2])
			.expect("write should succeed");
		let mut encoded = pager.encode_blocks().expect("encoding should succeed");
		assert!(encoded.len() >= 2, "expected at least two data pages");

		rewrite_test_page_header(&mut encoded[1], |header| header.file_page_no = 9);
		let data = encode_store_bytes(&encoded, 4);
		let (file, path) = temp_file_handle();

		let (_store, pages) =
			JpegBlockStore::from_bytes_or_init_strict(file, &data).expect("strict load should accept fragments");
		assert_eq!(pages.len(), encoded.len());

		std::fs::remove_file(path).expect("temp file should be removed");
	}

	#[test]
	fn from_bytes_or_init_strict_rejects_unsupported_persistence_version() {
		let mut data = encode_store_bytes(&[], 2);
		let mut header = FileHeaderV1::read_from_bytes(&data[..FILE_HEADER_SIZE]).expect("header should parse");
		header.version = FILE_VERSION + 1;
		data[..FILE_HEADER_SIZE].copy_from_slice(header.as_bytes());
		let (file, path) = temp_file_handle();

		let err = match JpegBlockStore::from_bytes_or_init_strict(file, &data) {
			Ok(_) => panic!("load should fail"),
			Err(err) => err,
		};

		assert!(matches!(err, Error::UnsupportedVersion(version) if version == FILE_VERSION + 1));

		std::fs::remove_file(path).expect("temp file should be removed");
	}

	#[test]
	fn successful_strict_load_tracks_page_slots() {
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
			JpegBlockStore::from_bytes_or_init_strict(file_b, &data_b).expect("store should load");

		assert_eq!(store_b.header.pages_used as usize, encoded_b.len());
		assert_eq!(store_b.pages_map.len(), encoded_b.len());
		assert_eq!(decoded_pages_b.len(), encoded_b.len());
		for (slot, page_id) in decoded_pages_b.page_ids().enumerate() {
			assert_eq!(store_b.pages_map.get(&page_id), Some(&slot));
		}
		std::fs::remove_file(path_b).expect("temp file should be removed");
	}

	#[test]
	fn from_bytes_or_init_strict_accepts_valid_store_with_extra_capacity_after_header_payload() {
		let data = encode_store_bytes(&[], 2);
		let mut expanded = data[..FILE_HEADER_SIZE + 2 * BLOCK_SIZE].to_vec();
		expanded.extend_from_slice(&[0xCC; BLOCK_SIZE]);
		let (file, path) = temp_file_handle();

		let (store, decoded_pages) =
			JpegBlockStore::from_bytes_or_init_strict(file, &expanded).expect("load should succeed");

		assert_eq!(store.header.page_capacity, 2);
		assert_eq!(store.header.pages_used, 0);
		assert!(decoded_pages.is_empty());

		drop(store);
		std::fs::remove_file(path).expect("temp file should be removed");
	}

	#[test]
	fn persist_blocks_roundtrips_store_payload() {
		let unique = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.expect("clock should be after unix epoch")
			.as_nanos();
		let path = std::env::temp_dir().join(format!("jpegfs-persistence-roundtrip-{unique}.jpg"));
		std::fs::copy("test/CRW_2609(FIN-Gebaeude).jpg", &path).expect("jpeg fixture should copy");

		let mut first_handle = init_file(&path).expect("copied jpeg should initialize");
		let first_data = first_handle
			.read_data(first_handle.capacity())
			.expect("copied jpeg should be readable");
		let (mut store, _) =
			JpegBlockStore::from_bytes_or_init_strict(first_handle, &first_data).expect("store should initialize");

		let mut pager = Pager::new(8);
		pager
			.bytes_write(INodeNo(99), 0, b"payload")
			.expect("write should succeed");
		let encoded = pager.encode_blocks().expect("encoding should succeed");
		let wrote = store.persist_blocks(&encoded).expect("persist should succeed");
		assert!(wrote, "changed blocks should be persisted");
		let wrote_again = store
			.persist_blocks(&encoded)
			.expect("idempotent persist should succeed");
		assert!(!wrote_again, "unchanged blocks should not be persisted");
		drop(store);

		let mut second_handle = init_file(&path).expect("persisted jpeg should initialize");
		let second_data = second_handle
			.read_data(second_handle.capacity())
			.expect("persisted jpeg should be readable");
		let (_reloaded, pages) =
			JpegBlockStore::from_bytes_or_init_strict(second_handle, &second_data).expect("store should reload");
		assert_eq!(pages.len(), encoded.len());

		std::fs::remove_file(path).expect("temp jpeg should be removed");
	}

	#[test]
	fn persist_blocks_keeps_metadata_unchanged_when_write_fails() {
		let unique = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.expect("clock should be after unix epoch")
			.as_nanos();
		let path = std::env::temp_dir().join(format!("jpegfs-persistence-write-fail-{unique}.jpg"));
		std::fs::copy("test/CRW_2609(FIN-Gebaeude).jpg", &path).expect("jpeg fixture should copy");

		let mut handle = init_file(&path).expect("copied jpeg should initialize");
		let data = handle
			.read_data(handle.capacity())
			.expect("copied jpeg should be readable");
		let (mut store, _) = JpegBlockStore::from_bytes_or_init_strict(handle, &data).expect("store should initialize");

		let header_before = store.header;
		let pages_map_before = store.pages_map.clone();
		let persisted_blocks_before = store.persisted_blocks.clone();

		let mut pager = Pager::new(8);
		pager
			.bytes_write(INodeNo(123), 0, b"write failure test payload")
			.expect("write should succeed");
		let encoded = pager.encode_blocks().expect("encoding should succeed");

		let missing_dir = std::env::temp_dir().join(format!("jpegfs-persistence-missing-dir-{unique}"));
		let _ = std::fs::remove_dir_all(&missing_dir);
		let unwritable_path = missing_dir.join("store.jpg");
		let file = File::options()
			.read(true)
			.write(true)
			.open(&path)
			.expect("fixture file should open");
		store.file = JpegFileHandle::from_parts(file, unwritable_path, store.file.capacity());

		let err = store
			.persist_blocks(&encoded)
			.expect_err("persist should fail when output path parent does not exist");
		assert!(matches!(err, Error::JpegWrite(_)), "unexpected error variant: {err:#}");
		assert_eq!(store.header, header_before);
		assert_eq!(store.pages_map, pages_map_before);
		assert_eq!(store.persisted_blocks, persisted_blocks_before);

		drop(store);
		std::fs::remove_file(path).expect("temp jpeg should be removed");
	}
}
