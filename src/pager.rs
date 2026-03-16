use crate::{
	MAGIC,
	filesystem::BLOCK_SIZE,
	inode::{Inode, InodeRaw},
	store::{Error as StoreError, StoreBlock, StoreSlot},
};
use crc::Crc;
use fuser::INodeNo;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::mem::size_of;
use std::num::{NonZeroU32, NonZeroU64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};
const PAGE_VERSION: u16 = 1;
const PAGE_CRC: Crc<u32> = Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);

#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(u16)]
pub enum PageType {
	Inodes,
	DirEntries,
	DataBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct PageId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
struct PageHeaderV1 {
	magic: [u8; 4],
	page_id: PageId,
	owner_ino: Option<NonZeroU64>,
	file_page_no: Option<NonZeroU32>,
	crc32: u32,
	version: u16,
	page_type: PageType,
	payload_len: u16,
	reserved: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
struct InodesPageWireHeader {
	count: u16,
}

const HEADER_SIZE: usize = size_of::<PageHeaderV1>();
const BLOCK_PAYLOAD_CAPACITY: usize = BLOCK_SIZE - HEADER_SIZE;

// Ensure entries.len() * size_of::<InodeRaw>() + 2 <= BLOCK_PAYLOAD_CAPACITY
// Persists to header + flattened data as bytes
pub struct InodesPage {
	page_id: PageId,
	entries: HashMap<INodeNo, Inode>,
	free_entries: usize,
}

const INODES_PAGE_CAPACITY: usize =
	(BLOCK_PAYLOAD_CAPACITY - size_of::<InodesPageWireHeader>()) / size_of::<InodeRaw>();
const DIRENTRIES_CAPACITY: usize = BLOCK_PAYLOAD_CAPACITY;

// Persists to header + entries.data
pub struct DirEntriesPage {
	page_id: PageId,
	inode: INodeNo,
	indices: BTreeMap<OsString, (StoreSlot, INodeNo)>,
	entries: StoreBlock<(OsString, INodeNo), DIRENTRIES_CAPACITY>,
}

const DATA_PAGE_CAPACITY: usize = BLOCK_PAYLOAD_CAPACITY;

// Persists to header + data
pub struct DataBytesPage {
	page_id: PageId,
	inode: INodeNo,
	length: usize,
	data: [u8; DATA_PAGE_CAPACITY],
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct INodesIndex(usize);
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct DirEntriesIndex(usize);
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct DataBytesIndex(usize);

pub struct Pager {
	inodes_pages: Vec<InodesPage>,
	dir_entries_pages: Vec<DirEntriesPage>,
	bytes_pages: Vec<DataBytesPage>,

	inodes: HashMap<INodeNo, INodesIndex>,
	dir_entries: HashMap<INodeNo, Vec<DirEntriesIndex>>,
	bytes: HashMap<INodeNo, Vec<DataBytesIndex>>,

	free_inode_slots: HashSet<INodesIndex>,
	free_dir_entry_pages: Vec<DirEntriesIndex>,
	free_bytes_pages: Vec<DataBytesIndex>,

	next_page_id: PageId,
	max_pages: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PagerBlockCounts {
	pub inodes: usize,
	pub dir_entries: usize,
	pub data_bytes: usize,
}

impl PagerBlockCounts {
	pub fn total(self) -> usize {
		self.inodes + self.dir_entries + self.data_bytes
	}
}

#[derive(Debug, thiserror::Error)]
pub enum PagerCodecError {
	#[error("unable to read header from bytes: {0:?}")]
	HeaderDecodeError(Vec<u8>),
	#[error("invalid magic: {0:?}")]
	InvalidMagic([u8; 4]),
	#[error("unsupported version: {0}")]
	UnsupportedVersion(u16),
	#[error("reserved header field is non-zero: {0}")]
	ReservedFieldNonZero(u16),
	#[error("payload length {payload_len} exceeds capacity {capacity}")]
	PayloadTooLarge { payload_len: usize, capacity: usize },
	#[error("payload length {payload_len} does not match expected {expected} for {page_type:?}")]
	InvalidPayloadLength {
		page_type: PageType,
		payload_len: usize,
		expected: usize,
	},
	#[error("page CRC mismatch: expected {expected:#010x}, actual {actual:#010x}")]
	CrcMismatch { expected: u32, actual: u32 },
	#[error("{0:?} page header is missing owner inode")]
	MissingOwnerInHeader(PageType),
	#[error("inode page entry count ({0}) exceeds capacity")]
	InodesEntryCountTooLarge(usize),
	#[error("duplicate inode {0:?} while decoding inode pages")]
	DuplicateInode(INodeNo),
	#[error("duplicate page id {0:?}")]
	DuplicatePageId(PageId),
	#[error("decoded page id space exhausted")]
	PageIdSpaceExhausted,
	#[error("block padding bytes must be zero")]
	NonZeroPadding,
	#[error("inode payload is malformed")]
	MalformedInodesPayload,
	#[error("data page length {0} exceeds capacity")]
	DataPageLengthTooLarge(usize),
	#[error("missing bytes page at index {0}")]
	MissingDataPageIndex(usize),
	#[error("file pages for inode {ino:?} are not contiguous: expected {expected}, got {found}")]
	NonContiguousDataPages { ino: INodeNo, expected: u32, found: u32 },
	#[error("duplicate directory entry name {0:?} in one page")]
	DuplicateDirEntryName(OsString),
	#[error("too many pages to encode: {0}")]
	TooManyPages(usize),
	#[error("inodes page conversion failed: {0}")]
	InodeConversion(#[from] crate::inode::InodeConversionError),
	#[error("directory page decode failed: {0}")]
	Store(#[from] StoreError),
}

pub enum DecodedPage {
	Inodes {
		page_id: PageId,
		entries: HashMap<INodeNo, Inode>,
	},
	DirEntries {
		page_id: PageId,
		inode: INodeNo,
		entries: StoreBlock<(OsString, INodeNo), DIRENTRIES_CAPACITY>,
		indices: BTreeMap<OsString, (StoreSlot, INodeNo)>,
	},
	DataBytes {
		page_id: PageId,
		inode: INodeNo,
		file_page_no: u32,
		length: usize,
		data: [u8; DATA_PAGE_CAPACITY],
	},
}

impl DecodedPage {
	pub fn page_id(&self) -> PageId {
		match self {
			Self::Inodes { page_id, .. } => *page_id,
			Self::DirEntries { page_id, .. } => *page_id,
			Self::DataBytes { page_id, .. } => *page_id,
		}
	}
}

/// Collection of pages that have been decoded from bytes but haven't been validated as part of a pager.
pub struct DecodedPages(Vec<DecodedPage>);

impl DecodedPages {
	pub fn empty() -> Self {
		Self(Vec::new())
	}

	pub fn decode_blocks(blocks: &[[u8; BLOCK_SIZE]]) -> Result<Self, PagerCodecError> {
		let pages = Pager::decode_page_blocks(blocks)?;
		Ok(Self(pages))
	}

	pub fn from_decoded_pages(pages: Vec<DecodedPage>) -> Self {
		Self(pages)
	}

	pub fn len(&self) -> usize {
		self.0.len()
	}

	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}

	pub fn page_ids(&self) -> impl Iterator<Item = PageId> + '_ {
		self.0.iter().map(DecodedPage::page_id)
	}

	pub fn append(&mut self, mut other: Self) {
		self.0.append(&mut other.0);
	}
}

impl Pager {
	pub fn new(max_pages: usize) -> Self {
		const {
			assert!(INODES_PAGE_CAPACITY > 0);
		}

		Self {
			inodes_pages: vec![],
			dir_entries_pages: vec![],
			bytes_pages: vec![],
			inodes: Default::default(),
			dir_entries: Default::default(),
			bytes: Default::default(),
			free_inode_slots: Default::default(),
			free_dir_entry_pages: Default::default(),
			free_bytes_pages: Default::default(),
			next_page_id: PageId(0),
			max_pages,
		}
	}

	/// Convenience for tests/fuzzing: encode blocks and drop PageId mapping
	pub fn encode_blocks(&self) -> Result<Vec<[u8; BLOCK_SIZE]>, PagerCodecError> {
		self.encode_blocks_with_ids()
			.map(|blocks| blocks.into_iter().map(|(_, block)| block).collect())
	}

	pub fn encode_blocks_with_ids(&self) -> Result<Vec<(PageId, [u8; BLOCK_SIZE])>, PagerCodecError> {
		let mut encoded = Vec::with_capacity(self.page_count());
		let free_dir_pages: HashSet<DirEntriesIndex> = self.free_dir_entry_pages.iter().copied().collect();
		for page in &self.inodes_pages {
			encoded.push((page.page_id, self.encode_inodes_page(page)?));
		}
		for (index, page) in self.dir_entries_pages.iter().enumerate() {
			if free_dir_pages.contains(&DirEntriesIndex(index)) {
				continue;
			}
			encoded.push((page.page_id, self.encode_dir_entries_page(page)?));
		}
		for (ino, page_indices) in &self.bytes {
			for (file_page_no, page_index) in page_indices.iter().enumerate() {
				let page = self
					.bytes_pages
					.get(page_index.0)
					.ok_or(PagerCodecError::MissingDataPageIndex(page_index.0))?;
				encoded.push((
					page.page_id,
					self.encode_data_bytes_page(page, *ino, file_page_no as u32)?,
				));
			}
		}
		Ok(encoded)
	}
	pub fn encode_blocks_by_id(&self) -> Result<BTreeMap<PageId, [u8; BLOCK_SIZE]>, PagerCodecError> {
		let mut encoded_by_id = BTreeMap::new();
		for (page_id, block) in self.encode_blocks_with_ids()? {
			if encoded_by_id.insert(page_id, block).is_some() {
				return Err(PagerCodecError::DuplicatePageId(page_id));
			}
		}
		Ok(encoded_by_id)
	}

	/// Initialize a pager from a set of decoded pages, validating them in the process
	/// Does not guarantee that a filesystem using this will be valid
	pub fn from_decoded_pages(decoded: DecodedPages, max_pages: usize) -> Result<Self, PagerCodecError> {
		Self::validate_decoded_pages(&decoded.0, max_pages)?;

		let mut max_page_id: Option<PageId> = None;
		for page in &decoded.0 {
			max_page_id = Some(max_page_id.map_or(page.page_id(), |current| PageId(current.0.max(page.page_id().0))));
		}

		let mut pager = Self::new(max_pages);
		pager.next_page_id = match max_page_id {
			Some(PageId(u32::MAX)) => return Err(PagerCodecError::PageIdSpaceExhausted),
			Some(id) => PageId(id.0 + 1),
			None => PageId(0),
		};
		let mut grouped_data_pages: HashMap<INodeNo, Vec<(u32, DataBytesPage)>> = HashMap::new();
		for page in decoded.0 {
			match page {
				DecodedPage::Inodes { page_id, entries } => {
					let index = INodesIndex(pager.inodes_pages.len());
					let free_entries = INODES_PAGE_CAPACITY.saturating_sub(entries.len());
					for ino in entries.keys() {
						pager.inodes.insert(*ino, index);
					}
					pager.inodes_pages.push(InodesPage {
						page_id,
						entries,
						free_entries,
					});
					if free_entries > 0 {
						pager.free_inode_slots.insert(index);
					}
				}
				DecodedPage::DirEntries {
					page_id,
					inode,
					entries,
					indices,
				} => {
					let index = DirEntriesIndex(pager.dir_entries_pages.len());
					pager.dir_entries_pages.push(DirEntriesPage {
						page_id,
						inode,
						indices,
						entries,
					});
					pager.dir_entries.entry(inode).or_default().push(index);
				}
				DecodedPage::DataBytes {
					page_id,
					inode,
					file_page_no,
					length,
					data,
				} => {
					grouped_data_pages.entry(inode).or_default().push((
						file_page_no,
						DataBytesPage {
							page_id,
							inode,
							length,
							data,
						},
					));
				}
			}
		}

		for (ino, mut pages) in grouped_data_pages {
			pages.sort_by_key(|(file_page_no, _)| *file_page_no);
			for (_, page) in pages {
				let index = DataBytesIndex(pager.bytes_pages.len());
				pager.bytes_pages.push(page);
				pager.bytes.entry(ino).or_default().push(index);
			}
		}
		Ok(pager)
	}

	/// Validate a set of decoded pages to uphold the nescessary invariants to construct a pager.
	/// This does not check for any additional invariants that the filesystem requires. see [`crate::filesystem::FileSystemState::check_invariants`].
	/// - Does not contain too many pages
	/// - No duplicate page ids
	/// - No page id equal to u32::MAX
	/// - No duplicate inodes
	/// - Decoded data pages for a decoded inode are contiguous
	fn validate_decoded_pages(decoded: &[DecodedPage], max_pages: usize) -> Result<(), PagerCodecError> {
		if decoded.len() > max_pages {
			return Err(PagerCodecError::TooManyPages(decoded.len()));
		}

		let mut page_ids = HashSet::new();
		let mut seen_inodes = HashSet::new();
		let mut grouped_data_pages: HashMap<INodeNo, Vec<u32>> = HashMap::new();

		for page in decoded {
			let page_id = page.page_id();
			if !page_ids.insert(page_id) {
				return Err(PagerCodecError::DuplicatePageId(page_id));
			}
			if page_id == PageId(u32::MAX) {
				return Err(PagerCodecError::PageIdSpaceExhausted);
			}

			match page {
				DecodedPage::Inodes { entries, .. } => {
					for ino in entries.keys() {
						if !seen_inodes.insert(*ino) {
							return Err(PagerCodecError::DuplicateInode(*ino));
						}
					}
				}
				DecodedPage::DataBytes {
					inode, file_page_no, ..
				} => {
					grouped_data_pages.entry(*inode).or_default().push(*file_page_no);
				}
				DecodedPage::DirEntries { .. } => {}
			}
		}

		for (ino, mut pages) in grouped_data_pages {
			pages.sort_unstable();
			for (expected, found) in pages.iter().enumerate() {
				let expected = expected as u32;
				if *found != expected {
					return Err(PagerCodecError::NonContiguousDataPages {
						ino,
						expected,
						found: *found,
					});
				}
			}
		}

		Ok(())
	}

	pub fn decode_page_blocks(blocks: &[[u8; BLOCK_SIZE]]) -> Result<Vec<DecodedPage>, PagerCodecError> {
		let mut decoded = Vec::with_capacity(blocks.len());
		for block in blocks {
			decoded.push(Self::decode_block(block)?);
		}
		Ok(decoded)
	}

	pub fn page_id_from_block(block: &[u8; BLOCK_SIZE]) -> Result<PageId, PagerCodecError> {
		let header = PageHeaderV1::try_read_from_bytes(&block[..HEADER_SIZE])
			.map_err(|_| PagerCodecError::HeaderDecodeError(block[..HEADER_SIZE].iter().copied().collect()))?;
		if header.magic != MAGIC {
			return Err(PagerCodecError::InvalidMagic(header.magic));
		}
		if header.version != PAGE_VERSION {
			return Err(PagerCodecError::UnsupportedVersion(header.version));
		}
		Ok(header.page_id)
	}

	pub fn page_count(&self) -> usize {
		self.inodes_pages.len() + self.dir_entries_pages.len() + self.bytes_pages.len()
	}

	pub fn max_pages(&self) -> usize {
		self.max_pages
	}

	pub fn block_counts(&self) -> PagerBlockCounts {
		PagerBlockCounts {
			inodes: self.inodes_pages.len(),
			dir_entries: self
				.dir_entries_pages
				.len()
				.saturating_sub(self.free_dir_entry_pages.len()),
			data_bytes: self.bytes_pages.len().saturating_sub(self.free_bytes_pages.len()),
		}
	}

	fn alloc_page_id(&mut self) -> PageId {
		let id = self.next_page_id;
		self.next_page_id = PageId(self.next_page_id.0.checked_add(1).expect("page id space exhausted"));
		id
	}

	pub fn inodes_len(&self) -> usize {
		self.inodes.len()
	}

	/// Returns a snapshot of the inodes in the pager, sorted by inode number.
	pub fn inodes_snapshot(&self) -> Vec<(INodeNo, Inode)> {
		let mut out = Vec::with_capacity(self.inodes.len());
		for ino in self.inodes.keys().copied() {
			if let Some(inode) = self.inode_get(ino).copied() {
				out.push((ino, inode));
			}
		}
		out.sort_by_key(|(ino, _)| ino.0);
		out
	}

	pub fn inode_get(&self, inode: INodeNo) -> Option<&Inode> {
		let index = self.inodes.get(&inode)?;
		self.inodes_pages.get(index.0)?.entries.get(&inode)
	}

	pub fn inode_get_mut(&mut self, inode: INodeNo) -> Option<&mut Inode> {
		let index = self.inodes.get(&inode)?;
		self.inodes_pages.get_mut(index.0)?.entries.get_mut(&inode)
	}

	pub fn inode_remove(&mut self, inode: INodeNo) -> Option<Inode> {
		let index = self.inodes.remove(&inode)?;
		let page = &mut self.inodes_pages[index.0];
		let removed = page.entries.remove(&inode)?;
		page.free_entries = INODES_PAGE_CAPACITY.saturating_sub(page.entries.len());
		if page.free_entries > 0 {
			self.free_inode_slots.insert(index);
		} else {
			self.free_inode_slots.remove(&index);
		}

		Some(removed)
	}

	pub fn inodes_contains(&self, inode: INodeNo) -> bool {
		self.inodes.contains_key(&inode)
	}

	pub fn inodes_insert(&mut self, ino: INodeNo, inode: Inode) -> Result<(), ()> {
		if let Some(&existing_index) = self.inodes.get(&ino) {
			let page = &mut self.inodes_pages[existing_index.0];
			page.entries.insert(ino, inode);
			return Ok(());
		}

		let free_index = self
			.free_inode_slots
			.iter()
			.copied()
			.find(|index| self.inodes_pages[index.0].free_entries > 0);

		if let Some(index) = free_index {
			let page = &mut self.inodes_pages[index.0];
			page.entries.insert(ino, inode);
			page.free_entries = page.free_entries.saturating_sub(1);
			self.inodes.insert(ino, index);
			if page.free_entries == 0 {
				self.free_inode_slots.remove(&index);
			}
		} else {
			if self.page_count() >= self.max_pages {
				return Err(());
			}
			let free_entries = INODES_PAGE_CAPACITY - 1;
			let new_page = InodesPage {
				page_id: self.alloc_page_id(),
				entries: [(ino, inode)].into(),
				free_entries,
			};
			let new_index = INodesIndex(self.inodes_pages.len());
			if free_entries > 0 {
				self.free_inode_slots.insert(new_index);
			}
			self.inodes_pages.push(new_page);
			self.inodes.insert(ino, new_index);
		}
		Ok(())
	}

	pub fn dir_entries_contains(&self, inode: INodeNo, name: &OsStr) -> bool {
		self.dir_entries_get(inode, name).is_some()
	}

	pub fn dir_entries_exists(&self, inode: INodeNo) -> bool {
		self.dir_entries.contains_key(&inode)
	}

	pub fn dir_entries_get(&self, inode: INodeNo, name: &OsStr) -> Option<INodeNo> {
		let page_indices = self.dir_entries.get(&inode)?;
		for page_index in page_indices.iter().rev() {
			let page = self.dir_entries_pages.get(page_index.0)?;
			if let Some((_, child_ino)) = page.indices.get(name) {
				return Some(*child_ino);
			}
		}
		None
	}

	pub fn dir_entries_get_dir(&self, inode: INodeNo) -> Option<BTreeMap<OsString, INodeNo>> {
		let page_indices = self.dir_entries.get(&inode)?;
		let mut out = BTreeMap::new();
		for page_index in page_indices {
			let page = self.dir_entries_pages.get(page_index.0)?;
			for (name, (_, child_ino)) in &page.indices {
				out.insert(name.clone(), *child_ino);
			}
		}
		Some(out)
	}

	pub fn dir_entries_insert(&mut self, inode: INodeNo, name: OsString, child: INodeNo) -> Result<(), ()> {
		// Remove existing entry if name already exists
		let previous_child = match self.remove_dir_entry(inode, name.as_os_str()) {
			Ok(previous) => previous,
			Err(()) => return Err(()),
		};

		// Insert it
		if self.insert_new_dir_entry(inode, name.clone(), child).is_ok() {
			return Ok(());
		}

		// If insertion failed: restore previously removed entry and error
		if let Some(previous_child) = previous_child {
			let _ = self.insert_new_dir_entry(inode, name, previous_child);
		}
		Err(())
	}

	pub fn dir_entries_remove(&mut self, inode: INodeNo, name: &OsStr) -> Option<INodeNo> {
		self.remove_dir_entry(inode, name).ok().flatten()
	}

	pub fn dir_entries_clear(&mut self, inode: INodeNo) {
		let Some(page_indices) = self.dir_entries.remove(&inode) else {
			return;
		};
		for page_index in page_indices {
			self.release_dir_entries_page(page_index);
		}
	}

	fn allocate_dir_entries_page(&mut self, inode: INodeNo) -> Result<DirEntriesIndex, ()> {
		if let Some(page_index) = self.free_dir_entry_pages.pop() {
			let page = self.dir_entries_pages.get_mut(page_index.0).ok_or(())?;
			page.inode = inode;
			page.indices.clear();
			page.entries = StoreBlock::new(page.page_id);
			return Ok(page_index);
		}

		if self.page_count() >= self.max_pages {
			return Err(());
		}

		let page_id = self.alloc_page_id();
		let new_index = DirEntriesIndex(self.dir_entries_pages.len());
		self.dir_entries_pages.push(DirEntriesPage {
			page_id,
			inode,
			indices: BTreeMap::new(),
			entries: StoreBlock::new(page_id),
		});
		Ok(new_index)
	}

	fn release_dir_entries_page(&mut self, page_index: DirEntriesIndex) {
		if let Some(page) = self.dir_entries_pages.get_mut(page_index.0) {
			page.indices.clear();
			page.entries = StoreBlock::new(page.page_id);
			self.free_dir_entry_pages.push(page_index);
		}
	}

	fn insert_new_dir_entry(&mut self, inode: INodeNo, name: OsString, child: INodeNo) -> Result<(), ()> {
		// Try finding dir entries page with free capacity
		if let Some(page_indices) = self.dir_entries.get(&inode) {
			for page_index in page_indices {
				let page = &mut self.dir_entries_pages[page_index.0];
				debug_assert_eq!(page.inode, inode);
				match page.entries.try_store((name.clone(), child)) {
					Ok(slot) => {
						page.indices.insert(name, (slot, child));
						return Ok(());
					}
					Err(StoreError::NoSpace) => continue,
					Err(_) => return Err(()),
				}
			}
		}

		// No free space found -> allocate new page
		let page_index = self.allocate_dir_entries_page(inode)?;
		let page = self.dir_entries_pages.get_mut(page_index.0).ok_or(())?;
		let slot = match page.entries.try_store((name.clone(), child)) {
			Ok(slot) => slot,
			Err(_) => {
				self.release_dir_entries_page(page_index);
				return Err(());
			}
		};
		page.indices.insert(name, (slot, child));
		self.dir_entries.entry(inode).or_default().push(page_index);
		Ok(())
	}

	fn remove_dir_entry(&mut self, inode: INodeNo, name: &OsStr) -> Result<Option<INodeNo>, ()> {
		let Some(page_indices) = self.dir_entries.get(&inode) else {
			return Ok(None);
		};

		for page_index in page_indices.into_iter().rev() {
			let removed = {
				let page = self.dir_entries_pages.get_mut(page_index.0).ok_or(())?;
				debug_assert_eq!(page.inode, inode);
				let Some((slot, child)) = page.indices.remove(name) else {
					continue;
				};
				let (_, remap) = page.entries.remove(slot).map_err(|_| ())?;
				if let Some((from_slot, to_slot)) = remap {
					Self::remap_single_dir_entry_slot(page, from_slot, to_slot);
				}
				Some(child)
			};

			if let Some(child) = removed {
				self.prune_empty_dir_pages(inode);
				return Ok(Some(child));
			}
		}
		Ok(None)
	}

	fn remap_single_dir_entry_slot(page: &mut DirEntriesPage, from_slot: StoreSlot, to_slot: StoreSlot) {
		if from_slot == to_slot {
			return;
		}
		for (slot, _) in page.indices.values_mut() {
			if *slot == from_slot {
				*slot = to_slot;
				return;
			}
		}
		debug_assert!(false, "swap-remove remap slot must exist in index map");
	}

	fn prune_empty_dir_pages(&mut self, inode: INodeNo) {
		let (remove_inode, to_release) = {
			let Some(page_indices) = self.dir_entries.get_mut(&inode) else {
				return;
			};

			let mut retained = Vec::with_capacity(page_indices.len());
			let mut to_release = Vec::new();
			for &page_index in page_indices.iter() {
				let is_empty = self
					.dir_entries_pages
					.get(page_index.0)
					.is_none_or(|page| page.indices.is_empty());
				if is_empty {
					to_release.push(page_index);
				} else {
					retained.push(page_index);
				}
			}
			*page_indices = retained;
			(page_indices.is_empty(), to_release)
		};

		for page_index in to_release {
			self.release_dir_entries_page(page_index);
		}
		if remove_inode {
			self.dir_entries.remove(&inode);
		}
	}

	pub fn bytes_len(&self, inode: INodeNo) -> usize {
		let Some(page_indices) = self.bytes.get(&inode) else {
			return 0;
		};
		page_indices
			.iter()
			.filter_map(|page_index| self.bytes_pages.get(page_index.0))
			.map(|page| page.length)
			.sum()
	}

	pub fn bytes_read(&self, inode: INodeNo, offset: usize, size: usize) -> Vec<u8> {
		let len = self.bytes_len(inode);
		if offset >= len || size == 0 {
			return Vec::new();
		}

		let end = offset.saturating_add(size).min(len);
		let mut out = vec![0u8; end - offset];
		let Some(page_indices) = self.bytes.get(&inode) else {
			return Vec::new();
		};

		let mut cursor = offset;
		let mut out_written = 0usize;
		while cursor < end {
			let page_no = cursor / DATA_PAGE_CAPACITY;
			let in_page = cursor % DATA_PAGE_CAPACITY;
			let take = (end - cursor).min(DATA_PAGE_CAPACITY - in_page);
			let Some(page_index) = page_indices.get(page_no) else {
				break;
			};
			let Some(page) = self.bytes_pages.get(page_index.0) else {
				break;
			};
			let available = page.length.saturating_sub(in_page).min(take);
			if available == 0 {
				break;
			}
			out[out_written..out_written + available].copy_from_slice(&page.data[in_page..in_page + available]);
			cursor += available;
			out_written += available;
		}

		out.truncate(out_written);
		out
	}

	pub fn bytes_write(&mut self, inode: INodeNo, offset: usize, data: &[u8]) -> Result<usize, ()> {
		if data.is_empty() {
			return Ok(0);
		}

		let end = offset.checked_add(data.len()).ok_or(())?;
		let new_len = self.bytes_len(inode).max(end);
		self.bytes_resize(inode, new_len)?;

		let page_indices = self.bytes.get(&inode).cloned().ok_or(())?;
		let mut data_cursor = 0usize;
		let mut write_cursor = offset;
		while data_cursor < data.len() {
			let page_no = write_cursor / DATA_PAGE_CAPACITY;
			let in_page = write_cursor % DATA_PAGE_CAPACITY;
			let take = (data.len() - data_cursor).min(DATA_PAGE_CAPACITY - in_page);
			let page_index = page_indices.get(page_no).ok_or(())?;
			let page = self.bytes_pages.get_mut(page_index.0).ok_or(())?;
			debug_assert_eq!(page.inode, inode);
			page.data[in_page..in_page + take].copy_from_slice(&data[data_cursor..data_cursor + take]);
			data_cursor += take;
			write_cursor += take;
		}
		Ok(data.len())
	}

	pub fn bytes_truncate(&mut self, inode: INodeNo, new_len: usize) -> Result<(), ()> {
		self.bytes_resize(inode, new_len)
	}

	pub fn bytes_remove(&mut self, inode: INodeNo) {
		let Some(page_indices) = self.bytes.remove(&inode) else {
			return;
		};
		for page_index in page_indices {
			self.release_bytes_page(page_index);
		}
	}

	fn bytes_resize(&mut self, inode: INodeNo, new_len: usize) -> Result<(), ()> {
		let old_len = self.bytes_len(inode);
		let current_pages = self.bytes.get(&inode).map_or(0, Vec::len);
		let required_pages = if new_len == 0 {
			0
		} else {
			new_len.div_ceil(DATA_PAGE_CAPACITY)
		};

		if required_pages > current_pages {
			let allocate = required_pages - current_pages;
			let mut allocated = Vec::with_capacity(allocate);
			for _ in 0..allocate {
				match self.allocate_bytes_page(inode) {
					Ok(new_index) => allocated.push(new_index),
					Err(()) => {
						// Keep resize atomic: return all newly allocated pages on failure.
						for page_index in allocated {
							self.release_bytes_page(page_index);
						}
						return Err(());
					}
				}
			}
			self.bytes.entry(inode).or_default().extend(allocated);
		} else if required_pages < current_pages {
			let mut removed = Vec::new();
			let mut remove_inode = false;
			if let Some(page_indices) = self.bytes.get_mut(&inode) {
				removed.extend(page_indices.drain(required_pages..));
				if page_indices.is_empty() {
					remove_inode = true;
				}
			}
			if remove_inode {
				self.bytes.remove(&inode);
			}
			for page_index in removed {
				self.release_bytes_page(page_index);
			}
		}

		if new_len > old_len {
			self.bytes_zero_range(inode, old_len, new_len);
		}
		if old_len > new_len {
			self.bytes_zero_range(inode, new_len, old_len);
		}

		if let Some(page_indices) = self.bytes.get(&inode).cloned() {
			for (page_no, page_index) in page_indices.iter().enumerate() {
				let page = self.bytes_pages.get_mut(page_index.0).ok_or(())?;
				debug_assert_eq!(page.inode, inode);
				let start = page_no * DATA_PAGE_CAPACITY;
				let desired = if start >= new_len {
					0
				} else {
					(new_len - start).min(DATA_PAGE_CAPACITY)
				};
				page.length = desired;
			}
		}
		Ok(())
	}

	fn allocate_bytes_page(&mut self, inode: INodeNo) -> Result<DataBytesIndex, ()> {
		if let Some(page_index) = self.free_bytes_pages.pop() {
			let page = self.bytes_pages.get_mut(page_index.0).ok_or(())?;
			page.inode = inode;
			page.length = 0;
			page.data.fill(0);
			return Ok(page_index);
		}

		if self.page_count() >= self.max_pages {
			return Err(());
		}

		let page_id = self.alloc_page_id();
		let new_index = DataBytesIndex(self.bytes_pages.len());
		self.bytes_pages.push(DataBytesPage {
			page_id,
			inode,
			length: 0,
			data: [0; DATA_PAGE_CAPACITY],
		});
		Ok(new_index)
	}

	fn release_bytes_page(&mut self, page_index: DataBytesIndex) {
		if let Some(page) = self.bytes_pages.get_mut(page_index.0) {
			page.length = 0;
			page.data.fill(0);
			self.free_bytes_pages.push(page_index);
		}
	}

	fn bytes_zero_range(&mut self, inode: INodeNo, start: usize, end: usize) {
		if start >= end {
			return;
		}
		let Some(page_indices) = self.bytes.get(&inode).cloned() else {
			return;
		};

		let mut cursor = start;
		while cursor < end {
			let page_no = cursor / DATA_PAGE_CAPACITY;
			let in_page = cursor % DATA_PAGE_CAPACITY;
			let clear = (end - cursor).min(DATA_PAGE_CAPACITY - in_page);
			if let Some(page_index) = page_indices.get(page_no)
				&& let Some(page) = self.bytes_pages.get_mut(page_index.0)
			{
				page.data[in_page..in_page + clear].fill(0);
			}
			cursor += clear;
		}
	}

	/// Encode an inodes page, format:
	/// header: {count: 2 bytes}
	/// payload: len * size_of::<InodeRaw>() bytes
	fn encode_inodes_page(&self, page: &InodesPage) -> Result<[u8; BLOCK_SIZE], PagerCodecError> {
		let mut entries: Vec<_> = page.entries.iter().collect();
		entries.sort_by_key(|(ino, _)| ino.0);
		if entries.len() > INODES_PAGE_CAPACITY {
			return Err(PagerCodecError::InodesEntryCountTooLarge(entries.len()));
		}

		let header = InodesPageWireHeader {
			count: u16::try_from(entries.len())
				.map_err(|_| PagerCodecError::InodesEntryCountTooLarge(entries.len()))?,
		};
		let mut payload = Vec::with_capacity(size_of::<InodesPageWireHeader>() + entries.len() * size_of::<InodeRaw>());
		payload.extend_from_slice(header.as_bytes());
		for (ino, inode) in entries {
			let raw = InodeRaw::from_parts(*ino, inode)?;
			payload.extend_from_slice(raw.as_bytes());
		}

		Self::encode_wire_block(
			PageType::Inodes,
			page.page_id,
			None,
			None,
			&payload,
			BLOCK_PAYLOAD_CAPACITY,
		)
	}

	fn encode_dir_entries_page(&self, page: &DirEntriesPage) -> Result<[u8; BLOCK_SIZE], PagerCodecError> {
		Self::encode_wire_block(
			PageType::DirEntries,
			page.page_id,
			Some(NonZeroU64::new(page.inode.0).expect("INodeNo::ROOT and allocated inodes must be nonzero")),
			None,
			page.entries.as_bytes(),
			DIRENTRIES_CAPACITY,
		)
	}

	fn encode_data_bytes_page(
		&self,
		page: &DataBytesPage,
		owner_ino: INodeNo,
		file_page_no: u32,
	) -> Result<[u8; BLOCK_SIZE], PagerCodecError> {
		if page.length > DATA_PAGE_CAPACITY {
			return Err(PagerCodecError::DataPageLengthTooLarge(page.length));
		}
		Self::encode_wire_block(
			PageType::DataBytes,
			page.page_id,
			Some(NonZeroU64::new(owner_ino.0).expect("InodeNo must never be 0")),
			NonZeroU32::new(file_page_no),
			&page.data[..page.length],
			DATA_PAGE_CAPACITY,
		)
	}

	/// Encode a wire block. Fails if paylod is too large
	fn encode_wire_block(
		page_type: PageType,
		page_id: PageId,
		owner_ino: Option<NonZeroU64>,
		file_page_no: Option<NonZeroU32>,
		payload: &[u8],
		max_payload: usize,
	) -> Result<[u8; BLOCK_SIZE], PagerCodecError> {
		if payload.len() > max_payload || payload.len() > BLOCK_PAYLOAD_CAPACITY {
			return Err(PagerCodecError::PayloadTooLarge {
				payload_len: payload.len(),
				capacity: max_payload.min(BLOCK_PAYLOAD_CAPACITY),
			});
		}

		let payload_len = u16::try_from(payload.len()).expect("block payload capacity must fit into u16");
		let mut header = PageHeaderV1 {
			magic: MAGIC,
			version: PAGE_VERSION,
			page_type,
			page_id,
			owner_ino,
			file_page_no,
			payload_len,
			reserved: 0,
			crc32: 0,
		};
		header.crc32 = Self::compute_crc(&header, payload);

		let mut out = [0u8; BLOCK_SIZE];
		out[..HEADER_SIZE].copy_from_slice(header.as_bytes());
		out[HEADER_SIZE..HEADER_SIZE + payload.len()].copy_from_slice(payload);
		Ok(out)
	}

	/// Decode block into a page, validating page internal invariants:
	/// - valid magic
	/// - current version
	/// - reserved data is not zero
	/// - payload length does not exceed block payload capacity
	/// - padding bytes after data are zeroed
	/// - crc matches
	/// - header holds values needed for its page type
	/// - header does hold values not needed for its page type
	/// - page type specific invariants
	fn decode_block(block: &[u8; BLOCK_SIZE]) -> Result<DecodedPage, PagerCodecError> {
		let header = Self::try_read_header(&block)?;
		if header.magic != MAGIC {
			return Err(PagerCodecError::InvalidMagic(header.magic));
		}
		if header.version != PAGE_VERSION {
			return Err(PagerCodecError::UnsupportedVersion(header.version));
		}
		if header.reserved != 0 {
			return Err(PagerCodecError::ReservedFieldNonZero(header.reserved));
		}

		let payload_len = header.payload_len as usize;
		if payload_len > BLOCK_PAYLOAD_CAPACITY {
			return Err(PagerCodecError::PayloadTooLarge {
				payload_len,
				capacity: BLOCK_PAYLOAD_CAPACITY,
			});
		}
		let payload = &block[HEADER_SIZE..HEADER_SIZE + payload_len];
		let padding = &block[HEADER_SIZE + payload_len..];
		if !padding.iter().all(|byte| *byte == 0) {
			return Err(PagerCodecError::NonZeroPadding);
		}

		let actual_crc = Self::compute_crc(&header, payload);
		if actual_crc != header.crc32 {
			return Err(PagerCodecError::CrcMismatch {
				expected: header.crc32,
				actual: actual_crc,
			});
		}

		match header.page_type {
			PageType::Inodes => Self::decode_inodes_page(header.page_id, payload_len, payload),
			PageType::DirEntries => {
				let owner_ino = INodeNo(
					header
						.owner_ino
						.map(NonZeroU64::get)
						.ok_or(PagerCodecError::MissingOwnerInHeader(PageType::DirEntries))?,
				);
				Self::decode_dir_entries_page(header.page_id, owner_ino, payload_len, payload)
			}
			PageType::DataBytes => Self::decode_data_bytes_page(
				header.page_id,
				INodeNo(
					header
						.owner_ino
						.map(NonZeroU64::get)
						.ok_or(PagerCodecError::MissingOwnerInHeader(PageType::DataBytes))?,
				),
				header.file_page_no.map(NonZeroU32::get).unwrap_or(0),
				payload_len,
				payload,
			),
		}
	}

	fn try_read_header(block: &[u8; 4096]) -> Result<PageHeaderV1, PagerCodecError> {
		PageHeaderV1::try_read_from_bytes(&block[..HEADER_SIZE])
			.map_err(|_| PagerCodecError::HeaderDecodeError(block[..HEADER_SIZE].iter().copied().collect()))
	}

	/// Decode a inodes page, validating its invariants:
	/// - payload is long enough
	/// - payload length matches encoded amount of items
	/// - inodes counts does not exceed capacity
	/// - no duplicate inodes
	fn decode_inodes_page(page_id: PageId, payload_len: usize, payload: &[u8]) -> Result<DecodedPage, PagerCodecError> {
		const HEADER_LEN: usize = size_of::<InodesPageWireHeader>();
		let header = InodesPageWireHeader::read_from_bytes(
			payload
				.get(..HEADER_LEN)
				.ok_or(PagerCodecError::MalformedInodesPayload)?,
		)
		.expect("..header_len is big enough for header");
		let count = usize::from(header.count);
		let raw_bytes = &payload[HEADER_LEN..];
		let expected = count
			.checked_mul(size_of::<InodeRaw>())
			.and_then(|bytes| bytes.checked_add(HEADER_LEN))
			.ok_or(PagerCodecError::MalformedInodesPayload)?;
		if payload_len != expected {
			return Err(PagerCodecError::InvalidPayloadLength {
				page_type: PageType::Inodes,
				payload_len,
				expected,
			});
		}
		if count > INODES_PAGE_CAPACITY {
			return Err(PagerCodecError::InodesEntryCountTooLarge(count));
		}

		let mut entries = HashMap::with_capacity(count);
		for chunk in raw_bytes.chunks_exact(size_of::<InodeRaw>()) {
			let raw = InodeRaw::try_read_from_bytes(chunk).map_err(|_| PagerCodecError::MalformedInodesPayload)?;
			let (ino, inode) = raw.into_parts()?;
			if entries.insert(ino, inode).is_some() {
				return Err(PagerCodecError::DuplicateInode(ino));
			}
		}
		Ok(DecodedPage::Inodes { page_id, entries })
	}

	/// Decode a dir entries page, validating its invariants:
	/// - payload length is correct
	/// - no duplicate entry names
	/// - StoreBlock is correctly encoded
	fn decode_dir_entries_page(
		page_id: PageId,
		inode: INodeNo,
		payload_len: usize,
		payload: &[u8],
	) -> Result<DecodedPage, PagerCodecError> {
		let raw_payload: [u8; DIRENTRIES_CAPACITY] =
			payload.try_into().map_err(|_| PagerCodecError::InvalidPayloadLength {
				page_type: PageType::DirEntries,
				payload_len,
				expected: DIRENTRIES_CAPACITY,
			})?;
		let entries = StoreBlock::<(OsString, INodeNo), DIRENTRIES_CAPACITY>::from_bytes(raw_payload)?;
		let mut indices = BTreeMap::new();
		for slot in entries.slots() {
			let (name, child_ino) = entries.get(slot)?;
			if indices.insert(name.clone(), (slot, child_ino)).is_some() {
				return Err(PagerCodecError::DuplicateDirEntryName(name));
			}
		}
		Ok(DecodedPage::DirEntries {
			page_id,
			inode,
			entries,
			indices,
		})
	}

	/// Decode a data bytes page, validating that its payload length does not exceed capacity
	fn decode_data_bytes_page(
		page_id: PageId,
		inode: INodeNo,
		file_page_no: u32,
		payload_len: usize,
		payload: &[u8],
	) -> Result<DecodedPage, PagerCodecError> {
		if payload_len > DATA_PAGE_CAPACITY {
			return Err(PagerCodecError::PayloadTooLarge {
				payload_len,
				capacity: DATA_PAGE_CAPACITY,
			});
		}
		let mut data = [0u8; DATA_PAGE_CAPACITY];
		data[..payload_len].copy_from_slice(payload);
		Ok(DecodedPage::DataBytes {
			page_id,
			inode,
			file_page_no,
			length: payload_len,
			data,
		})
	}

	fn compute_crc(header: &PageHeaderV1, payload: &[u8]) -> u32 {
		let mut header_no_crc = *header;
		header_no_crc.crc32 = 0; // Remove existing checksum so it does not influence new checksum
		let mut digest = PAGE_CRC.digest();
		digest.update(header_no_crc.as_bytes());
		digest.update(payload);
		digest.finalize()
	}

	/// Expensive consistency validation for tests, fuzzing, and diagnostics.
	/// Normal pager operations must not call this implicitly.
	pub fn check_invariants(&self) {
		debug_assert!(self.page_count() <= self.max_pages);

		let mut active_dir_pages = HashSet::new();
		for (ino, page_indices) in &self.dir_entries {
			for page_index in page_indices {
				let page = &self.dir_entries_pages[page_index.0];
				debug_assert_eq!(page.inode, *ino);
				debug_assert!(active_dir_pages.insert(*page_index));
				for (name, (slot, child_ino)) in &page.indices {
					let (stored_name, stored_child) = page.entries.get(*slot).expect("slot index must stay valid");
					debug_assert_eq!(&stored_name, name);
					debug_assert_eq!(stored_child, *child_ino);
				}
			}
		}
		let mut free_dir_pages = HashSet::new();
		for page_index in &self.free_dir_entry_pages {
			debug_assert!(free_dir_pages.insert(*page_index));
			debug_assert!(!active_dir_pages.contains(page_index));
		}

		let mut active_bytes_pages = HashSet::new();
		for (ino, page_indices) in &self.bytes {
			for (page_no, page_index) in page_indices.iter().enumerate() {
				let page = &self.bytes_pages[page_index.0];
				debug_assert_eq!(page.inode, *ino);
				debug_assert!(active_bytes_pages.insert(*page_index));
				debug_assert!(page.length <= DATA_PAGE_CAPACITY);
				if page_no + 1 < page_indices.len() {
					debug_assert_eq!(page.length, DATA_PAGE_CAPACITY);
				}
			}
		}
		let mut free_bytes_pages = HashSet::new();
		for page_index in &self.free_bytes_pages {
			debug_assert!(free_bytes_pages.insert(*page_index));
			debug_assert!(!active_bytes_pages.contains(page_index));
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use fuser::FileType;
	use std::os::unix::ffi::OsStringExt;
	use std::time::SystemTime;

	fn inode() -> Inode {
		let now = SystemTime::now();
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

	#[test]
	fn insert_updates_index_and_lookup() {
		let mut pager = Pager::new(8);
		let a = inode();

		pager.inodes_insert(INodeNo(1), a).expect("insert should succeed");

		assert!(pager.inodes_contains(INodeNo(1)));
		assert_eq!(pager.inodes_len(), 1);
		assert!(pager.inode_get(INodeNo(1)).is_some());
		pager.check_invariants();
	}

	#[test]
	fn remove_clears_index_and_lookup() {
		let mut pager = Pager::new(8);
		let a = inode();

		pager.inodes_insert(INodeNo(2), a).expect("insert should succeed");
		let _removed = pager.inode_remove(INodeNo(2)).expect("remove should return inode");

		assert!(!pager.inodes_contains(INodeNo(2)));
		assert!(pager.inode_get(INodeNo(2)).is_none());
		assert_eq!(pager.inodes_len(), 0);
		pager.check_invariants();
	}

	#[test]
	fn insert_same_inode_replaces_value() {
		let mut pager = Pager::new(8);
		let mut a = inode();
		a.size = 10;
		pager.inodes_insert(INodeNo(3), a).expect("insert should succeed");

		let mut b = inode();
		b.size = 99;
		pager.inodes_insert(INodeNo(3), b).expect("update should succeed");

		assert_eq!(pager.inodes_len(), 1);
		assert_eq!(pager.inode_get(INodeNo(3)).expect("inode should exist").size, 99);
		pager.check_invariants();
	}

	#[test]
	fn dir_entries_insert_lookup_replace_remove() {
		let mut pager = Pager::new(8);
		let name = OsString::from("child");
		let parent = INodeNo(10);
		assert!(!pager.dir_entries_exists(parent));

		pager
			.dir_entries_insert(parent, name.clone(), INodeNo(11))
			.expect("initial insert should succeed");
		assert!(pager.dir_entries_exists(parent));
		assert!(pager.dir_entries_contains(parent, &name));
		assert_eq!(pager.dir_entries_get(parent, &name), Some(INodeNo(11)));

		pager
			.dir_entries_insert(parent, name.clone(), INodeNo(12))
			.expect("replace should succeed");
		assert_eq!(pager.dir_entries_get(parent, &name), Some(INodeNo(12)));

		let removed = pager.dir_entries_remove(parent, &name);
		assert_eq!(removed, Some(INodeNo(12)));
		assert_eq!(pager.dir_entries_get(parent, &name), None);
		assert!(!pager.dir_entries_exists(parent));
		pager.check_invariants();
	}

	#[test]
	fn dir_entries_grow_to_multiple_pages() {
		let mut pager = Pager::new(32);
		let parent = INodeNo(20);

		for i in 0..100u64 {
			let bytes = vec![b'a'; 96];
			let mut name = OsString::from_vec(bytes);
			name.push(i.to_string());
			pager
				.dir_entries_insert(parent, name.clone(), INodeNo(1_000 + i))
				.expect("insert should fit in available page budget");
			assert_eq!(pager.dir_entries_get(parent, &name), Some(INodeNo(1_000 + i)));
		}

		let snapshot = pager.dir_entries_get_dir(parent).expect("directory should exist");
		assert_eq!(snapshot.len(), 100);
		pager.check_invariants();
	}

	#[test]
	fn dir_entries_fail_when_out_of_pages() {
		let mut pager = Pager::new(1);
		let parent = INodeNo(30);
		let mut hit_limit = false;

		for i in 0..1000u64 {
			let mut name = OsString::from_vec(vec![b'z'; 128]);
			name.push(i.to_string());
			if pager.dir_entries_insert(parent, name, INodeNo(31 + i)).is_err() {
				hit_limit = true;
				break;
			}
		}
		assert!(hit_limit, "directory inserts should eventually exhaust a single page");
		pager.check_invariants();
	}

	#[test]
	fn bytes_write_read_single_page() {
		let mut pager = Pager::new(8);
		let ino = INodeNo(40);

		pager.bytes_write(ino, 0, b"hello").expect("write should succeed");
		assert_eq!(pager.bytes_len(ino), 5);
		assert_eq!(pager.bytes_read(ino, 0, 5), b"hello");
		pager.check_invariants();
	}

	#[test]
	fn bytes_write_read_cross_page() {
		let mut pager = Pager::new(8);
		let ino = INodeNo(41);
		let first = vec![0x11; DATA_PAGE_CAPACITY - 2];
		let second = vec![0x22; 8];

		pager.bytes_write(ino, 0, &first).expect("first write should succeed");
		pager
			.bytes_write(ino, DATA_PAGE_CAPACITY - 2, &second)
			.expect("cross-page write should succeed");

		let out = pager.bytes_read(ino, DATA_PAGE_CAPACITY - 4, 12);
		assert_eq!(out, vec![0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22]);
		pager.check_invariants();
	}

	#[test]
	fn bytes_sparse_write_zero_fills_gap() {
		let mut pager = Pager::new(8);
		let ino = INodeNo(42);

		pager.bytes_write(ino, 4, b"xy").expect("sparse write should succeed");
		assert_eq!(pager.bytes_len(ino), 6);
		assert_eq!(pager.bytes_read(ino, 0, 6), vec![0, 0, 0, 0, b'x', b'y']);
		pager.check_invariants();
	}

	#[test]
	fn bytes_truncate_shrink_and_extend() {
		let mut pager = Pager::new(8);
		let ino = INodeNo(43);

		pager
			.bytes_write(ino, 0, b"abcdef")
			.expect("initial write should succeed");
		pager.bytes_truncate(ino, 3).expect("shrink should succeed");
		assert_eq!(pager.bytes_read(ino, 0, 8), b"abc");

		pager.bytes_truncate(ino, 6).expect("extend should succeed");
		assert_eq!(pager.bytes_read(ino, 0, 8), vec![b'a', b'b', b'c', 0, 0, 0]);
		pager.check_invariants();
	}

	#[test]
	fn bytes_overwrite_keeps_length() {
		let mut pager = Pager::new(8);
		let ino = INodeNo(44);
		pager
			.bytes_write(ino, 0, b"abcdef")
			.expect("initial write should succeed");
		pager
			.bytes_write(ino, 2, b"ZZ")
			.expect("overwrite write should succeed");

		assert_eq!(pager.bytes_len(ino), 6);
		assert_eq!(pager.bytes_read(ino, 0, 6), b"abZZef");
		pager.check_invariants();
	}

	#[test]
	fn bytes_remove_clears_data() {
		let mut pager = Pager::new(8);
		let ino = INodeNo(45);
		pager.bytes_write(ino, 0, b"payload").expect("write should succeed");
		assert_eq!(pager.bytes_len(ino), 7);

		pager.bytes_remove(ino);
		assert_eq!(pager.bytes_len(ino), 0);
		assert!(pager.bytes_read(ino, 0, 8).is_empty());
		pager.check_invariants();
	}

	#[test]
	fn bytes_fail_when_out_of_pages() {
		let mut pager = Pager::new(1);
		let ino = INodeNo(46);
		let data = vec![0x55; DATA_PAGE_CAPACITY + 1];
		assert!(pager.bytes_write(ino, 0, &data).is_err());
		pager.check_invariants();
	}

	#[test]
	fn bytes_resize_rollback_on_partial_allocation_failure() {
		let mut pager = Pager::new(2);
		let a = INodeNo(60);
		let b = INodeNo(61);
		let one_page = vec![0xAA; DATA_PAGE_CAPACITY];

		pager
			.bytes_write(a, 0, &one_page)
			.expect("first inode should consume one page");
		assert!(
			pager.bytes_write(b, 0, &vec![0xBB; DATA_PAGE_CAPACITY + 1]).is_err(),
			"second inode write should fail after partial growth attempt"
		);

		pager.bytes_remove(a);
		assert!(
			pager.bytes_write(b, 0, &one_page).is_ok(),
			"failed write must not leak partially allocated pages"
		);
		pager.check_invariants();
	}

	#[test]
	fn bytes_remove_reuses_freed_pages() {
		let mut pager = Pager::new(1);
		let ino = INodeNo(47);
		let payload = vec![0x33; DATA_PAGE_CAPACITY];

		pager
			.bytes_write(ino, 0, &payload)
			.expect("initial write should fit exactly one page");
		pager.bytes_remove(ino);

		assert!(
			pager.bytes_write(ino, 0, &payload).is_ok(),
			"second write should reuse freed page instead of failing max_pages"
		);
		pager.check_invariants();
	}

	#[test]
	fn dir_entries_clear_reuses_freed_pages() {
		let mut pager = Pager::new(1);
		let inode = INodeNo(48);

		let mut exhausted = false;
		for i in 0..1000u64 {
			let mut name = OsString::from_vec(vec![b'c'; 128]);
			name.push(i.to_string());
			if pager.dir_entries_insert(inode, name, INodeNo(1000 + i)).is_err() {
				exhausted = true;
				break;
			}
		}
		assert!(exhausted, "single directory page should eventually fill");

		pager.dir_entries_clear(inode);
		assert!(
			pager
				.dir_entries_insert(inode, OsString::from("fresh"), INodeNo(9999))
				.is_ok(),
			"insert after clear should reuse page capacity"
		);
		pager.check_invariants();
	}

	#[test]
	fn dir_entries_replace_does_not_consume_store_space() {
		let mut pager = Pager::new(1);
		let inode = INodeNo(49);
		let name = OsString::from("stable");

		pager
			.dir_entries_insert(inode, name.clone(), INodeNo(1))
			.expect("initial insert should succeed");
		for i in 0..10_000u64 {
			pager
				.dir_entries_insert(inode, name.clone(), INodeNo(2 + i))
				.expect("replacement should not consume additional store slots");
		}
		assert_eq!(pager.page_count(), 1);
		assert_eq!(pager.dir_entries_get(inode, name.as_os_str()), Some(INodeNo(10_001)));
		pager.check_invariants();
	}

	#[test]
	fn dir_entries_replace_on_full_page_with_larger_varint_fails_without_panicking() {
		let inode = INodeNo(64);
		let mut pager = Pager::new(1);
		let mut target = OsString::from("target");
		let original_child = INodeNo(1);

		let mut found_failure_case = false;
		for len in (1..DIRENTRIES_CAPACITY).rev() {
			let candidate = OsString::from_vec(vec![b'x'; len]);
			let mut candidate_pager = Pager::new(1);
			if candidate_pager
				.dir_entries_insert(inode, candidate.clone(), original_child)
				.is_err()
			{
				continue;
			}
			if candidate_pager
				.dir_entries_insert(inode, candidate.clone(), INodeNo(u64::MAX))
				.is_err()
			{
				pager = candidate_pager;
				target = candidate;
				found_failure_case = true;
				break;
			}
		}
		assert!(
			found_failure_case,
			"test setup should find an entry size where varint growth no longer fits"
		);

		assert!(
			pager
				.dir_entries_insert(inode, target.clone(), INodeNo(u64::MAX))
				.is_err(),
			"replacing with larger varint should fail gracefully on full page"
		);
		assert_eq!(pager.dir_entries_get(inode, target.as_os_str()), Some(original_child));
		pager.check_invariants();
	}

	#[test]
	fn dir_entries_oversized_insert_does_not_leak_page() {
		let mut pager = Pager::new(1);
		let inode = INodeNo(62);
		let too_large_name = OsString::from_vec(vec![b'q'; DIRENTRIES_CAPACITY]);

		assert!(pager.dir_entries_insert(inode, too_large_name, INodeNo(1)).is_err());
		assert!(
			pager
				.dir_entries_insert(inode, OsString::from("ok"), INodeNo(2))
				.is_ok(),
			"failed oversized insert must release the allocated directory page"
		);
		pager.check_invariants();
	}

	#[test]
	fn dir_entries_remove_reclaims_store_capacity_under_churn() {
		let mut pager = Pager::new(1);
		let inode = INodeNo(63);
		pager
			.dir_entries_insert(inode, OsString::from("."), inode)
			.expect("seed entry should succeed");
		pager
			.dir_entries_insert(inode, OsString::from(".."), INodeNo(1))
			.expect("seed entry should succeed");

		for i in 0..10_000u64 {
			let name = OsString::from(format!("tmp_{i}"));
			pager
				.dir_entries_insert(inode, name.clone(), INodeNo(1_000 + i))
				.expect("insert/remove churn should not exhaust a single page");
			let removed = pager.dir_entries_remove(inode, name.as_os_str());
			assert_eq!(removed, Some(INodeNo(1_000 + i)));
		}
		pager.check_invariants();
	}

	#[test]
	fn codec_roundtrip_preserves_pages_and_lookups() {
		let mut pager = Pager::new(16);
		let dir_ino = INodeNo(70);
		let file_ino = INodeNo(71);
		let mut dir_inode = inode();
		dir_inode.kind = FileType::Directory;
		dir_inode.nlink = 2;
		let mut file_inode = inode();
		file_inode.size = (DATA_PAGE_CAPACITY + 9) as u64;

		pager
			.inodes_insert(dir_ino, dir_inode)
			.expect("dir inode insert should succeed");
		pager
			.inodes_insert(file_ino, file_inode)
			.expect("file inode insert should succeed");
		pager
			.dir_entries_insert(dir_ino, OsString::from("file.bin"), file_ino)
			.expect("directory entry insert should succeed");
		let mut payload = vec![0x2A; DATA_PAGE_CAPACITY + 9];
		payload[0] = 0x11;
		payload[DATA_PAGE_CAPACITY] = 0x22;
		pager
			.bytes_write(file_ino, 0, &payload)
			.expect("bytes write should succeed");

		let encoded = pager.encode_blocks().expect("encoding should succeed");
		let decoded_pages = DecodedPages::decode_blocks(&encoded).expect("page decoding should succeed");
		let decoded = Pager::from_decoded_pages(decoded_pages, 16).expect("decoding should succeed");

		assert_eq!(decoded.inodes_len(), 2);
		assert_eq!(decoded.inode_get(dir_ino), Some(&dir_inode));
		assert_eq!(decoded.inode_get(file_ino), Some(&file_inode));
		assert_eq!(decoded.dir_entries_get(dir_ino, OsStr::new("file.bin")), Some(file_ino));
		assert_eq!(decoded.bytes_len(file_ino), payload.len());
		assert_eq!(decoded.bytes_read(file_ino, 0, payload.len() + 16), payload);
		pager.check_invariants();
		decoded.check_invariants();
	}

	#[test]
	fn decoded_pages_are_validated_during_pager_construction() {
		let mut pager = Pager::new(16);
		let ino = INodeNo(172);
		pager
			.bytes_write(ino, 0, b"decoded-pages")
			.expect("bytes write should succeed");

		let encoded = pager.encode_blocks().expect("encoding should succeed");
		let decoded_pages = DecodedPages::decode_blocks(&encoded).expect("page decoding should succeed");
		let decoded = Pager::from_decoded_pages(decoded_pages, 16).expect("pager construction should succeed");

		assert_eq!(decoded.bytes_read(ino, 0, 32), b"decoded-pages");
		decoded.check_invariants();
	}

	#[test]
	fn encode_blocks_by_id_matches_encode_blocks_with_ids() {
		let mut pager = Pager::new(16);
		let ino = INodeNo(170);
		let payload = vec![0x5A; DATA_PAGE_CAPACITY + 3];
		pager.bytes_write(ino, 0, &payload).expect("bytes write should succeed");

		let with_ids = pager
			.encode_blocks_with_ids()
			.expect("encoding with page ids should succeed");
		let by_id = pager
			.encode_blocks_by_id()
			.expect("encoding map by page id should succeed");

		assert_eq!(by_id.len(), with_ids.len());
		for (page_id, block) in with_ids {
			assert_eq!(by_id.get(&page_id), Some(&block));
		}
	}

	#[test]
	fn codec_roundtrip_does_not_resurrect_released_dir_entry_pages() {
		let mut pager = Pager::new(1);
		let first_inode = INodeNo(200);
		let second_inode = INodeNo(201);

		pager
			.dir_entries_insert(first_inode, OsString::from("tmp"), second_inode)
			.expect("first insert should allocate a dir entries page");
		assert_eq!(
			pager.dir_entries_remove(first_inode, OsStr::new("tmp")),
			Some(second_inode)
		);
		assert_eq!(pager.dir_entries_get_dir(first_inode), None);

		let encoded = pager.encode_blocks().expect("encoding should succeed");
		let decoded_pages = DecodedPages::decode_blocks(&encoded).expect("page decoding should succeed");
		let mut decoded = Pager::from_decoded_pages(decoded_pages, 1).expect("decoding should succeed");
		assert_eq!(decoded.dir_entries_get_dir(first_inode), None);

		decoded
			.dir_entries_insert(second_inode, OsString::from("fresh"), first_inode)
			.expect("insert after roundtrip should not hit ENOSPC");
		assert_eq!(
			decoded.dir_entries_get(second_inode, OsStr::new("fresh")),
			Some(first_inode)
		);
		pager.check_invariants();
		decoded.check_invariants();
	}

	#[test]
	fn codec_decode_rejects_crc_mismatch() {
		let mut pager = Pager::new(8);
		let ino = INodeNo(80);
		pager.bytes_write(ino, 0, b"crc-check").expect("write should succeed");
		let mut encoded = pager.encode_blocks().expect("encoding should succeed");
		assert!(!encoded.is_empty(), "encoding should emit at least one block");
		pager.check_invariants();

		encoded[0][HEADER_SIZE] ^= 0x01;
		let decoded_pages = DecodedPages::decode_blocks(&encoded);
		match decoded_pages.and_then(|pages| Pager::from_decoded_pages(pages, 8)) {
			Err(PagerCodecError::CrcMismatch { .. }) => {}
			Err(other) => panic!("expected CRC mismatch, got {other:?}"),
			Ok(_) => panic!("decode must fail"),
		}
	}

	#[test]
	fn codec_decode_rejects_inodes_payload_shorter_than_wire_header() {
		let page_id = PageId(1);
		let payload = [];

		match Pager::decode_inodes_page(page_id, payload.len(), &payload) {
			Err(PagerCodecError::MalformedInodesPayload) => {}
			Err(other) => panic!("expected malformed inodes payload, got {other:?}"),
			Ok(_) => panic!("decode must fail"),
		}
	}

	#[test]
	fn codec_decode_rejects_inodes_payload_with_mismatched_count() {
		let page_id = PageId(2);
		let payload = InodesPageWireHeader { count: 1 }.as_bytes().to_vec();

		match Pager::decode_inodes_page(page_id, payload.len(), &payload) {
			Err(PagerCodecError::InvalidPayloadLength {
				page_type: PageType::Inodes,
				payload_len,
				expected,
			}) => {
				assert_eq!(payload_len, payload.len());
				assert_eq!(expected, size_of::<InodesPageWireHeader>() + size_of::<InodeRaw>());
			}
			Err(other) => panic!("expected invalid payload length, got {other:?}"),
			Ok(_) => panic!("decode must fail"),
		}
	}

	#[test]
	fn codec_decode_rejects_dir_entries_block_without_owner_ino() {
		let mut pager = Pager::new(8);
		pager
			.dir_entries_insert(INodeNo(86), OsString::from("child"), INodeNo(87))
			.expect("insert should succeed");
		let mut encoded = pager.encode_blocks().expect("encoding should succeed");
		assert_eq!(encoded.len(), 1, "single dir page should encode into one block");

		let block = &mut encoded[0];
		let mut header = PageHeaderV1::try_read_from_bytes(&block[..HEADER_SIZE]).expect("header should parse");
		header.owner_ino = None;
		header.crc32 = Pager::compute_crc(&header, &block[HEADER_SIZE..HEADER_SIZE + header.payload_len as usize]);
		block[..HEADER_SIZE].copy_from_slice(header.as_bytes());

		match DecodedPages::decode_blocks(&encoded) {
			Err(PagerCodecError::MissingOwnerInHeader(PageType::DirEntries)) => {}
			Err(other) => panic!("expected missing-owner error, got {other:?}"),
			Ok(_) => panic!("decode must fail"),
		}
	}

	#[test]
	fn codec_decode_rejects_data_block_without_owner_ino() {
		let mut pager = Pager::new(8);
		pager
			.bytes_write(INodeNo(88), 0, b"owner-check")
			.expect("write should succeed");
		let mut encoded = pager.encode_blocks().expect("encoding should succeed");
		assert!(!encoded.is_empty(), "encoding should emit at least one block");

		let block = &mut encoded[0];
		let mut header = PageHeaderV1::try_read_from_bytes(&block[..HEADER_SIZE]).expect("header should parse");
		header.owner_ino = None;
		header.crc32 = Pager::compute_crc(&header, &block[HEADER_SIZE..HEADER_SIZE + header.payload_len as usize]);
		block[..HEADER_SIZE].copy_from_slice(header.as_bytes());

		match DecodedPages::decode_blocks(&encoded) {
			Err(PagerCodecError::MissingOwnerInHeader(PageType::DataBytes)) => {}
			Err(other) => panic!("expected missing-owner error, got {other:?}"),
			Ok(_) => panic!("decode must fail"),
		}
	}

	#[test]
	fn codec_decode_rejects_non_contiguous_data_page_numbers() {
		let mut pager = Pager::new(8);
		let ino = INodeNo(81);
		let payload = vec![0x44; DATA_PAGE_CAPACITY + 1];
		pager.bytes_write(ino, 0, &payload).expect("write should succeed");
		let mut encoded = pager.encode_blocks().expect("encoding should succeed");
		assert!(encoded.len() >= 2, "payload must produce at least two blocks");
		pager.check_invariants();

		let second_block = &mut encoded[1];
		let mut header = PageHeaderV1::try_read_from_bytes(&second_block[..HEADER_SIZE]).expect("header should parse");
		header.file_page_no = NonZeroU32::new(2);
		header.crc32 = Pager::compute_crc(
			&header,
			&second_block[HEADER_SIZE..HEADER_SIZE + header.payload_len as usize],
		);
		second_block[..HEADER_SIZE].copy_from_slice(header.as_bytes());

		let decoded_pages = DecodedPages::decode_blocks(&encoded);
		match decoded_pages.and_then(|pages| Pager::from_decoded_pages(pages, 8)) {
			Err(PagerCodecError::NonContiguousDataPages { .. }) => {}
			Err(other) => panic!("expected non-contiguous error, got {other:?}"),
			Ok(_) => panic!("decode must fail"),
		}
	}

	#[test]
	fn codec_decode_rejects_max_page_id() {
		let mut pager = Pager::new(8);
		let ino = INodeNo(82);
		pager.bytes_write(ino, 0, b"max-page-id").expect("write should succeed");
		let mut encoded = pager.encode_blocks().expect("encoding should succeed");
		assert!(!encoded.is_empty(), "encoding should emit at least one block");
		pager.check_invariants();

		let first_block = &mut encoded[0];
		let mut header = PageHeaderV1::try_read_from_bytes(&first_block[..HEADER_SIZE]).expect("header should parse");
		header.page_id = PageId(u32::MAX);
		header.crc32 = Pager::compute_crc(
			&header,
			&first_block[HEADER_SIZE..HEADER_SIZE + header.payload_len as usize],
		);
		first_block[..HEADER_SIZE].copy_from_slice(header.as_bytes());

		let decoded_pages = DecodedPages::decode_blocks(&encoded);
		match decoded_pages.and_then(|pages| Pager::from_decoded_pages(pages, 8)) {
			Err(PagerCodecError::PageIdSpaceExhausted) => {}
			Err(other) => panic!("expected page-id exhaustion error, got {other:?}"),
			Ok(_) => panic!("decode must fail"),
		}
	}

	#[test]
	fn codec_roundtrip_followed_by_allocation_keeps_page_ids_unique() {
		let mut pager = Pager::new(16);
		let data_ino_a = INodeNo(90);
		let data_ino_b = INodeNo(91);
		let dir_ino = INodeNo(92);

		let payload = vec![0xAB; DATA_PAGE_CAPACITY + 1];
		pager
			.bytes_write(data_ino_a, 0, &payload)
			.expect("initial write should allocate two data pages");
		pager.bytes_remove(data_ino_a);
		pager
			.bytes_write(data_ino_b, 0, &[0xCD])
			.expect("single-byte write should reuse one freed page");

		let encoded = pager.encode_blocks().expect("encoding should succeed");
		let decoded_pages = DecodedPages::decode_blocks(&encoded).expect("page decoding should succeed");
		let mut pager = Pager::from_decoded_pages(decoded_pages, 16).expect("decoding should succeed");
		pager.check_invariants();

		// This allocation used to collide with an existing page_id after roundtrip.
		pager
			.dir_entries_insert(dir_ino, OsString::from("entry"), data_ino_b)
			.expect("directory insert should allocate a fresh page id");

		let encoded = pager.encode_blocks().expect("encoding after allocation should succeed");
		let decoded_pages = DecodedPages::decode_blocks(&encoded).expect("page decoding should succeed");
		let decoded = Pager::from_decoded_pages(decoded_pages, 16).expect("decoding after allocation should succeed");
		assert_eq!(decoded.dir_entries_get(dir_ino, OsStr::new("entry")), Some(data_ino_b));
		pager.check_invariants();
		decoded.check_invariants();
	}
}
