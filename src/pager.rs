use crate::{
	filesystem::BLOCK_SIZE,
	inode::{Inode, InodeRaw},
	store::{Error as StoreError, StoreBlock},
};
use fuser::INodeNo;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::mem::size_of;
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes};

#[derive(TryFromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(u32)]
pub enum PAGETYPE {
	Inodes,
	DirEntries,
	DataBytes,
}

#[derive(TryFromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct PageHeader {
	page_id: u32,
	header_type: PAGETYPE,
}

// Ensure entries.len() * size_of::<InodeRaw>() - size_of::<PageHeader>() <= BLOCK_SIZE
// Persists to header + flattened data as bytes
pub struct InodesPage {
	page_id: u32,
	entries: HashMap<INodeNo, Inode>,
	free_entries: usize,
}

const INODES_PAGE_CAPACITY: usize = (BLOCK_SIZE - size_of::<PageHeader>()) / size_of::<InodeRaw>();
const DIRENTRIES_CAPACITY: usize = BLOCK_SIZE - size_of::<PageHeader>();

// Persists to header + entries.data
pub struct DirEntriesPage {
	page_id: u32,
	inode: INodeNo,
	indices: BTreeMap<OsString, (u32, INodeNo)>,
	entries: StoreBlock<(OsString, INodeNo), DIRENTRIES_CAPACITY>,
}

const DATA_PAGE_CAPACITY: usize = BLOCK_SIZE - size_of::<PageHeader>();

// Persists to header + data
pub struct DataBytesPage {
	page_id: u32,
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

	max_pages: usize,
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
			max_pages,
		}
	}

	pub fn page_count(&self) -> usize {
		self.inodes_pages.len() + self.dir_entries_pages.len() + self.bytes_pages.len()
	}

	pub fn inodes_len(&self) -> usize {
		self.inodes.len()
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
				page_id: self.page_count() as u32,
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
		if let Some(page_indices) = self.dir_entries.get(&inode).cloned() {
			for page_index in page_indices.iter().rev() {
				let page = &mut self.dir_entries_pages[page_index.0];
				debug_assert_eq!(page.inode, inode);
				if let Some((_, existing_child)) = page.indices.get_mut(name.as_os_str()) {
					*existing_child = child;
					self.check_invariants();
					return Ok(());
				}
			}

			for page_index in page_indices {
				let page = &mut self.dir_entries_pages[page_index.0];
				debug_assert_eq!(page.inode, inode);
				match page.entries.try_store((name.clone(), child)) {
					Ok(slot) => {
						page.indices.insert(name, (slot, child));
						self.check_invariants();
						return Ok(());
					}
					Err(StoreError::NoSpace) => continue,
					Err(_) => return Err(()),
				}
			}
		}

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
		self.check_invariants();
		Ok(())
	}

	pub fn dir_entries_remove(&mut self, inode: INodeNo, name: &OsStr) -> Option<INodeNo> {
		let page_indices = self.dir_entries.get(&inode)?.clone();
		for page_index in page_indices.into_iter().rev() {
			let page = self.dir_entries_pages.get_mut(page_index.0)?;
			debug_assert_eq!(page.inode, inode);
			if let Some((_, child)) = page.indices.remove(name) {
				Self::compact_dir_entries_page(page);
				self.prune_empty_dir_pages(inode);
				self.check_invariants();
				return Some(child);
			}
		}
		None
	}

	pub fn dir_entries_clear(&mut self, inode: INodeNo) {
		let Some(page_indices) = self.dir_entries.remove(&inode) else {
			return;
		};
		for page_index in page_indices {
			self.release_dir_entries_page(page_index);
		}
		self.check_invariants();
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

		let page_id = self.page_count() as u32;
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

	fn compact_dir_entries_page(page: &mut DirEntriesPage) {
		let mut rebuilt_entries = StoreBlock::new(page.page_id);
		let mut rebuilt_indices = BTreeMap::new();
		for (name, (_, child_ino)) in &page.indices {
			let slot = rebuilt_entries
				.try_store((name.clone(), *child_ino))
				.expect("compacting an existing directory page must preserve capacity");
			rebuilt_indices.insert(name.clone(), (slot, *child_ino));
		}
		page.entries = rebuilt_entries;
		page.indices = rebuilt_indices;
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

		self.check_invariants();
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
		self.check_invariants();
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

		self.check_invariants();
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

		let page_id = self.page_count() as u32;
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

	fn check_invariants(&self) {
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
					let _ = (stored_child, child_ino);
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
	}

	#[test]
	fn dir_entries_insert_lookup_replace_remove() {
		let mut pager = Pager::new(8);
		let name = OsString::from("child");
		let parent = INodeNo(10);

		pager
			.dir_entries_insert(parent, name.clone(), INodeNo(11))
			.expect("initial insert should succeed");
		assert!(pager.dir_entries_contains(parent, &name));
		assert_eq!(pager.dir_entries_get(parent, &name), Some(INodeNo(11)));

		pager
			.dir_entries_insert(parent, name.clone(), INodeNo(12))
			.expect("replace should succeed");
		assert_eq!(pager.dir_entries_get(parent, &name), Some(INodeNo(12)));

		let removed = pager.dir_entries_remove(parent, &name);
		assert_eq!(removed, Some(INodeNo(12)));
		assert_eq!(pager.dir_entries_get(parent, &name), None);
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
	}

	#[test]
	fn bytes_write_read_single_page() {
		let mut pager = Pager::new(8);
		let ino = INodeNo(40);

		pager.bytes_write(ino, 0, b"hello").expect("write should succeed");
		assert_eq!(pager.bytes_len(ino), 5);
		assert_eq!(pager.bytes_read(ino, 0, 5), b"hello");
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
	}

	#[test]
	fn bytes_sparse_write_zero_fills_gap() {
		let mut pager = Pager::new(8);
		let ino = INodeNo(42);

		pager.bytes_write(ino, 4, b"xy").expect("sparse write should succeed");
		assert_eq!(pager.bytes_len(ino), 6);
		assert_eq!(pager.bytes_read(ino, 0, 6), vec![0, 0, 0, 0, b'x', b'y']);
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
	}

	#[test]
	fn bytes_fail_when_out_of_pages() {
		let mut pager = Pager::new(1);
		let ino = INodeNo(46);
		let data = vec![0x55; DATA_PAGE_CAPACITY + 1];
		assert!(pager.bytes_write(ino, 0, &data).is_err());
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
	}
}
