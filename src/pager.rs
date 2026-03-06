use crate::{
	filesystem::BLOCK_SIZE,
	inode::{Inode, InodeRaw},
	store::StoreBlock,
};
use fuser::INodeNo;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsString;
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
}

#[cfg(test)]
mod tests {
	use super::*;
	use fuser::FileType;
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
}
