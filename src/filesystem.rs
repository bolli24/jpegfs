use std::{
	collections::{HashMap, HashSet},
	ffi::{OsStr, OsString},
	io,
	os::unix::ffi::OsStrExt,
	path::Path,
	sync::Arc,
	time::{Duration, SystemTime},
};

use crate::inode::Inode;
use crate::pager::Pager;
use fuser::*;
use log::{info, warn};
use parking_lot::RwLock;

pub const BLOCK_SIZE: usize = 4096;
const POSIX_BLOCK: u64 = 512;

pub const MAX_INODES: usize = 4096;
pub const MAX_NAME_LEN: usize = 64;
pub const MAX_FILE_SIZE: usize = 4 * 1024 * 1024;
pub const TOTAL_BYTES_LIMIT: usize = 100 * 1024 * 1024;

macro_rules! invariant_or_eio {
	($opt:expr, $reply:expr, $($arg:tt)*) => {{
		match $opt {
			Some(value) => value,
			None => {
				if cfg!(test) {
					panic!($($arg)*);
				}
				warn!($($arg)*);
				$reply.error(Errno::EIO);
				return;
			}
		}
	}};
}

#[derive(Clone)]
pub struct FileSystem {
	pub state: Arc<RwLock<FileSystemState>>,
}

pub struct FileSystemState {
	pub pager: Pager,

	pub handles: HashMap<FileHandle, INodeNo>,
	next_fh: u64,

	// Allocation state
	next_ino: INodeNo,
	free_inos: Vec<INodeNo>,

	// Limits
	pub max_inodes: usize,
	pub max_name_len: usize,
	pub max_file_size: usize,
	pub total_bytes_limit: usize,

	used_bytes: u64,
	dirty: bool,
}

impl FileSystem {
	fn pager_max_pages(total_bytes_limit: usize, max_inodes: usize) -> usize {
		total_bytes_limit
			.div_ceil(BLOCK_SIZE)
			.saturating_add(max_inodes.saturating_mul(8))
			.max(1)
	}

	pub fn new() -> Self {
		Self::new_with_limits(Self::pager_max_pages(TOTAL_BYTES_LIMIT, MAX_INODES), TOTAL_BYTES_LIMIT)
			.expect("default file system limits must allow root inode and root directory entries")
	}

	pub fn new_with_limits(max_pages: usize, total_bytes_limit: usize) -> Result<Self, String> {
		let now = SystemTime::now();
		let root_ino = INodeNo(1);
		let root_uid = unsafe { libc::geteuid() };
		let root_gid = unsafe { libc::getegid() };

		let root_inode = Inode {
			kind: FileType::Directory,
			perm: 0o755,
			uid: root_uid,
			gid: root_gid,
			size: 0,
			nlink: 2,
			atime: now,
			mtime: now,
			ctime: now,
			crtime: now,
		};

		let mut pager = Pager::new(max_pages.max(1));
		pager
			.inodes_insert(root_ino, root_inode)
			.map_err(|()| "insufficient page capacity for root inode".to_string())?;
		pager
			.dir_entries_insert(root_ino, OsString::from("."), root_ino)
			.map_err(|()| "insufficient page capacity for root '.' entry".to_string())?;
		pager
			.dir_entries_insert(root_ino, OsString::from(".."), root_ino)
			.map_err(|()| "insufficient page capacity for root '..' entry".to_string())?;

		let state = FileSystemState {
			pager,
			handles: HashMap::new(),
			next_fh: 1,
			next_ino: INodeNo(root_ino.0 + 1),
			free_inos: Vec::new(),
			max_inodes: MAX_INODES,
			max_name_len: MAX_NAME_LEN,
			max_file_size: MAX_FILE_SIZE,
			total_bytes_limit,
			used_bytes: 0,
			dirty: false,
		};
		Ok(Self {
			state: Arc::new(RwLock::new(state)),
		})
	}

	pub fn from_pager(pager: Pager, total_bytes_limit: usize) -> Result<Self, String> {
		let inode_numbers: HashSet<INodeNo> = pager.inodes_snapshot().into_iter().map(|(ino, _)| ino).collect();
		let max_ino = inode_numbers.iter().map(|ino| ino.0).max().unwrap_or(1);
		let free_inos = (2..max_ino)
			.filter_map(|raw| {
				let ino = INodeNo(raw);
				(!inode_numbers.contains(&ino)).then_some(ino)
			})
			.rev()
			.collect();

		let state = FileSystemState {
			pager,
			handles: HashMap::new(),
			next_fh: 1,
			next_ino: INodeNo(max_ino.saturating_add(1)),
			free_inos,
			max_inodes: MAX_INODES,
			max_name_len: MAX_NAME_LEN,
			max_file_size: MAX_FILE_SIZE,
			total_bytes_limit,
			used_bytes: 0,
			dirty: false,
		};

		let used_bytes = state.recompute_used_bytes();
		if used_bytes > total_bytes_limit as u64 {
			return Err(format!(
				"persisted file data ({used_bytes} bytes) exceeds configured limit ({total_bytes_limit} bytes)"
			));
		}

		let mut state = state;
		state.used_bytes = used_bytes;

		state.check_invariants()?;
		Ok(Self {
			state: Arc::new(RwLock::new(state)),
		})
	}

	fn alloc_ino_with_count(state: &mut FileSystemState, current_inode_count: usize) -> Option<INodeNo> {
		if let Some(reused) = state.free_inos.pop() {
			return Some(reused);
		}

		if current_inode_count >= state.max_inodes {
			return None;
		}

		let new = state.next_ino;
		let incremented = state.next_ino.0.checked_add(1)?;
		state.next_ino = INodeNo(incremented);
		Some(new)
	}

	pub fn get_next(&self) -> Option<INodeNo> {
		let mut state = self.state.write();
		let inode_count = state.pager.inodes_len();
		Self::alloc_ino_with_count(&mut state, inode_count)
	}

	fn cleanup_unlinked_inode_if_releasable(state: &mut FileSystemState, ino: INodeNo) {
		let Some(inode) = state.pager.inode_get(ino) else {
			return;
		};
		if inode.nlink != 0 {
			return;
		}

		let has_open_handles = state.handles.values().any(|open_ino| *open_ino == ino);
		if has_open_handles {
			return;
		}

		let released = state.pager.bytes_len(ino) as u64;
		state.used_bytes = state.used_bytes.saturating_sub(released);
		state.pager.bytes_remove(ino);
		state.pager.inode_remove(ino);
		state.free_inos.push(ino);
	}

	fn blocks_for_bytes(bytes: u64) -> u64 {
		bytes.div_ceil(BLOCK_SIZE as u64)
	}

	fn statfs_data(state: &FileSystemState) -> StatfsData {
		let blocks = Self::blocks_for_bytes(state.total_bytes_limit as u64);
		let used_blocks = Self::blocks_for_bytes(state.used_bytes());
		let bfree = blocks.saturating_sub(used_blocks);
		let files = state.max_inodes as u64;
		let ffree = state.max_inodes.saturating_sub(state.pager.inodes_len()) as u64;
		let namelen = u32::try_from(state.max_name_len).unwrap_or(u32::MAX);

		StatfsData {
			blocks,
			bfree,
			bavail: bfree,
			files,
			ffree,
			bsize: BLOCK_SIZE as u32,
			namelen,
			frsize: BLOCK_SIZE as u32,
		}
	}
}

impl Default for FileSystem {
	fn default() -> Self {
		Self::new()
	}
}

impl Inode {
	pub fn to_file_attr(ino: INodeNo, inode: &Self) -> FileAttr {
		let blocks = inode.size.div_ceil(POSIX_BLOCK);
		FileAttr {
			ino,
			size: inode.size,
			blocks,
			atime: inode.atime,
			mtime: inode.mtime,
			ctime: inode.ctime,
			crtime: inode.crtime,
			kind: inode.kind,
			perm: inode.perm,
			nlink: inode.nlink,
			uid: inode.uid,
			gid: inode.gid,
			rdev: 0,
			blksize: BLOCK_SIZE as u32,
			flags: 0,
		}
	}
}

const ONE_SEC: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatfsData {
	pub blocks: u64,
	pub bfree: u64,
	pub bavail: u64,
	pub files: u64,
	pub ffree: u64,
	pub bsize: u32,
	pub namelen: u32,
	pub frsize: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsDashboardStats {
	pub total_blocks: usize,
	pub used_blocks: usize,
	pub free_blocks: usize,
	pub inode_blocks: usize,
	pub dir_entry_blocks: usize,
	pub data_blocks: usize,
	pub file_count: usize,
	pub directory_count: usize,
	pub open_handles: usize,
}

pub type FsOpResult<T> = Result<T, Errno>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReaddirEntry {
	pub ino: INodeNo,
	pub kind: FileType,
	pub name: OsString,
}

impl FileSystemState {
	pub fn dashboard_stats(&self) -> FsDashboardStats {
		let counts = self.pager.block_counts();
		let total_blocks = self.pager.max_pages();
		let mut file_count = 0usize;
		let mut directory_count = 0usize;
		for (_, inode) in self.pager.inodes_snapshot() {
			match inode.kind {
				FileType::RegularFile => file_count += 1,
				FileType::Directory => directory_count += 1,
				_ => {}
			}
		}

		FsDashboardStats {
			total_blocks,
			used_blocks: counts.total(),
			free_blocks: total_blocks.saturating_sub(counts.total()),
			inode_blocks: counts.inodes,
			dir_entry_blocks: counts.dir_entries,
			data_blocks: counts.data_bytes,
			file_count,
			directory_count,
			open_handles: self.handles.len(),
		}
	}

	pub fn used_bytes(&self) -> u64 {
		self.used_bytes
	}

	pub fn is_dirty(&self) -> bool {
		self.dirty
	}

	fn mark_dirty(&mut self) {
		self.dirty = true;
	}

	pub fn recompute_used_bytes(&self) -> u64 {
		self.pager
			.inodes_snapshot()
			.into_iter()
			.filter(|(_, inode)| inode.kind == FileType::RegularFile)
			.map(|(ino, _)| self.pager.bytes_len(ino) as u64)
			.sum()
	}

	pub fn inode_numbers(&self) -> Vec<INodeNo> {
		self.pager.inodes_snapshot().into_iter().map(|(ino, _)| ino).collect()
	}

	pub fn handle_ids(&self) -> Vec<FileHandle> {
		self.handles.keys().copied().collect()
	}

	fn ensure_name_len(&self, name: &OsStr) -> FsOpResult<()> {
		if name.as_bytes().len() > self.max_name_len {
			return Err(Errno::ENAMETOOLONG);
		}
		Ok(())
	}

	fn reject_dot_entries(name: &OsStr) -> FsOpResult<()> {
		if name == OsStr::new(".") || name == OsStr::new("..") {
			return Err(Errno::EINVAL);
		}
		Ok(())
	}

	fn ensure_parent_dir(&self, parent: INodeNo) -> FsOpResult<()> {
		let inode = self.inode_or_enoent(parent)?;
		if inode.kind != FileType::Directory {
			return Err(Errno::ENOTDIR);
		}
		if !self.pager.dir_entries_exists(parent) {
			return Err(Errno::EIO);
		}
		Ok(())
	}

	fn inode_or_enoent(&self, ino: INodeNo) -> FsOpResult<&Inode> {
		self.pager.inode_get(ino).ok_or(Errno::ENOENT)
	}

	fn ensure_regular_file_inode(&self, ino: INodeNo) -> FsOpResult<&Inode> {
		let inode = self.inode_or_enoent(ino)?;
		if inode.kind == FileType::Directory {
			return Err(Errno::EISDIR);
		}
		Ok(inode)
	}

	fn lookup_child_ino(&self, parent: INodeNo, name: &OsStr) -> FsOpResult<INodeNo> {
		self.ensure_parent_dir(parent)?;
		self.pager.dir_entries_get(parent, name).ok_or(Errno::ENOENT)
	}

	fn is_descendant_dir(&self, candidate: INodeNo, ancestor: INodeNo) -> FsOpResult<bool> {
		let mut cursor = candidate;
		let mut visited = HashSet::new();
		loop {
			if cursor == ancestor {
				return Ok(true);
			}
			if !visited.insert(cursor) {
				return Err(Errno::EIO);
			}
			if cursor == INodeNo(1) {
				return Ok(false);
			}

			let parent = self.pager.dir_entries_get(cursor, OsStr::new("..")).ok_or(Errno::EIO)?;
			cursor = parent;
		}
	}

	fn validate_file_handle(&self, ino: INodeNo, fh: FileHandle) -> FsOpResult<()> {
		let Some(handle_ino) = self.handles.get(&fh) else {
			return Err(Errno::EBADF);
		};
		if *handle_ino != ino {
			return Err(Errno::EBADF);
		}
		self.ensure_regular_file_inode(ino)?;
		Ok(())
	}

	fn alloc_file_handle_for(&mut self, ino: INodeNo) -> FsOpResult<FileHandle> {
		let file_handle = FileHandle(self.next_fh);
		let Some(next_fh) = self.next_fh.checked_add(1) else {
			return Err(Errno::ENFILE);
		};
		self.next_fh = next_fh;
		self.handles.insert(file_handle, ino);
		Ok(file_handle)
	}

	fn resize_file_len(&mut self, ino: INodeNo, new_len: usize) -> FsOpResult<()> {
		let old_len = self.pager.bytes_len(ino);
		if new_len > old_len {
			let growth = new_len - old_len;
			let Some(new_used_bytes) = self.used_bytes.checked_add(growth as u64) else {
				return Err(Errno::ENOSPC);
			};
			if new_used_bytes > self.total_bytes_limit as u64 {
				return Err(Errno::ENOSPC);
			}
			self.pager.bytes_truncate(ino, new_len).map_err(|()| Errno::ENOSPC)?;
			self.used_bytes = new_used_bytes;
		} else {
			self.pager.bytes_truncate(ino, new_len).map_err(|()| Errno::ENOSPC)?;
			self.used_bytes = self.used_bytes.saturating_sub((old_len - new_len) as u64);
		}

		let inode = self.pager.inode_get_mut(ino).ok_or(Errno::EIO)?;
		inode.size = new_len as u64;
		Ok(())
	}

	fn apply_dir_nlink_delta(&mut self, ino: INodeNo, delta: i32) -> FsOpResult<()> {
		if delta == 0 {
			return Ok(());
		}

		// Keep rename link accounting centralized and explicit for directory moves/replacements.
		let inode = self.pager.inode_get_mut(ino).ok_or(Errno::EIO)?;
		match delta {
			-1 => {
				if inode.nlink == 0 {
					return Err(Errno::EIO);
				}
				inode.nlink -= 1;
			}
			1 => {
				inode.nlink += 1;
			}
			_ => return Err(Errno::EIO),
		}
		Ok(())
	}

	pub fn op_getattr(&self, ino: INodeNo) -> FsOpResult<Inode> {
		self.inode_or_enoent(ino).copied()
	}

	pub fn op_mkdir(
		&mut self,
		parent: INodeNo,
		name: &OsStr,
		mode: u32,
		umask: u32,
		uid: u32,
		gid: u32,
	) -> FsOpResult<(INodeNo, Inode)> {
		self.ensure_name_len(name)?;
		self.ensure_parent_dir(parent)?;
		if self.pager.dir_entries_contains(parent, name) {
			return Err(Errno::EEXIST);
		}

		let inode_count = self.pager.inodes_len();
		let Some(new_ino) = FileSystem::alloc_ino_with_count(self, inode_count) else {
			return Err(Errno::ENOSPC);
		};

		let now = SystemTime::now();
		let new_inode = Inode {
			kind: FileType::Directory,
			perm: ((mode & 0o7777) & !umask) as u16,
			uid,
			gid,
			size: 0,
			nlink: 2,
			atime: now,
			mtime: now,
			ctime: now,
			crtime: now,
		};

		self.pager
			.inodes_insert(new_ino, new_inode)
			.map_err(|()| Errno::ENOSPC)?;
		if self
			.pager
			.dir_entries_insert(new_ino, OsString::from("."), new_ino)
			.is_err()
		{
			self.pager.inode_remove(new_ino);
			self.free_inos.push(new_ino);
			return Err(Errno::ENOSPC);
		}
		if self
			.pager
			.dir_entries_insert(new_ino, OsString::from(".."), parent)
			.is_err()
		{
			self.pager.dir_entries_clear(new_ino);
			self.pager.inode_remove(new_ino);
			self.free_inos.push(new_ino);
			return Err(Errno::ENOSPC);
		}
		if self.pager.dir_entries_insert(parent, name.to_owned(), new_ino).is_err() {
			self.pager.dir_entries_clear(new_ino);
			self.pager.inode_remove(new_ino);
			self.free_inos.push(new_ino);
			return Err(Errno::ENOSPC);
		}

		let parent_inode = self.pager.inode_get_mut(parent).ok_or(Errno::EIO)?;
		parent_inode.nlink += 1;
		parent_inode.mtime = now;
		parent_inode.ctime = now;
		self.mark_dirty();

		Ok((new_ino, new_inode))
	}

	pub fn op_unlink(&mut self, parent: INodeNo, name: &OsStr) -> FsOpResult<()> {
		Self::reject_dot_entries(name)?;
		let child_ino = self.lookup_child_ino(parent, name)?;

		let child_inode = self.pager.inode_get(child_ino).ok_or(Errno::EIO)?;
		if child_inode.kind == FileType::Directory {
			return Err(Errno::EISDIR);
		}

		let now = SystemTime::now();
		if self.pager.dir_entries_remove(parent, name).is_none() {
			return Err(Errno::EIO);
		}

		let remove_inode = {
			let child_inode = self.pager.inode_get_mut(child_ino).ok_or(Errno::EIO)?;
			if child_inode.nlink == 0 {
				return Err(Errno::EIO);
			}
			child_inode.nlink -= 1;
			child_inode.ctime = now;
			child_inode.nlink == 0
		};
		if remove_inode {
			FileSystem::cleanup_unlinked_inode_if_releasable(self, child_ino);
		}

		let parent_inode = self.pager.inode_get_mut(parent).ok_or(Errno::EIO)?;
		parent_inode.mtime = now;
		parent_inode.ctime = now;
		self.mark_dirty();
		Ok(())
	}

	pub fn op_rmdir(&mut self, parent: INodeNo, name: &OsStr) -> FsOpResult<()> {
		Self::reject_dot_entries(name)?;
		let child_ino = self.lookup_child_ino(parent, name)?;

		if child_ino == INodeNo(1) {
			return Err(Errno::EBUSY);
		}

		let child_inode = self.pager.inode_get(child_ino).ok_or(Errno::EIO)?;
		if child_inode.kind != FileType::Directory {
			return Err(Errno::ENOTDIR);
		}

		let child_dir = self.pager.dir_entries_get_dir(child_ino).ok_or(Errno::EIO)?;
		if child_dir.len() > 2 {
			return Err(Errno::ENOTEMPTY);
		}

		let now = SystemTime::now();
		if self.pager.dir_entries_remove(parent, name).is_none() {
			return Err(Errno::EIO);
		}
		self.pager.dir_entries_clear(child_ino);
		self.pager.inode_remove(child_ino).ok_or(Errno::EIO)?;

		let parent_inode = self.pager.inode_get_mut(parent).ok_or(Errno::EIO)?;
		if parent_inode.nlink == 0 {
			return Err(Errno::EIO);
		}
		parent_inode.nlink -= 1;
		parent_inode.mtime = now;
		parent_inode.ctime = now;
		self.free_inos.push(child_ino);
		self.mark_dirty();
		Ok(())
	}

	pub fn op_open(&mut self, ino: INodeNo) -> FsOpResult<FileHandle> {
		self.ensure_regular_file_inode(ino)?;
		self.alloc_file_handle_for(ino)
	}

	pub fn op_read(&mut self, ino: INodeNo, fh: FileHandle, offset: u64, size: u32) -> FsOpResult<Vec<u8>> {
		self.validate_file_handle(ino, fh)?;

		let start = usize::try_from(offset).unwrap_or(usize::MAX);
		let out = self.pager.bytes_read(ino, start, size as usize);

		let inode = self.pager.inode_get_mut(ino).ok_or(Errno::EIO)?;
		inode.atime = SystemTime::now();
		Ok(out)
	}

	pub fn op_write(&mut self, ino: INodeNo, fh: FileHandle, offset: u64, data: &[u8]) -> FsOpResult<u32> {
		self.validate_file_handle(ino, fh)?;

		let Ok(start) = usize::try_from(offset) else {
			return Err(Errno::EFBIG);
		};
		let Some(end) = start.checked_add(data.len()) else {
			return Err(Errno::EFBIG);
		};
		if end > self.max_file_size {
			return Err(Errno::EFBIG);
		}

		let current_len = self.pager.bytes_len(ino);
		if end > current_len {
			self.resize_file_len(ino, end)?;
		}
		self.pager.bytes_write(ino, start, data).map_err(|()| Errno::ENOSPC)?;

		let now = SystemTime::now();
		let inode = self.pager.inode_get_mut(ino).ok_or(Errno::EIO)?;
		inode.mtime = now;
		inode.ctime = now;
		self.mark_dirty();

		Ok(data.len() as u32)
	}

	pub fn op_release(&mut self, fh: FileHandle) {
		if let Some(ino) = self.handles.remove(&fh) {
			FileSystem::cleanup_unlinked_inode_if_releasable(self, ino);
		}
	}

	pub fn op_readdir(&self, ino: INodeNo, offset: u64) -> FsOpResult<Vec<ReaddirEntry>> {
		let inode = self.inode_or_enoent(ino)?;
		if inode.kind != FileType::Directory {
			return Err(Errno::ENOTDIR);
		}
		let Some(dir) = self.pager.dir_entries_get_dir(ino) else {
			return Err(Errno::EIO);
		};

		let mut entries = Vec::new();
		for (name, entry_ino) in dir.iter().skip(offset as usize) {
			let inode = self.pager.inode_get(*entry_ino).ok_or(Errno::EIO)?;
			entries.push(ReaddirEntry {
				ino: *entry_ino,
				kind: inode.kind,
				name: name.clone(),
			});
		}
		Ok(entries)
	}

	pub fn op_statfs(&self) -> StatfsData {
		FileSystem::statfs_data(self)
	}

	pub fn op_create(
		&mut self,
		parent: INodeNo,
		name: &OsStr,
		mode: u32,
		umask: u32,
		uid: u32,
		gid: u32,
	) -> FsOpResult<(INodeNo, Inode, FileHandle)> {
		self.ensure_name_len(name)?;
		self.ensure_parent_dir(parent)?;
		if self.pager.dir_entries_contains(parent, name) {
			return Err(Errno::EEXIST);
		}

		let inode_count = self.pager.inodes_len();
		let Some(new_ino) = FileSystem::alloc_ino_with_count(self, inode_count) else {
			return Err(Errno::ENOSPC);
		};

		let now = SystemTime::now();
		let new_inode = Inode {
			kind: FileType::RegularFile,
			perm: ((mode & 0o7777) & !umask) as u16,
			uid,
			gid,
			size: 0,
			nlink: 1,
			atime: now,
			mtime: now,
			ctime: now,
			crtime: now,
		};

		self.pager
			.inodes_insert(new_ino, new_inode)
			.map_err(|()| Errno::ENOSPC)?;
		if self.pager.dir_entries_insert(parent, name.to_owned(), new_ino).is_err() {
			self.pager.inode_remove(new_ino);
			self.free_inos.push(new_ino);
			return Err(Errno::ENOSPC);
		}

		let file_handle = match self.alloc_file_handle_for(new_ino) {
			Ok(file_handle) => file_handle,
			Err(err) => {
				self.pager.dir_entries_remove(parent, name);
				self.pager.inode_remove(new_ino);
				self.free_inos.push(new_ino);
				return Err(err);
			}
		};

		let parent_inode = self.pager.inode_get_mut(parent).ok_or(Errno::EIO)?;
		parent_inode.mtime = now;
		parent_inode.ctime = now;
		self.mark_dirty();

		Ok((new_ino, new_inode, file_handle))
	}

	pub fn op_setattr_size(&mut self, ino: INodeNo, size: u64) -> FsOpResult<Inode> {
		let now = SystemTime::now();
		let max_file_size = self.max_file_size;
		self.ensure_regular_file_inode(ino)?;
		if size as usize > max_file_size {
			return Err(Errno::EFBIG);
		}

		self.resize_file_len(ino, size as usize)?;
		let updated = {
			let inode = self.pager.inode_get_mut(ino).ok_or(Errno::EIO)?;
			inode.mtime = now;
			inode.ctime = now;
			*inode
		};
		self.mark_dirty();
		Ok(updated)
	}

	pub fn op_rename(
		&mut self,
		parent: INodeNo,
		name: &OsStr,
		newparent: INodeNo,
		newname: &OsStr,
		flags: RenameFlags,
	) -> FsOpResult<()> {
		if !flags.is_empty() {
			return Err(Errno::EINVAL);
		}
		Self::reject_dot_entries(name)?;
		Self::reject_dot_entries(newname)?;
		self.ensure_name_len(newname)?;
		self.ensure_parent_dir(parent)?;
		self.ensure_parent_dir(newparent)?;

		if parent == newparent && name == newname {
			return Ok(());
		}

		let source_ino = self.lookup_child_ino(parent, name)?;
		if source_ino == INodeNo(1) {
			return Err(Errno::EBUSY);
		}
		let source_inode = self.pager.inode_get(source_ino).ok_or(Errno::EIO)?;
		let source_is_dir = source_inode.kind == FileType::Directory;

		if source_is_dir && parent != newparent && self.is_descendant_dir(newparent, source_ino)? {
			return Err(Errno::EINVAL);
		}

		let target_ino = self.pager.dir_entries_get(newparent, newname);
		if target_ino == Some(source_ino) {
			return Ok(());
		}

		let mut target_is_dir = false;
		if let Some(existing_ino) = target_ino {
			if existing_ino == INodeNo(1) {
				return Err(Errno::EBUSY);
			}
			let existing_inode = self.pager.inode_get(existing_ino).ok_or(Errno::EIO)?;
			target_is_dir = existing_inode.kind == FileType::Directory;

			if source_is_dir && !target_is_dir {
				return Err(Errno::ENOTDIR);
			}
			if !source_is_dir && target_is_dir {
				return Err(Errno::EISDIR);
			}
			if target_is_dir {
				let target_dir = self.pager.dir_entries_get_dir(existing_ino).ok_or(Errno::EIO)?;
				if target_dir.len() > 2 {
					return Err(Errno::ENOTEMPTY);
				}
			}
		}

		if self
			.pager
			.dir_entries_insert(newparent, newname.to_owned(), source_ino)
			.is_err()
		{
			return Err(Errno::ENOSPC);
		}

		let removed_source = self.pager.dir_entries_remove(parent, name);
		if removed_source != Some(source_ino) {
			// Best-effort rollback on unexpected state.
			let _ = self.pager.dir_entries_remove(newparent, newname);
			if let Some(existing_ino) = target_ino {
				let _ = self
					.pager
					.dir_entries_insert(newparent, newname.to_owned(), existing_ino);
			}
			let _ = self.pager.dir_entries_insert(parent, name.to_owned(), source_ino);
			return Err(Errno::EIO);
		}

		let now = SystemTime::now();
		let mut old_parent_dir_delta = 0i32;
		let mut new_parent_dir_delta = 0i32;

		if let Some(existing_ino) = target_ino {
			if target_is_dir {
				self.pager.dir_entries_clear(existing_ino);
				self.pager.inode_remove(existing_ino).ok_or(Errno::EIO)?;
				self.free_inos.push(existing_ino);
				// Replacing an existing directory removes one subdirectory edge from newparent.
				new_parent_dir_delta -= 1;
			} else {
				let remove_inode = {
					let target_inode = self.pager.inode_get_mut(existing_ino).ok_or(Errno::EIO)?;
					if target_inode.nlink == 0 {
						return Err(Errno::EIO);
					}
					target_inode.nlink -= 1;
					target_inode.ctime = now;
					target_inode.nlink == 0
				};
				if remove_inode {
					FileSystem::cleanup_unlinked_inode_if_releasable(self, existing_ino);
				}
			}
		}

		if source_is_dir && parent != newparent {
			if self
				.pager
				.dir_entries_insert(source_ino, OsString::from(".."), newparent)
				.is_err()
			{
				return Err(Errno::EIO);
			}
			old_parent_dir_delta -= 1;
			new_parent_dir_delta += 1;
		}

		self.apply_dir_nlink_delta(parent, old_parent_dir_delta)?;
		self.apply_dir_nlink_delta(newparent, new_parent_dir_delta)?;

		if parent == newparent {
			let parent_inode = self.pager.inode_get_mut(parent).ok_or(Errno::EIO)?;
			parent_inode.mtime = now;
			parent_inode.ctime = now;
		} else {
			let parent_inode = self.pager.inode_get_mut(parent).ok_or(Errno::EIO)?;
			parent_inode.mtime = now;
			parent_inode.ctime = now;

			let new_parent_inode = self.pager.inode_get_mut(newparent).ok_or(Errno::EIO)?;
			new_parent_inode.mtime = now;
			new_parent_inode.ctime = now;
		}

		let source_inode = self.pager.inode_get_mut(source_ino).ok_or(Errno::EIO)?;
		source_inode.ctime = now;
		self.mark_dirty();
		Ok(())
	}

	pub fn op_access(&self, ino: INodeNo, _mask: AccessFlags) -> FsOpResult<()> {
		self.inode_or_enoent(ino)?;
		Ok(())
	}

	pub fn check_invariants(&self) -> Result<(), String> {
		let root = INodeNo(1);
		let Some(root_inode) = self.pager.inode_get(root) else {
			return Err("missing root inode".to_string());
		};
		if root_inode.kind != FileType::Directory {
			return Err("root inode is not a directory".to_string());
		}

		let Some(root_dir) = self.pager.dir_entries_get_dir(root) else {
			return Err("missing root directory entries".to_string());
		};
		if root_dir.get(OsStr::new(".")) != Some(&root) || root_dir.get(OsStr::new("..")) != Some(&root) {
			return Err("root directory is missing '.' or '..'".to_string());
		}

		let mut computed_used_bytes = 0u64;
		let inode_snapshot = self.pager.inodes_snapshot();
		for (ino, inode) in &inode_snapshot {
			let bytes_len = self.pager.bytes_len(*ino) as u64;
			if inode.kind == FileType::RegularFile {
				if inode.size != bytes_len {
					return Err(format!("inode size mismatch for {ino:?}"));
				}
				computed_used_bytes = computed_used_bytes
					.checked_add(bytes_len)
					.ok_or_else(|| "used_bytes overflow while checking invariants".to_string())?;
			} else if bytes_len != 0 {
				return Err(format!("non-regular inode carries byte pages: {ino:?}"));
			}
		}

		let used_bytes = self.used_bytes();
		if used_bytes != computed_used_bytes {
			return Err(format!(
				"used_bytes mismatch: actual={used_bytes} computed={computed_used_bytes}",
			));
		}
		if used_bytes > self.total_bytes_limit as u64 {
			return Err("used_bytes exceeds total_bytes_limit".to_string());
		}
		if self.pager.inodes_len() > self.max_inodes {
			return Err("inode count exceeds max_inodes".to_string());
		}

		for ino in &self.free_inos {
			if self.pager.inodes_contains(*ino) {
				return Err(format!("free inode set overlaps live inodes: {ino:?}"));
			}
		}

		for (fh, ino) in &self.handles {
			let Some(inode) = self.pager.inode_get(*ino) else {
				return Err(format!("handle points to missing inode: fh={fh:?}, ino={ino:?}"));
			};
			if inode.kind != FileType::RegularFile {
				return Err(format!("handle points to non-regular inode: fh={fh:?}, ino={ino:?}"));
			}
		}

		for (dir_ino, dir_inode) in inode_snapshot
			.iter()
			.filter(|(_, inode)| inode.kind == FileType::Directory)
		{
			let Some(entries) = self.pager.dir_entries_get_dir(*dir_ino) else {
				return Err(format!("missing directory entries for {dir_ino:?}"));
			};

			let Some(parent_dot) = entries.get(OsStr::new(".")) else {
				return Err(format!("directory missing '.': {dir_ino:?}"));
			};
			if parent_dot != dir_ino {
				return Err(format!("'.' entry mismatch in directory: {dir_ino:?}"));
			}
			if !entries.contains_key(OsStr::new("..")) {
				return Err(format!("directory missing '..': {dir_ino:?}"));
			}

			let mut subdir_count = 0u32;
			for (name, child_ino) in entries {
				if name != OsStr::new(".") && name != OsStr::new("..") && name.as_bytes().len() > self.max_name_len {
					return Err(format!("entry name too long in {dir_ino:?}: {name:?}"));
				}
				let Some(child_inode) = self.pager.inode_get(child_ino) else {
					return Err(format!(
						"directory entry points to missing inode: parent={dir_ino:?}, name={name:?}, child={child_ino:?}"
					));
				};
				if name != OsStr::new(".") && name != OsStr::new("..") && child_inode.kind == FileType::Directory {
					subdir_count += 1;
				}
			}

			let expected_nlink = 2u32.saturating_add(subdir_count);
			if dir_inode.nlink != expected_nlink {
				return Err(format!(
					"directory nlink mismatch for {dir_ino:?}: actual={} expected={expected_nlink}",
					dir_inode.nlink
				));
			}
		}

		Ok(())
	}
}

impl Filesystem for FileSystem {
	fn init(&mut self, _req: &Request, _config: &mut KernelConfig) -> io::Result<()> {
		info!("init()");
		Ok(())
	}

	fn destroy(&mut self) {
		info!("destroy()");
	}

	// Get file in directory by name
	fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
		info!("lookup(parent={parent:?}, name={name:?})");
		let state = self.state.read();
		let file = match state.lookup_child_ino(parent, name) {
			Ok(file) => file,
			Err(err) => return reply.error(err),
		};

		let inode = invariant_or_eio!(
			state.pager.inode_get(file),
			reply,
			"directory entry points to missing inode: parent={parent:?}, name={name:?}, child={file:?}"
		);

		reply.entry(&ONE_SEC, &Inode::to_file_attr(file, inode), Generation(0));
	}

	fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
		info!("forget(ino={ino:?}, nlookup={nlookup})");
	}

	fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
		info!("getattr(ino={ino:?})");
		let state = self.state.read();
		match state.op_getattr(ino) {
			Ok(inode) => reply.attr(&ONE_SEC, &Inode::to_file_attr(ino, &inode)),
			Err(err) => reply.error(err),
		}
	}

	fn setattr(
		&self,
		_req: &Request,
		ino: INodeNo,
		mode: Option<u32>,
		uid: Option<u32>,
		gid: Option<u32>,
		size: Option<u64>,
		atime: Option<TimeOrNow>,
		mtime: Option<TimeOrNow>,
		ctime: Option<SystemTime>,
		_fh: Option<FileHandle>,
		crtime: Option<SystemTime>,
		chgtime: Option<SystemTime>,
		_bkuptime: Option<SystemTime>,
		_flags: Option<BsdFileFlags>,
		reply: ReplyAttr,
	) {
		info!("setattr(ino={ino:?})");
		let now = SystemTime::now();
		let mut state = self.state.write();
		let max_file_size = state.max_file_size;
		if !state.pager.inodes_contains(ino) {
			return reply.error(Errno::ENOENT);
		}

		let mut changed = false;

		if let Some(size) = size {
			let is_dir = state
				.pager
				.inode_get(ino)
				.map(|inode| inode.kind == FileType::Directory)
				.unwrap_or(false);
			if is_dir {
				return reply.error(Errno::EISDIR);
			}
			if size as usize > max_file_size {
				return reply.error(Errno::EFBIG);
			}

			if let Err(err) = state.resize_file_len(ino, size as usize) {
				return reply.error(err);
			}
			let inode = state.pager.inode_get_mut(ino).expect("validated inode must exist");
			inode.mtime = now;
			changed = true;
		}

		{
			let inode = state.pager.inode_get_mut(ino).expect("validated inode must exist");

			if let Some(mode) = mode {
				inode.perm = (mode & 0o7777) as u16;
				changed = true;
			}

			if let Some(uid) = uid {
				inode.uid = uid;
				changed = true;
			}

			if let Some(gid) = gid {
				inode.gid = gid;
				changed = true;
			}

			if let Some(atime) = atime {
				inode.atime = match atime {
					TimeOrNow::SpecificTime(t) => t,
					TimeOrNow::Now => now,
				};
				changed = true;
			}

			if let Some(mtime) = mtime {
				inode.mtime = match mtime {
					TimeOrNow::SpecificTime(t) => t,
					TimeOrNow::Now => now,
				};
				changed = true;
			}

			if let Some(ctime) = ctime {
				inode.ctime = ctime;
				changed = true;
			}

			if let Some(crtime) = crtime {
				inode.crtime = crtime;
				changed = true;
			}

			if let Some(chgtime) = chgtime {
				inode.ctime = chgtime;
				changed = true;
			}

			if changed {
				inode.ctime = now;
			}
		}
		if changed {
			state.mark_dirty();
		}

		let inode = state.pager.inode_get(ino).expect("validated inode must exist");
		reply.attr(&ONE_SEC, &Inode::to_file_attr(ino, inode));
	}

	fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
		info!("readlink(ino={ino:?})");
		warn!("[Not Implemented] readlink(ino: {ino:#x?})");
		reply.error(Errno::ENOSYS);
	}

	fn mknod(
		&self,
		_req: &Request,
		parent: INodeNo,
		name: &OsStr,
		mode: u32,
		umask: u32,
		rdev: u32,
		reply: ReplyEntry,
	) {
		info!("mknod(parent={parent:?}, name={name:?})");
		warn!(
			"[Not Implemented] mknod(parent: {parent:#x?}, name: {name:?}, \
            mode: {mode}, umask: {umask:#x?}, rdev: {rdev})"
		);
		reply.error(Errno::ENOSYS);
	}

	fn mkdir(&self, req: &Request, parent: INodeNo, name: &OsStr, mode: u32, umask: u32, reply: ReplyEntry) {
		info!("mkdir(parent={parent:?}, name={name:?}, mode={mode:#o}, umask={umask:#o})");
		let mut state = self.state.write();
		match state.op_mkdir(parent, name, mode, umask, req.uid(), req.gid()) {
			Ok((ino, inode)) => reply.entry(&ONE_SEC, &Inode::to_file_attr(ino, &inode), Generation(0)),
			Err(err) => reply.error(err),
		}
	}

	fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
		info!("unlink(parent={parent:?}, name={name:?})");
		let mut state = self.state.write();
		match state.op_unlink(parent, name) {
			Ok(()) => reply.ok(),
			Err(err) => reply.error(err),
		}
	}

	fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
		info!("rmdir(parent={parent:?}, name={name:?})");
		let mut state = self.state.write();
		match state.op_rmdir(parent, name) {
			Ok(()) => reply.ok(),
			Err(err) => reply.error(err),
		}
	}

	fn symlink(&self, _req: &Request, parent: INodeNo, link_name: &OsStr, target: &Path, reply: ReplyEntry) {
		info!("symlink(parent={parent:?}, link_name={link_name:?}, target={target:?})");
		warn!("[Not Implemented] symlink(parent: {parent:#x?}, link_name: {link_name:?}, target: {target:?})",);
		reply.error(Errno::EPERM);
	}

	fn rename(
		&self,
		_req: &Request,
		parent: INodeNo,
		name: &OsStr,
		newparent: INodeNo,
		newname: &OsStr,
		flags: RenameFlags,
		reply: ReplyEmpty,
	) {
		info!(
			"rename(parent={parent:?}, name={name:?}, newparent={newparent:?}, newname={newname:?}, flags={flags:?})"
		);
		let mut state = self.state.write();
		match state.op_rename(parent, name, newparent, newname, flags) {
			Ok(()) => reply.ok(),
			Err(err) => reply.error(err),
		}
	}

	fn link(&self, _req: &Request, ino: INodeNo, newparent: INodeNo, newname: &OsStr, reply: ReplyEntry) {
		info!("link(ino={ino:?}, newparent={newparent:?}, newname={newname:?})");
		warn!("[Not Implemented] link(ino: {ino:#x?}, newparent: {newparent:#x?}, newname: {newname:?})");
		reply.error(Errno::EPERM);
	}

	fn open(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
		info!("open(ino={ino:?})");
		let mut state = self.state.write();
		match state.op_open(ino) {
			Ok(file_handle) => reply.opened(file_handle, FopenFlags::empty()),
			Err(err) => reply.error(err),
		}
	}

	fn read(
		&self,
		_req: &Request,
		ino: INodeNo,
		fh: FileHandle,
		offset: u64,
		size: u32,
		_flags: OpenFlags,
		_lock_owner: Option<LockOwner>,
		reply: ReplyData,
	) {
		info!("read(ino={ino:?}, fh={fh}, offset={offset}, size={size})");
		let mut state = self.state.write();
		match state.op_read(ino, fh, offset, size) {
			Ok(out) => reply.data(&out),
			Err(err) => reply.error(err),
		}
	}

	fn write(
		&self,
		_req: &Request,
		ino: INodeNo,
		fh: FileHandle,
		offset: u64,
		data: &[u8],
		_write_flags: WriteFlags,
		_flags: OpenFlags,
		_lock_owner: Option<LockOwner>,
		reply: ReplyWrite,
	) {
		info!("write(ino={ino:?}, fh={fh}, offset={offset}, data_len={})", data.len());
		let mut state = self.state.write();
		match state.op_write(ino, fh, offset, data) {
			Ok(written) => reply.written(written),
			Err(err) => reply.error(err),
		}
	}

	fn flush(&self, _req: &Request, ino: INodeNo, fh: FileHandle, lock_owner: LockOwner, reply: ReplyEmpty) {
		info!("flush(ino={ino:?}, fh={fh}, lock_owner={lock_owner:?})");
		reply.ok();
	}

	fn release(
		&self,
		_req: &Request,
		_ino: INodeNo,
		fh: FileHandle,
		_flags: OpenFlags,
		_lock_owner: Option<LockOwner>,
		_flush: bool,
		reply: ReplyEmpty,
	) {
		info!("release(fh={fh})");
		let mut state = self.state.write();
		state.op_release(fh);
		reply.ok();
	}

	fn fsync(&self, _req: &Request, ino: INodeNo, fh: FileHandle, datasync: bool, reply: ReplyEmpty) {
		info!("fsync(ino={ino:?}, fh={fh}, datasync={datasync})");
		reply.ok();
	}

	fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
		info!("opendir(ino={ino:?})");
		let state = self.state.read();

		let Some(inode) = state.pager.inode_get(ino) else {
			return reply.error(Errno::ENOENT);
		};
		if inode.kind != FileType::Directory {
			return reply.error(Errno::ENOTDIR);
		}

		reply.opened(FileHandle(0), FopenFlags::empty());
	}

	fn readdir(&self, _req: &Request, ino: INodeNo, _fh: FileHandle, offset: u64, mut reply: ReplyDirectory) {
		info!("readdir(ino={ino:?}, offset={offset})");
		let state = self.state.read();
		match state.op_readdir(ino, offset) {
			Ok(entries) => {
				for (i, entry) in entries.iter().enumerate() {
					if reply.add(entry.ino, offset + i as u64 + 1, entry.kind, &entry.name) {
						break;
					}
				}
				reply.ok();
			}
			Err(err) => reply.error(err),
		}
	}

	fn readdirplus(&self, _req: &Request, ino: INodeNo, fh: FileHandle, offset: u64, reply: ReplyDirectoryPlus) {
		info!("readdirplus(ino={ino:?}, fh={fh}, offset={offset})");
		warn!("[Not Implemented] readdirplus(ino: {ino:#x?}, fh: {fh}, offset: {offset})");
		reply.error(Errno::ENOSYS);
	}

	fn releasedir(&self, _req: &Request, _ino: INodeNo, _fh: FileHandle, _flags: OpenFlags, reply: ReplyEmpty) {
		info!("releasedir()");
		reply.ok();
	}

	fn fsyncdir(&self, _req: &Request, ino: INodeNo, fh: FileHandle, datasync: bool, reply: ReplyEmpty) {
		info!("fsyncdir(ino={ino:?}, fh={fh}, datasync={datasync})");
		reply.ok();
	}

	fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
		info!("statfs()");
		let state = self.state.read();
		let statfs = state.op_statfs();
		reply.statfs(
			statfs.blocks,
			statfs.bfree,
			statfs.bavail,
			statfs.files,
			statfs.ffree,
			statfs.bsize,
			statfs.namelen,
			statfs.frsize,
		);
	}

	fn setxattr(
		&self,
		_req: &Request,
		ino: INodeNo,
		name: &OsStr,
		_value: &[u8],
		flags: i32,
		position: u32,
		reply: ReplyEmpty,
	) {
		info!("setxattr(ino={ino:?}, name={name:?}, flags={flags:#x}, position={position})");
		warn!(
			"[Not Implemented] setxattr(ino: {ino:#x?}, name: {name:?}, \
            flags: {flags:#x?}, position: {position})"
		);
		reply.error(Errno::ENOSYS);
	}

	fn getxattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, size: u32, reply: ReplyXattr) {
		info!("getxattr(ino={ino:?}, name={name:?}, size={size})");
		warn!("[Not Implemented] getxattr(ino: {ino:#x?}, name: {name:?}, size: {size})");
		reply.error(Errno::ENOSYS);
	}

	fn listxattr(&self, _req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
		info!("listxattr(ino={ino:?}, size={size})");
		warn!("[Not Implemented] listxattr(ino: {ino:#x?}, size: {size})");
		reply.error(Errno::ENOSYS);
	}

	fn removexattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, reply: ReplyEmpty) {
		info!("removexattr(ino={ino:?}, name={name:?})");
		warn!("[Not Implemented] removexattr(ino: {ino:#x?}, name: {name:?})");
		reply.error(Errno::ENOSYS);
	}

	fn access(&self, _req: &Request, ino: INodeNo, mask: AccessFlags, reply: ReplyEmpty) {
		info!("access(ino={ino:?}, mask={mask:?})");
		let state = self.state.read();
		match state.op_access(ino, mask) {
			Ok(()) => reply.ok(),
			Err(err) => reply.error(err),
		}
	}

	fn create(
		&self,
		req: &Request,
		parent: INodeNo,
		name: &OsStr,
		mode: u32,
		umask: u32,
		_flags: i32,
		reply: ReplyCreate,
	) {
		info!("create(parent={parent:?}, name={name:?}, mode={mode:#o}, umask={umask:#o})");
		let mut state = self.state.write();
		match state.op_create(parent, name, mode, umask, req.uid(), req.gid()) {
			Ok((ino, new_inode, file_handle)) => reply.created(
				&ONE_SEC,
				&Inode::to_file_attr(ino, &new_inode),
				Generation(0),
				file_handle,
				FopenFlags::empty(),
			),
			Err(err) => reply.error(err),
		}
	}

	fn getlk(
		&self,
		_req: &Request,
		ino: INodeNo,
		fh: FileHandle,
		lock_owner: LockOwner,
		start: u64,
		end: u64,
		typ: i32,
		pid: u32,
		reply: ReplyLock,
	) {
		info!("getlk(ino={ino:?}, fh={fh}, lock_owner={lock_owner:?}, start={start}, end={end}, typ={typ}, pid={pid})");
		warn!(
			"[Not Implemented] getlk(ino: {ino:#x?}, fh: {fh}, lock_owner: {lock_owner}, \
            start: {start}, end: {end}, typ: {typ}, pid: {pid})"
		);
		reply.error(Errno::ENOSYS);
	}

	fn setlk(
		&self,
		_req: &Request,
		ino: INodeNo,
		fh: FileHandle,
		lock_owner: LockOwner,
		start: u64,
		end: u64,
		typ: i32,
		pid: u32,
		sleep: bool,
		reply: ReplyEmpty,
	) {
		info!(
			"setlk(ino={ino:?}, fh={fh}, lock_owner={lock_owner:?}, start={start}, end={end}, typ={typ}, pid={pid}, sleep={sleep})"
		);
		warn!(
			"[Not Implemented] setlk(ino: {ino:#x?}, fh: {fh}, lock_owner: {lock_owner}, \
            start: {start}, end: {end}, typ: {typ}, pid: {pid}, sleep: {sleep})"
		);
		reply.error(Errno::ENOSYS);
	}

	fn bmap(&self, _req: &Request, ino: INodeNo, blocksize: u32, idx: u64, reply: ReplyBmap) {
		info!("bmap(ino={ino:?}, blocksize={blocksize}, idx={idx})");
		warn!("[Not Implemented] bmap(ino: {ino:#x?}, blocksize: {blocksize}, idx: {idx})",);
		reply.error(Errno::ENOSYS);
	}

	fn ioctl(
		&self,
		_req: &Request,
		ino: INodeNo,
		fh: FileHandle,
		flags: IoctlFlags,
		cmd: u32,
		in_data: &[u8],
		out_size: u32,
		reply: ReplyIoctl,
	) {
		info!(
			"ioctl(ino={ino:?}, fh={fh}, flags={flags:?}, cmd={cmd}, in_data_len={}, out_size={out_size})",
			in_data.len()
		);
		warn!(
			"[Not Implemented] ioctl(ino: {ino:#x?}, fh: {fh}, flags: {flags}, \
            cmd: {cmd}, in_data.len(): {}, out_size: {out_size})",
			in_data.len()
		);
		reply.error(Errno::ENOSYS);
	}

	fn poll(
		&self,
		_req: &Request,
		ino: INodeNo,
		fh: FileHandle,
		ph: PollNotifier,
		events: PollEvents,
		flags: PollFlags,
		reply: ReplyPoll,
	) {
		info!("poll(ino={ino:?}, fh={fh}, ph={ph:?}, events={events:?}, flags={flags:?})");
		warn!(
			"[Not Implemented] poll(ino: {ino:#x?}, fh: {fh}, \
            ph: {ph:?}, events: {events}, flags: {flags})"
		);
		reply.error(Errno::ENOSYS);
	}

	fn fallocate(
		&self,
		_req: &Request,
		ino: INodeNo,
		fh: FileHandle,
		offset: u64,
		length: u64,
		mode: i32,
		reply: ReplyEmpty,
	) {
		info!("fallocate(ino={ino:?}, fh={fh}, offset={offset}, length={length}, mode={mode})");
		warn!(
			"[Not Implemented] fallocate(ino: {ino:#x?}, fh: {fh}, \
            offset: {offset}, length: {length}, mode: {mode})"
		);
		reply.error(Errno::ENOSYS);
	}

	fn lseek(&self, _req: &Request, ino: INodeNo, fh: FileHandle, offset: i64, whence: i32, reply: ReplyLseek) {
		info!("lseek(ino={ino:?}, fh={fh}, offset={offset}, whence={whence})");
		warn!(
			"[Not Implemented] lseek(ino: {ino:#x?}, fh: {fh}, \
            offset: {offset}, whence: {whence})"
		);
		reply.error(Errno::ENOSYS);
	}

	fn copy_file_range(
		&self,
		_req: &Request,
		ino_in: INodeNo,
		fh_in: FileHandle,
		offset_in: u64,
		ino_out: INodeNo,
		fh_out: FileHandle,
		offset_out: u64,
		len: u64,
		flags: CopyFileRangeFlags,
		reply: ReplyWrite,
	) {
		info!(
			"copy_file_range(ino_in={ino_in:?}, fh_in={fh_in}, offset_in={offset_in}, ino_out={ino_out:?}, fh_out={fh_out}, offset_out={offset_out}, len={len}, flags={flags:?})"
		);
		warn!(
			"[Not Implemented] copy_file_range(ino_in: {ino_in:#x?}, fh_in: {fh_in}, \
            offset_in: {offset_in}, ino_out: {ino_out:#x?}, fh_out: {fh_out}, \
            offset_out: {offset_out}, len: {len}, flags: {flags:?})"
		);
		reply.error(Errno::ENOSYS);
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::ffi::OsStr;

	#[test]
	fn statfs_data_for_fresh_filesystem() {
		let fs = FileSystem::new();
		let state = fs.state.read();
		let statfs = FileSystem::statfs_data(&state);

		assert_eq!(statfs.blocks, (TOTAL_BYTES_LIMIT / BLOCK_SIZE) as u64);
		assert_eq!(statfs.bfree, statfs.blocks);
		assert_eq!(statfs.bavail, statfs.blocks);
		assert_eq!(statfs.files, MAX_INODES as u64);
		assert_eq!(statfs.ffree, (MAX_INODES - 1) as u64);
		assert_eq!(statfs.bsize, BLOCK_SIZE as u32);
		assert_eq!(statfs.frsize, BLOCK_SIZE as u32);
		assert_eq!(statfs.namelen, MAX_NAME_LEN as u32);
	}

	#[test]
	fn statfs_data_rounds_blocks_up() {
		let fs = FileSystem::new();
		let mut state = fs.state.write();
		let (ino, _inode, fh) = state
			.op_create(INodeNo(1), OsStr::new("blocks"), 0o644, 0, 1000, 1000)
			.expect("create should succeed");
		state
			.op_write(ino, fh, 0, &vec![0u8; BLOCK_SIZE + 1])
			.expect("write should succeed");
		state.op_release(fh);
		state.total_bytes_limit = BLOCK_SIZE * 2 + 1;

		let statfs = FileSystem::statfs_data(&state);
		assert_eq!(statfs.blocks, 3);
		assert_eq!(statfs.bfree, 1);
		assert_eq!(statfs.bavail, 1);
	}

	#[test]
	fn statfs_data_saturates_free_counts() {
		let fs = FileSystem::new();
		let mut state = fs.state.write();
		let (ino, _inode, fh) = state
			.op_create(INodeNo(1), OsStr::new("saturate"), 0o644, 0, 1000, 1000)
			.expect("create should succeed");
		state
			.op_write(ino, fh, 0, &vec![0u8; BLOCK_SIZE * 3])
			.expect("write should succeed");
		state.op_release(fh);
		state.total_bytes_limit = BLOCK_SIZE;
		state.max_inodes = 0;
		state.max_name_len = usize::MAX;

		let statfs = FileSystem::statfs_data(&state);
		assert_eq!(statfs.blocks, 1);
		assert_eq!(statfs.bfree, 0);
		assert_eq!(statfs.bavail, 0);
		assert_eq!(statfs.files, 0);
		assert_eq!(statfs.ffree, 0);
		assert_eq!(statfs.namelen, u32::MAX);
	}

	#[test]
	fn unlinked_inode_lives_until_last_handle_release() {
		let fs = FileSystem::new();
		let ino = {
			let mut state = fs.state.write();
			let (ino, _inode, fh) = state
				.op_create(INodeNo(1), OsStr::new("file"), 0o644, 0, 1000, 1000)
				.expect("create should succeed");
			state.op_write(ino, fh, 0, b"abc").expect("write should succeed");
			state
				.op_unlink(INodeNo(1), OsStr::new("file"))
				.expect("unlink should succeed");
			assert!(state.op_getattr(ino).is_ok());
			state.op_release(fh);
			ino
		};
		let state = fs.state.read();
		assert_eq!(
			state
				.op_getattr(ino)
				.map_err(i32::from)
				.expect_err("inode should be removed"),
			i32::from(Errno::ENOENT)
		);
		assert!(state.check_invariants().is_ok());
	}

	#[test]
	fn setattr_size_updates_used_bytes_for_growth_and_shrink() {
		let fs = FileSystem::new();
		let mut state = fs.state.write();
		let (ino, _inode, fh) = state
			.op_create(INodeNo(1), OsStr::new("growshrink"), 0o644, 0, 1000, 1000)
			.expect("create should succeed");
		state.op_release(fh);

		state.op_setattr_size(ino, 10).expect("grow should succeed");
		assert_eq!(state.used_bytes(), 10);

		state.op_setattr_size(ino, 3).expect("shrink should succeed");
		assert_eq!(state.used_bytes(), 3);
		assert!(state.check_invariants().is_ok());
	}

	#[test]
	fn rmdir_rejects_non_empty_directory() {
		let fs = FileSystem::new();
		let mut state = fs.state.write();
		let (dir_ino, _dir) = state
			.op_mkdir(INodeNo(1), OsStr::new("dir"), 0o755, 0, 1000, 1000)
			.expect("mkdir should succeed");
		let (_file_ino, _file, fh) = state
			.op_create(dir_ino, OsStr::new("child"), 0o644, 0, 1000, 1000)
			.expect("create in dir should succeed");
		state.op_release(fh);

		assert_eq!(
			state
				.op_rmdir(INodeNo(1), OsStr::new("dir"))
				.map_err(i32::from)
				.expect_err("non-empty directory should fail"),
			i32::from(Errno::ENOTEMPTY)
		);
		assert!(state.check_invariants().is_ok());
	}

	#[test]
	fn write_with_huge_offset_returns_efbig() {
		let fs = FileSystem::new();
		let mut state = fs.state.write();
		let (ino, _inode, fh) = state
			.op_create(INodeNo(1), OsStr::new("offset"), 0o644, 0, 1000, 1000)
			.expect("create should succeed");
		let err = state
			.op_write(ino, fh, u64::MAX, b"x")
			.expect_err("write should fail with huge offset");
		assert_eq!(i32::from(err), i32::from(Errno::EFBIG));
		assert!(state.check_invariants().is_ok());
	}

	#[test]
	fn freed_inode_is_reused_without_collision() {
		let fs = FileSystem::new();
		let mut state = fs.state.write();
		let (first, _first_inode, fh_first) = state
			.op_create(INodeNo(1), OsStr::new("first"), 0o644, 0, 1000, 1000)
			.expect("first create should succeed");
		state.op_release(fh_first);
		state
			.op_unlink(INodeNo(1), OsStr::new("first"))
			.expect("unlink should succeed");

		let (second, _second_inode, fh_second) = state
			.op_create(INodeNo(1), OsStr::new("second"), 0o644, 0, 1000, 1000)
			.expect("second create should succeed");
		state.op_release(fh_second);

		assert_eq!(first, second);
		assert!(state.check_invariants().is_ok());
	}

	#[test]
	fn rename_file_same_dir_changes_name() {
		let fs = FileSystem::new();
		let mut state = fs.state.write();
		let (ino, _inode, fh) = state
			.op_create(INodeNo(1), OsStr::new("old"), 0o644, 0, 1000, 1000)
			.expect("create should succeed");
		state.op_release(fh);

		state
			.op_rename(
				INodeNo(1),
				OsStr::new("old"),
				INodeNo(1),
				OsStr::new("new"),
				RenameFlags::empty(),
			)
			.expect("rename should succeed");

		assert_eq!(state.pager.dir_entries_get(INodeNo(1), OsStr::new("old")), None);
		assert_eq!(state.pager.dir_entries_get(INodeNo(1), OsStr::new("new")), Some(ino));
		assert!(state.check_invariants().is_ok());
	}

	#[test]
	fn rename_replace_file_unlinks_old_target() {
		let fs = FileSystem::new();
		let mut state = fs.state.write();
		let (src_ino, _src_inode, src_fh) = state
			.op_create(INodeNo(1), OsStr::new("src"), 0o644, 0, 1000, 1000)
			.expect("create src should succeed");
		state.op_release(src_fh);

		let (dst_ino, _dst_inode, dst_fh) = state
			.op_create(INodeNo(1), OsStr::new("dst"), 0o644, 0, 1000, 1000)
			.expect("create dst should succeed");
		state
			.op_write(dst_ino, dst_fh, 0, b"payload")
			.expect("write should succeed");
		state.op_release(dst_fh);

		state
			.op_rename(
				INodeNo(1),
				OsStr::new("src"),
				INodeNo(1),
				OsStr::new("dst"),
				RenameFlags::empty(),
			)
			.expect("rename should succeed");

		assert_eq!(state.pager.dir_entries_get(INodeNo(1), OsStr::new("src")), None);
		assert_eq!(
			state.pager.dir_entries_get(INodeNo(1), OsStr::new("dst")),
			Some(src_ino)
		);
		assert_eq!(
			state
				.op_getattr(dst_ino)
				.map_err(i32::from)
				.expect_err("old dst inode should be removed"),
			i32::from(Errno::ENOENT)
		);
		assert!(state.check_invariants().is_ok());
	}

	#[test]
	fn rename_dir_across_dirs_updates_dotdot_and_nlink() {
		let fs = FileSystem::new();
		let mut state = fs.state.write();
		let (a, _) = state
			.op_mkdir(INodeNo(1), OsStr::new("a"), 0o755, 0, 1000, 1000)
			.expect("mkdir a should succeed");
		let (b, _) = state
			.op_mkdir(INodeNo(1), OsStr::new("b"), 0o755, 0, 1000, 1000)
			.expect("mkdir b should succeed");
		let (child, _) = state
			.op_mkdir(a, OsStr::new("child"), 0o755, 0, 1000, 1000)
			.expect("mkdir child should succeed");

		state
			.op_rename(a, OsStr::new("child"), b, OsStr::new("moved"), RenameFlags::empty())
			.expect("rename should succeed");

		assert_eq!(state.pager.dir_entries_get(a, OsStr::new("child")), None);
		assert_eq!(state.pager.dir_entries_get(b, OsStr::new("moved")), Some(child));
		assert_eq!(state.pager.dir_entries_get(child, OsStr::new("..")), Some(b));
		assert_eq!(state.pager.inode_get(a).expect("a should exist").nlink, 2);
		assert_eq!(state.pager.inode_get(b).expect("b should exist").nlink, 3);
		assert!(state.check_invariants().is_ok());
	}

	#[test]
	fn rename_replace_empty_dir_same_parent_decrements_parent_nlink() {
		let fs = FileSystem::new();
		let mut state = fs.state.write();
		let root = INodeNo(1);
		let (src_ino, _) = state
			.op_mkdir(root, OsStr::new("src"), 0o755, 0, 1000, 1000)
			.expect("mkdir src should succeed");
		let (dst_ino, _) = state
			.op_mkdir(root, OsStr::new("dst"), 0o755, 0, 1000, 1000)
			.expect("mkdir dst should succeed");

		let before = state.pager.inode_get(root).expect("root exists").nlink;
		state
			.op_rename(root, OsStr::new("src"), root, OsStr::new("dst"), RenameFlags::empty())
			.expect("rename should succeed");

		assert_eq!(state.pager.dir_entries_get(root, OsStr::new("src")), None);
		assert_eq!(state.pager.dir_entries_get(root, OsStr::new("dst")), Some(src_ino));
		assert_eq!(
			state
				.op_getattr(dst_ino)
				.map_err(i32::from)
				.expect_err("old dst inode should be removed"),
			i32::from(Errno::ENOENT)
		);
		let after = state.pager.inode_get(root).expect("root exists").nlink;
		assert_eq!(after, before - 1);
		assert!(state.check_invariants().is_ok());
	}

	#[test]
	fn rename_replace_empty_dir_cross_parent_keeps_newparent_nlink() {
		let fs = FileSystem::new();
		let mut state = fs.state.write();
		let root = INodeNo(1);
		let (old_parent, _) = state
			.op_mkdir(root, OsStr::new("old_parent"), 0o755, 0, 1000, 1000)
			.expect("mkdir old_parent should succeed");
		let (new_parent, _) = state
			.op_mkdir(root, OsStr::new("new_parent"), 0o755, 0, 1000, 1000)
			.expect("mkdir new_parent should succeed");
		let (src_ino, _) = state
			.op_mkdir(old_parent, OsStr::new("src"), 0o755, 0, 1000, 1000)
			.expect("mkdir src should succeed");
		let (dst_ino, _) = state
			.op_mkdir(new_parent, OsStr::new("dst"), 0o755, 0, 1000, 1000)
			.expect("mkdir dst should succeed");

		let old_before = state.pager.inode_get(old_parent).expect("old_parent exists").nlink;
		let new_before = state.pager.inode_get(new_parent).expect("new_parent exists").nlink;
		state
			.op_rename(
				old_parent,
				OsStr::new("src"),
				new_parent,
				OsStr::new("dst"),
				RenameFlags::empty(),
			)
			.expect("rename should succeed");

		assert_eq!(state.pager.dir_entries_get(old_parent, OsStr::new("src")), None);
		assert_eq!(
			state.pager.dir_entries_get(new_parent, OsStr::new("dst")),
			Some(src_ino)
		);
		assert_eq!(state.pager.dir_entries_get(src_ino, OsStr::new("..")), Some(new_parent));
		assert_eq!(
			state
				.op_getattr(dst_ino)
				.map_err(i32::from)
				.expect_err("old dst inode should be removed"),
			i32::from(Errno::ENOENT)
		);
		let old_after = state.pager.inode_get(old_parent).expect("old_parent exists").nlink;
		let new_after = state.pager.inode_get(new_parent).expect("new_parent exists").nlink;
		assert_eq!(old_after, old_before - 1);
		assert_eq!(new_after, new_before);
		assert!(state.check_invariants().is_ok());
	}

	#[test]
	fn rename_replace_non_empty_dir_fails_with_enotempty() {
		let fs = FileSystem::new();
		let mut state = fs.state.write();
		let (src_parent, _) = state
			.op_mkdir(INodeNo(1), OsStr::new("src_parent"), 0o755, 0, 1000, 1000)
			.expect("mkdir src_parent should succeed");
		let (dst_parent, _) = state
			.op_mkdir(INodeNo(1), OsStr::new("dst_parent"), 0o755, 0, 1000, 1000)
			.expect("mkdir dst_parent should succeed");
		let (_src_dir, _) = state
			.op_mkdir(src_parent, OsStr::new("src_dir"), 0o755, 0, 1000, 1000)
			.expect("mkdir src_dir should succeed");
		let (dst_dir, _) = state
			.op_mkdir(dst_parent, OsStr::new("dst_dir"), 0o755, 0, 1000, 1000)
			.expect("mkdir dst_dir should succeed");
		let (_file, _inode, fh) = state
			.op_create(dst_dir, OsStr::new("payload"), 0o644, 0, 1000, 1000)
			.expect("create payload should succeed");
		state.op_release(fh);

		let err = state
			.op_rename(
				src_parent,
				OsStr::new("src_dir"),
				dst_parent,
				OsStr::new("dst_dir"),
				RenameFlags::empty(),
			)
			.expect_err("rename should fail");

		assert_eq!(i32::from(err), i32::from(Errno::ENOTEMPTY));
		assert!(state.pager.dir_entries_get(src_parent, OsStr::new("src_dir")).is_some());
		assert_eq!(
			state.pager.dir_entries_get(dst_parent, OsStr::new("dst_dir")),
			Some(dst_dir)
		);
		assert!(state.check_invariants().is_ok());
	}

	#[test]
	fn rename_rejects_non_empty_flags() {
		let fs = FileSystem::new();
		let mut state = fs.state.write();
		let (_ino, _inode, fh) = state
			.op_create(INodeNo(1), OsStr::new("a"), 0o644, 0, 1000, 1000)
			.expect("create should succeed");
		state.op_release(fh);

		let err = state
			.op_rename(
				INodeNo(1),
				OsStr::new("a"),
				INodeNo(1),
				OsStr::new("b"),
				RenameFlags::RENAME_NOREPLACE,
			)
			.expect_err("rename should fail");
		assert_eq!(i32::from(err), i32::from(Errno::EINVAL));
		assert!(state.check_invariants().is_ok());
	}

	#[test]
	fn access_existing_ok_missing_enoent() {
		let fs = FileSystem::new();
		let mut state = fs.state.write();
		let (ino, _inode, fh) = state
			.op_create(INodeNo(1), OsStr::new("acc"), 0o644, 0, 1000, 1000)
			.expect("create should succeed");
		state.op_release(fh);

		assert!(state.op_access(ino, AccessFlags::F_OK).is_ok());
		let err = state
			.op_access(INodeNo(999_999), AccessFlags::F_OK)
			.expect_err("missing inode should fail");
		assert_eq!(i32::from(err), i32::from(Errno::ENOENT));
		assert!(state.check_invariants().is_ok());
	}

	#[test]
	fn new_with_limits_rejects_page_budget_too_small_for_root() {
		let err = match FileSystem::new_with_limits(1, BLOCK_SIZE) {
			Ok(_) => panic!("init should fail"),
			Err(err) => err,
		};
		assert!(err.contains("insufficient page capacity"));
	}
}
