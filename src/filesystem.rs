use std::{
	collections::{BTreeMap, HashMap},
	ffi::{OsStr, OsString},
	io,
	os::unix::ffi::OsStrExt,
	path::Path,
	sync::Arc,
	time::{Duration, SystemTime},
};

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

pub struct FileSystem {
	pub state: Arc<RwLock<FileSystemState>>,
}

pub struct FileSystemState {
	// Inode number -> inode metadata
	pub inodes: HashMap<INodeNo, Inode>,

	// Directory inode -> (name -> child inode)
	pub dirs: HashMap<INodeNo, BTreeMap<OsString, INodeNo>>,

	// Regular file inode -> file bytes (RAM-first version)
	pub file_data: HashMap<INodeNo, Vec<u8>>,

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

	// Accounting
	pub used_bytes: u64,
}

impl FileSystem {
	pub fn new() -> Self {
		let now = SystemTime::now();
		let root_ino = INodeNo(1);
		let root_uid = unsafe { libc::geteuid() };
		let root_gid = unsafe { libc::getegid() };

		let root_inode = Inode {
			ino: root_ino,
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

		let mut root_dir_entries = BTreeMap::new();
		root_dir_entries.insert(OsString::from("."), root_ino);
		root_dir_entries.insert(OsString::from(".."), root_ino);

		let mut inodes = HashMap::new();
		inodes.insert(root_ino, root_inode);

		let mut dirs = HashMap::new();
		dirs.insert(root_ino, root_dir_entries);

		let state = FileSystemState {
			inodes,
			dirs,
			file_data: HashMap::new(),
			handles: HashMap::new(),
			next_fh: 1,
			next_ino: INodeNo(root_ino.0 + 1),
			free_inos: Vec::new(),
			max_inodes: MAX_INODES,
			max_name_len: MAX_NAME_LEN,
			max_file_size: MAX_FILE_SIZE,
			total_bytes_limit: TOTAL_BYTES_LIMIT,
			used_bytes: 0,
		};
		Self {
			state: Arc::new(RwLock::new(state)),
		}
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
		let inode_count = state.inodes.len();
		Self::alloc_ino_with_count(&mut state, inode_count)
	}

	fn cleanup_unlinked_inode_if_releasable(state: &mut FileSystemState, ino: INodeNo) {
		let Some(inode) = state.inodes.get(&ino) else {
			return;
		};
		if inode.nlink != 0 {
			return;
		}

		let has_open_handles = state.handles.values().any(|open_ino| *open_ino == ino);
		if has_open_handles {
			return;
		}

		let released = state.file_data.remove(&ino).map_or(0usize, |d| d.len());
		state.used_bytes = state.used_bytes.saturating_sub(released as u64);
		state.inodes.remove(&ino);
		state.free_inos.push(ino);
	}

	fn blocks_for_bytes(bytes: u64) -> u64 {
		bytes.div_ceil(BLOCK_SIZE as u64)
	}

	fn statfs_data(state: &FileSystemState) -> StatfsData {
		let blocks = Self::blocks_for_bytes(state.total_bytes_limit as u64);
		let used_blocks = Self::blocks_for_bytes(state.used_bytes);
		let bfree = blocks.saturating_sub(used_blocks);
		let files = state.max_inodes as u64;
		let ffree = state.max_inodes.saturating_sub(state.inodes.len()) as u64;
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Inode {
	pub ino: INodeNo,
	pub kind: FileType,
	pub perm: u16,
	pub uid: u32,
	pub gid: u32,
	pub size: u64,
	pub nlink: u32,

	pub atime: SystemTime,
	pub mtime: SystemTime,
	pub ctime: SystemTime,
	pub crtime: SystemTime,
}

impl Inode {
	pub fn to_file_attr(&self) -> FileAttr {
		let blocks = self.size.div_ceil(POSIX_BLOCK);
		FileAttr {
			ino: self.ino,
			size: self.size,
			blocks,
			atime: self.atime,
			mtime: self.mtime,
			ctime: self.ctime,
			crtime: self.crtime,
			kind: self.kind,
			perm: self.perm,
			nlink: self.nlink,
			uid: self.uid,
			gid: self.gid,
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

pub type FsOpResult<T> = Result<T, Errno>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReaddirEntry {
	pub ino: INodeNo,
	pub kind: FileType,
	pub name: OsString,
}

impl FileSystemState {
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

	fn ensure_parent_dir(&self, parent: INodeNo) -> FsOpResult<&BTreeMap<OsString, INodeNo>> {
		if !self.inodes.contains_key(&parent) {
			return Err(Errno::ENOENT);
		}
		self.dirs.get(&parent).ok_or(Errno::ENOTDIR)
	}

	fn lookup_child_ino(&self, parent: INodeNo, name: &OsStr) -> FsOpResult<INodeNo> {
		let parent_dir = self.ensure_parent_dir(parent)?;
		parent_dir.get(name).copied().ok_or(Errno::ENOENT)
	}

	fn validate_file_handle(&self, ino: INodeNo, fh: FileHandle) -> FsOpResult<()> {
		let Some(handle_ino) = self.handles.get(&fh) else {
			return Err(Errno::EBADF);
		};
		if *handle_ino != ino {
			return Err(Errno::EBADF);
		}

		let Some(inode) = self.inodes.get(&ino) else {
			return Err(Errno::ENOENT);
		};
		if inode.kind == FileType::Directory {
			return Err(Errno::EISDIR);
		}
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
		let old_len = self.file_data.get(&ino).map_or(0usize, Vec::len);
		if new_len > old_len {
			let growth = new_len - old_len;
			let Some(new_used_bytes) = self.used_bytes.checked_add(growth as u64) else {
				return Err(Errno::ENOSPC);
			};
			if new_used_bytes > self.total_bytes_limit as u64 {
				return Err(Errno::ENOSPC);
			}
			self.used_bytes = new_used_bytes;
		} else {
			let shrink = old_len - new_len;
			self.used_bytes = self.used_bytes.saturating_sub(shrink as u64);
		}

		let entry = self.file_data.entry(ino).or_default();
		entry.resize(new_len, 0);

		let inode = self.inodes.get_mut(&ino).ok_or(Errno::EIO)?;
		inode.size = new_len as u64;
		Ok(())
	}

	pub fn op_getattr(&self, ino: INodeNo) -> FsOpResult<Inode> {
		self.inodes.get(&ino).copied().ok_or(Errno::ENOENT)
	}

	pub fn op_mkdir(
		&mut self,
		parent: INodeNo,
		name: &OsStr,
		mode: u32,
		umask: u32,
		uid: u32,
		gid: u32,
	) -> FsOpResult<Inode> {
		self.ensure_name_len(name)?;
		let parent_dir_view = self.ensure_parent_dir(parent)?;
		if parent_dir_view.contains_key(name) {
			return Err(Errno::EEXIST);
		}

		let inode_count = self.inodes.len();
		let Some(new_ino) = FileSystem::alloc_ino_with_count(self, inode_count) else {
			return Err(Errno::ENOSPC);
		};

		let now = SystemTime::now();
		let new_inode = Inode {
			ino: new_ino,
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

		let mut dir_entries = BTreeMap::new();
		dir_entries.insert(OsString::from("."), new_ino);
		dir_entries.insert(OsString::from(".."), parent);

		let parent_dir = self.dirs.get_mut(&parent).ok_or(Errno::EIO)?;
		parent_dir.insert(name.to_owned(), new_ino);

		let parent_inode = self.inodes.get_mut(&parent).ok_or(Errno::EIO)?;
		parent_inode.nlink += 1;
		parent_inode.mtime = now;
		parent_inode.ctime = now;

		self.dirs.insert(new_ino, dir_entries);
		self.inodes.insert(new_ino, new_inode);
		Ok(new_inode)
	}

	pub fn op_unlink(&mut self, parent: INodeNo, name: &OsStr) -> FsOpResult<()> {
		Self::reject_dot_entries(name)?;
		let child_ino = self.lookup_child_ino(parent, name)?;

		let child_inode = self.inodes.get(&child_ino).ok_or(Errno::EIO)?;
		if child_inode.kind == FileType::Directory {
			return Err(Errno::EISDIR);
		}

		let now = SystemTime::now();
		let parent_dir = self.dirs.get_mut(&parent).ok_or(Errno::EIO)?;
		parent_dir.remove(name);

		let remove_inode = {
			let child_inode = self.inodes.get_mut(&child_ino).ok_or(Errno::EIO)?;
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

		let parent_inode = self.inodes.get_mut(&parent).ok_or(Errno::EIO)?;
		parent_inode.mtime = now;
		parent_inode.ctime = now;
		Ok(())
	}

	pub fn op_rmdir(&mut self, parent: INodeNo, name: &OsStr) -> FsOpResult<()> {
		Self::reject_dot_entries(name)?;
		let child_ino = self.lookup_child_ino(parent, name)?;

		if child_ino == INodeNo(1) {
			return Err(Errno::EBUSY);
		}

		let child_inode = self.inodes.get(&child_ino).ok_or(Errno::EIO)?;
		if child_inode.kind != FileType::Directory {
			return Err(Errno::ENOTDIR);
		}

		let child_dir = self.dirs.get(&child_ino).ok_or(Errno::EIO)?;
		if child_dir.len() > 2 {
			return Err(Errno::ENOTEMPTY);
		}

		let now = SystemTime::now();
		let parent_dir = self.dirs.get_mut(&parent).ok_or(Errno::EIO)?;
		parent_dir.remove(name);
		self.dirs.remove(&child_ino);
		self.inodes.remove(&child_ino);

		let parent_inode = self.inodes.get_mut(&parent).ok_or(Errno::EIO)?;
		if parent_inode.nlink == 0 {
			return Err(Errno::EIO);
		}
		parent_inode.nlink -= 1;
		parent_inode.mtime = now;
		parent_inode.ctime = now;
		self.free_inos.push(child_ino);
		Ok(())
	}

	pub fn op_open(&mut self, ino: INodeNo) -> FsOpResult<FileHandle> {
		let Some(inode) = self.inodes.get(&ino) else {
			return Err(Errno::ENOENT);
		};
		if inode.kind == FileType::Directory {
			return Err(Errno::EISDIR);
		}
		self.alloc_file_handle_for(ino)
	}

	pub fn op_read(&mut self, ino: INodeNo, fh: FileHandle, offset: u64, size: u32) -> FsOpResult<Vec<u8>> {
		self.validate_file_handle(ino, fh)?;

		let data = self.file_data.entry(ino).or_default();
		let start = (offset as usize).min(data.len());
		let end = start.saturating_add(size as usize).min(data.len());
		let out = data[start..end].to_vec();

		let inode = self.inodes.get_mut(&ino).ok_or(Errno::EIO)?;
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

		let current_len = self.file_data.get(&ino).map_or(0, Vec::len);
		if end > current_len {
			self.resize_file_len(ino, end)?;
		}
		let file = self.file_data.entry(ino).or_default();
		file[start..end].copy_from_slice(data);

		let now = SystemTime::now();
		let inode = self.inodes.get_mut(&ino).ok_or(Errno::EIO)?;
		inode.mtime = now;
		inode.ctime = now;

		Ok(data.len() as u32)
	}

	pub fn op_release(&mut self, fh: FileHandle) {
		if let Some(ino) = self.handles.remove(&fh) {
			FileSystem::cleanup_unlinked_inode_if_releasable(self, ino);
		}
	}

	pub fn op_readdir(&self, ino: INodeNo, offset: u64) -> FsOpResult<Vec<ReaddirEntry>> {
		if !self.inodes.contains_key(&ino) {
			return Err(Errno::ENOENT);
		}
		let Some(dir) = self.dirs.get(&ino) else {
			return Err(Errno::ENOTDIR);
		};

		let mut entries = Vec::new();
		for (name, entry_ino) in dir.iter().skip(offset as usize) {
			let inode = self.inodes.get(entry_ino).ok_or(Errno::EIO)?;
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
	) -> FsOpResult<(Inode, FileHandle)> {
		self.ensure_name_len(name)?;
		let parent_dir_view = self.ensure_parent_dir(parent)?;
		if parent_dir_view.contains_key(name) {
			return Err(Errno::EEXIST);
		}

		let inode_count = self.inodes.len();
		let Some(new_ino) = FileSystem::alloc_ino_with_count(self, inode_count) else {
			return Err(Errno::ENOSPC);
		};

		let now = SystemTime::now();
		let new_inode = Inode {
			ino: new_ino,
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

		let parent_dir = self.dirs.get_mut(&parent).ok_or(Errno::EIO)?;
		parent_dir.insert(name.to_owned(), new_ino);
		self.inodes.insert(new_ino, new_inode);
		self.file_data.insert(new_ino, Vec::new());

		let file_handle = self.alloc_file_handle_for(new_ino)?;

		let parent_inode = self.inodes.get_mut(&parent).ok_or(Errno::EIO)?;
		parent_inode.mtime = now;
		parent_inode.ctime = now;

		Ok((new_inode, file_handle))
	}

	pub fn op_setattr_size(&mut self, ino: INodeNo, size: u64) -> FsOpResult<Inode> {
		let now = SystemTime::now();
		let max_file_size = self.max_file_size;
		if !self.inodes.contains_key(&ino) {
			return Err(Errno::ENOENT);
		}

		let is_dir = self
			.inodes
			.get(&ino)
			.map(|inode| inode.kind == FileType::Directory)
			.unwrap_or(false);
		if is_dir {
			return Err(Errno::EISDIR);
		}
		if size as usize > max_file_size {
			return Err(Errno::EFBIG);
		}

		self.resize_file_len(ino, size as usize)?;
		let inode = self.inodes.get_mut(&ino).ok_or(Errno::EIO)?;
		inode.mtime = now;
		inode.ctime = now;
		Ok(*inode)
	}

	pub fn check_invariants(&self) -> Result<(), String> {
		let root = INodeNo(1);
		let Some(root_inode) = self.inodes.get(&root) else {
			return Err("missing root inode".to_string());
		};
		if root_inode.kind != FileType::Directory {
			return Err("root inode is not a directory".to_string());
		}

		let Some(root_dir) = self.dirs.get(&root) else {
			return Err("missing root directory entries".to_string());
		};
		if root_dir.get(OsStr::new(".")) != Some(&root) || root_dir.get(OsStr::new("..")) != Some(&root) {
			return Err("root directory is missing '.' or '..'".to_string());
		}

		let mut computed_used_bytes = 0u64;
		for (ino, data) in &self.file_data {
			let Some(inode) = self.inodes.get(ino) else {
				return Err(format!("file_data points to missing inode: {ino:?}"));
			};
			if inode.kind != FileType::RegularFile {
				return Err(format!("file_data points to non-regular inode: {ino:?}"));
			}
			if inode.size != data.len() as u64 {
				return Err(format!("inode size mismatch for {ino:?}"));
			}
			computed_used_bytes = computed_used_bytes
				.checked_add(data.len() as u64)
				.ok_or_else(|| "used_bytes overflow while checking invariants".to_string())?;
		}

		if self.used_bytes != computed_used_bytes {
			return Err(format!(
				"used_bytes mismatch: actual={} computed={computed_used_bytes}",
				self.used_bytes
			));
		}
		if self.used_bytes > self.total_bytes_limit as u64 {
			return Err("used_bytes exceeds total_bytes_limit".to_string());
		}
		if self.inodes.len() > self.max_inodes {
			return Err("inode count exceeds max_inodes".to_string());
		}

		for ino in &self.free_inos {
			if self.inodes.contains_key(ino) {
				return Err(format!("free inode set overlaps live inodes: {ino:?}"));
			}
		}

		for (fh, ino) in &self.handles {
			let Some(inode) = self.inodes.get(ino) else {
				return Err(format!("handle points to missing inode: fh={fh:?}, ino={ino:?}"));
			};
			if inode.kind != FileType::RegularFile {
				return Err(format!("handle points to non-regular inode: fh={fh:?}, ino={ino:?}"));
			}
		}

		for (dir_ino, entries) in &self.dirs {
			if !self.inodes.contains_key(dir_ino) {
				return Err(format!("directory map points to missing inode: {dir_ino:?}"));
			}

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
				let Some(child_inode) = self.inodes.get(child_ino) else {
					return Err(format!(
						"directory entry points to missing inode: parent={dir_ino:?}, name={name:?}, child={child_ino:?}"
					));
				};
				if name != OsStr::new(".") && name != OsStr::new("..") && child_inode.kind == FileType::Directory {
					subdir_count += 1;
				}
			}

			let Some(dir_inode) = self.inodes.get(dir_ino) else {
				return Err(format!("directory inode missing from inode map: {dir_ino:?}"));
			};
			if dir_inode.kind != FileType::Directory {
				return Err(format!("dir table contains non-directory inode: {dir_ino:?}"));
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
		if !state.inodes.contains_key(&parent) {
			return reply.error(Errno::ENOENT);
		}

		let Some(dir) = state.dirs.get(&parent) else {
			return reply.error(Errno::ENOTDIR);
		};

		let Some(file) = dir.get(name) else {
			return reply.error(Errno::ENOENT);
		};

		let inode = invariant_or_eio!(
			state.inodes.get(file),
			reply,
			"directory entry points to missing inode: parent={parent:?}, name={name:?}, child={file:?}"
		);

		reply.entry(&ONE_SEC, &inode.to_file_attr(), Generation(0));
	}

	fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
		info!("forget(ino={ino:?}, nlookup={nlookup})");
	}

	fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
		info!("getattr(ino={ino:?})");
		let state = self.state.read();
		match state.op_getattr(ino) {
			Ok(inode) => reply.attr(&ONE_SEC, &inode.to_file_attr()),
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
		if !state.inodes.contains_key(&ino) {
			return reply.error(Errno::ENOENT);
		}

		let mut changed = false;

		if let Some(size) = size {
			let is_dir = state
				.inodes
				.get(&ino)
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
			let inode = state.inodes.get_mut(&ino).expect("validated inode must exist");
			inode.mtime = now;
			changed = true;
		}

		let inode = state.inodes.get_mut(&ino).expect("validated inode must exist");

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

		reply.attr(&ONE_SEC, &inode.to_file_attr());
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
			Ok(inode) => reply.entry(&ONE_SEC, &inode.to_file_attr(), Generation(0)),
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
		warn!(
			"[Not Implemented] rename(parent: {parent:#x?}, name: {name:?}, \
            newparent: {newparent:#x?}, newname: {newname:?}, flags: {flags})",
		);
		reply.error(Errno::ENOSYS);
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
		warn!("[Not Implemented] flush(ino: {ino:#x?}, fh: {fh}, lock_owner: {lock_owner:?})");
		reply.error(Errno::ENOSYS);
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
		warn!("[Not Implemented] fsync(ino: {ino:#x?}, fh: {fh}, datasync: {datasync})");
		reply.error(Errno::ENOSYS);
	}

	fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
		info!("opendir(ino={ino:?})");
		let state = self.state.read();

		let Some(inode) = state.inodes.get(&ino) else {
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
		warn!("[Not Implemented] fsyncdir(ino: {ino:#x?}, fh: {fh}, datasync: {datasync})");
		reply.error(Errno::ENOSYS);
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
		warn!("[Not Implemented] access(ino: {ino:#x?}, mask: {mask})");
		reply.error(Errno::ENOSYS);
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
			Ok((new_inode, file_handle)) => reply.created(
				&ONE_SEC,
				&new_inode.to_file_attr(),
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
		state.total_bytes_limit = BLOCK_SIZE * 2 + 1;
		state.used_bytes = (BLOCK_SIZE as u64) + 1;

		let statfs = FileSystem::statfs_data(&state);
		assert_eq!(statfs.blocks, 3);
		assert_eq!(statfs.bfree, 1);
		assert_eq!(statfs.bavail, 1);
	}

	#[test]
	fn statfs_data_saturates_free_counts() {
		let fs = FileSystem::new();
		let mut state = fs.state.write();
		state.total_bytes_limit = BLOCK_SIZE;
		state.used_bytes = (BLOCK_SIZE as u64) * 3;
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
		let inode = {
			let mut state = fs.state.write();
			let (inode, fh) = state
				.op_create(INodeNo(1), OsStr::new("file"), 0o644, 0, 1000, 1000)
				.expect("create should succeed");
			state.op_write(inode.ino, fh, 0, b"abc").expect("write should succeed");
			state
				.op_unlink(INodeNo(1), OsStr::new("file"))
				.expect("unlink should succeed");
			assert!(state.op_getattr(inode.ino).is_ok());
			state.op_release(fh);
			inode
		};
		let state = fs.state.read();
		assert_eq!(
			state
				.op_getattr(inode.ino)
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
		let (inode, fh) = state
			.op_create(INodeNo(1), OsStr::new("growshrink"), 0o644, 0, 1000, 1000)
			.expect("create should succeed");
		state.op_release(fh);

		state.op_setattr_size(inode.ino, 10).expect("grow should succeed");
		assert_eq!(state.used_bytes, 10);

		state.op_setattr_size(inode.ino, 3).expect("shrink should succeed");
		assert_eq!(state.used_bytes, 3);
		assert!(state.check_invariants().is_ok());
	}

	#[test]
	fn rmdir_rejects_non_empty_directory() {
		let fs = FileSystem::new();
		let mut state = fs.state.write();
		let dir = state
			.op_mkdir(INodeNo(1), OsStr::new("dir"), 0o755, 0, 1000, 1000)
			.expect("mkdir should succeed");
		let (_file, fh) = state
			.op_create(dir.ino, OsStr::new("child"), 0o644, 0, 1000, 1000)
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
		let (inode, fh) = state
			.op_create(INodeNo(1), OsStr::new("offset"), 0o644, 0, 1000, 1000)
			.expect("create should succeed");
		let err = state
			.op_write(inode.ino, fh, u64::MAX, b"x")
			.expect_err("write should fail with huge offset");
		assert_eq!(i32::from(err), i32::from(Errno::EFBIG));
		assert!(state.check_invariants().is_ok());
	}

	#[test]
	fn freed_inode_is_reused_without_collision() {
		let fs = FileSystem::new();
		let mut state = fs.state.write();
		let (first, fh_first) = state
			.op_create(INodeNo(1), OsStr::new("first"), 0o644, 0, 1000, 1000)
			.expect("first create should succeed");
		state.op_release(fh_first);
		state
			.op_unlink(INodeNo(1), OsStr::new("first"))
			.expect("unlink should succeed");

		let (second, fh_second) = state
			.op_create(INodeNo(1), OsStr::new("second"), 0o644, 0, 1000, 1000)
			.expect("second create should succeed");
		state.op_release(fh_second);

		assert_eq!(first.ino, second.ino);
		assert!(state.check_invariants().is_ok());
	}
}
