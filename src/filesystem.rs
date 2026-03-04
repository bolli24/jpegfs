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
pub const MAX_NAME_LEN: usize = 32;
pub const MAX_FILE_SIZE: usize = 4 * 1024 * 1024;
pub const TOTAL_BYTES_LIMIT: usize = 10 * 1024 * 1024;

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

/* Minimum:
	1. lookup   +
	2. getattr  +
	3. readdir  +
	4. mkdir    +
	5. rmdir    +
	6. create   +
	7. open     +
	8. release  +
	9. read     +
	10. write   +
	11. unlink  +
*/

const ONE_SEC: Duration = Duration::from_secs(1);

impl fuser::Filesystem for FileSystem {
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
		let Some(inode) = state.inodes.get(&ino) else {
			return reply.error(Errno::ENOENT);
		};

		reply.attr(&ONE_SEC, &inode.to_file_attr());
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

			let old_len = state.file_data.get(&ino).map_or(0usize, Vec::len);
			let new_len = size as usize;

			if new_len > old_len {
				let growth = new_len - old_len;
				let Some(new_used_bytes) = state.used_bytes.checked_add(growth as u64) else {
					return reply.error(Errno::ENOSPC);
				};
				if new_used_bytes > state.total_bytes_limit as u64 {
					return reply.error(Errno::ENOSPC);
				}
				state.used_bytes = new_used_bytes;
			} else {
				let shrink = old_len - new_len;
				state.used_bytes = state.used_bytes.saturating_sub(shrink as u64);
			}

			let entry = state.file_data.entry(ino).or_default();
			entry.resize(new_len, 0);

			let inode = state.inodes.get_mut(&ino).expect("validated inode must exist");
			inode.size = size;
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

		if name.as_bytes().len() > state.max_name_len {
			return reply.error(Errno::ENAMETOOLONG);
		}

		if !state.inodes.contains_key(&parent) {
			return reply.error(Errno::ENOENT);
		}

		let Some(parent_dir_view) = state.dirs.get(&parent) else {
			return reply.error(Errno::ENOTDIR);
		};

		if parent_dir_view.contains_key(name) {
			return reply.error(Errno::EEXIST);
		}

		let inode_count = state.inodes.len();
		let Some(new_ino) = Self::alloc_ino_with_count(&mut state, inode_count) else {
			return reply.error(Errno::ENOSPC);
		};

		let now = SystemTime::now();

		let new_inode = Inode {
			ino: new_ino,
			kind: FileType::Directory,
			perm: ((mode & 0o7777) & !umask) as u16,
			uid: req.uid(),
			gid: req.gid(),
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

		let parent_dir = state
			.dirs
			.get_mut(&parent)
			.expect("validated parent directory must exist");
		parent_dir.insert(name.to_owned(), new_ino);

		let parent_inode = state
			.inodes
			.get_mut(&parent)
			.expect("validated parent inode must exist");
		parent_inode.nlink += 1;
		parent_inode.mtime = now;
		parent_inode.ctime = now;

		state.dirs.insert(new_ino, dir_entries);
		state.inodes.insert(new_ino, new_inode);

		reply.entry(&ONE_SEC, &new_inode.to_file_attr(), Generation(0));
	}

	fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
		info!("unlink(parent={parent:?}, name={name:?})");
		if name == OsStr::new(".") || name == OsStr::new("..") {
			return reply.error(Errno::EINVAL);
		}

		let mut state = self.state.write();

		if !state.inodes.contains_key(&parent) {
			return reply.error(Errno::ENOENT);
		}

		let child_ino = {
			let Some(parent_dir_view) = state.dirs.get(&parent) else {
				return reply.error(Errno::ENOTDIR);
			};

			let Some(child_ino) = parent_dir_view.get(name) else {
				return reply.error(Errno::ENOENT);
			};

			*child_ino
		};

		let child_inode_view = invariant_or_eio!(
			state.inodes.get(&child_ino),
			reply,
			"directory entry points to missing inode during unlink: parent={parent:?}, name={name:?}, child={child_ino:?}"
		);
		if child_inode_view.kind == FileType::Directory {
			return reply.error(Errno::EISDIR);
		}

		let now = SystemTime::now();
		let parent_dir = state
			.dirs
			.get_mut(&parent)
			.expect("validated parent directory must exist");
		parent_dir.remove(name);

		let remove_inode = {
			let child_inode = state
				.inodes
				.get_mut(&child_ino)
				.expect("validated child inode must exist");
			if child_inode.nlink == 0 {
				return reply.error(Errno::EIO);
			}
			child_inode.nlink -= 1;
			child_inode.ctime = now;
			child_inode.nlink == 0
		};

		if remove_inode {
			Self::cleanup_unlinked_inode_if_releasable(&mut state, child_ino);
		}

		let parent_inode = state
			.inodes
			.get_mut(&parent)
			.expect("validated parent inode must exist");
		parent_inode.mtime = now;
		parent_inode.ctime = now;

		reply.ok();
	}

	fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
		info!("rmdir(parent={parent:?}, name={name:?})");
		if name == OsStr::new(".") || name == OsStr::new("..") {
			return reply.error(Errno::EINVAL);
		}

		let mut state = self.state.write();

		if !state.inodes.contains_key(&parent) {
			return reply.error(Errno::ENOENT);
		}

		let child_ino = {
			let Some(parent_dir_view) = state.dirs.get(&parent) else {
				return reply.error(Errno::ENOTDIR);
			};

			let Some(child_ino) = parent_dir_view.get(name) else {
				return reply.error(Errno::ENOENT);
			};

			*child_ino
		};

		if child_ino == INodeNo(1) {
			return reply.error(Errno::EBUSY);
		}

		let child_inode = invariant_or_eio!(
			state.inodes.get(&child_ino),
			reply,
			"directory entry points to missing inode during rmdir: parent={parent:?}, name={name:?}, child={child_ino:?}"
		);
		if child_inode.kind != FileType::Directory {
			return reply.error(Errno::ENOTDIR);
		}

		let child_is_empty = {
			let child_dir = invariant_or_eio!(
				state.dirs.get(&child_ino),
				reply,
				"directory inode missing entry map during rmdir: parent={parent:?}, name={name:?}, child={child_ino:?}"
			);
			child_dir.len() <= 2
		};
		if !child_is_empty {
			return reply.error(Errno::ENOTEMPTY);
		}

		let now = SystemTime::now();

		let parent_dir = state.dirs.get_mut(&parent).expect("validated parent dir must exist");
		parent_dir.remove(name);
		state.dirs.remove(&child_ino);

		state.inodes.remove(&child_ino);
		let parent_inode = state
			.inodes
			.get_mut(&parent)
			.expect("validated parent inode must exist");
		if parent_inode.nlink == 0 {
			return reply.error(Errno::EIO);
		}
		parent_inode.nlink -= 1;
		parent_inode.mtime = now;
		parent_inode.ctime = now;

		state.free_inos.push(child_ino);
		reply.ok();
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
		let Some(inode) = state.inodes.get(&ino) else {
			return reply.error(Errno::ENOENT);
		};
		if inode.kind == FileType::Directory {
			return reply.error(Errno::EISDIR);
		}

		let file_handle = FileHandle(state.next_fh);
		let Some(next_fh) = state.next_fh.checked_add(1) else {
			return reply.error(Errno::ENFILE);
		};
		state.next_fh = next_fh;
		state.handles.insert(file_handle, ino);

		reply.opened(file_handle, FopenFlags::empty());
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

		let Some(handle_ino) = state.handles.get(&fh) else {
			return reply.error(Errno::EBADF);
		};
		if *handle_ino != ino {
			return reply.error(Errno::EBADF);
		}

		let Some(inode) = state.inodes.get(&ino) else {
			return reply.error(Errno::ENOENT);
		};
		if inode.kind == FileType::Directory {
			return reply.error(Errno::EISDIR);
		}

		let data = state.file_data.entry(ino).or_default();
		let start = (offset as usize).min(data.len());
		let end = start.saturating_add(size as usize).min(data.len());
		let out = data[start..end].to_vec();

		let inode = state.inodes.get_mut(&ino).expect("validated inode must exist");
		inode.atime = SystemTime::now();
		reply.data(&out);
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

		let Some(handle_ino) = state.handles.get(&fh) else {
			return reply.error(Errno::EBADF);
		};
		if *handle_ino != ino {
			return reply.error(Errno::EBADF);
		}

		let Some(inode_view) = state.inodes.get(&ino) else {
			return reply.error(Errno::ENOENT);
		};
		if inode_view.kind == FileType::Directory {
			return reply.error(Errno::EISDIR);
		}

		let Ok(start) = usize::try_from(offset) else {
			return reply.error(Errno::EFBIG);
		};
		let Some(end) = start.checked_add(data.len()) else {
			return reply.error(Errno::EFBIG);
		};

		if end > state.max_file_size {
			return reply.error(Errno::EFBIG);
		}

		let current_len = state.file_data.get(&ino).map_or(0, Vec::len);
		let growth = end.saturating_sub(current_len);
		let new_used_bytes = match state.used_bytes.checked_add(growth as u64) {
			Some(v) => v,
			None => return reply.error(Errno::ENOSPC),
		};
		if new_used_bytes > state.total_bytes_limit as u64 {
			return reply.error(Errno::ENOSPC);
		}

		let new_file_len = {
			let file = state.file_data.entry(ino).or_default();
			if end > file.len() {
				file.resize(end, 0);
			}
			file[start..end].copy_from_slice(data);
			file.len()
		};

		state.used_bytes = new_used_bytes;

		let now = SystemTime::now();
		let inode = state.inodes.get_mut(&ino).expect("validated inode must exist");
		inode.size = new_file_len as u64;
		inode.mtime = now;
		inode.ctime = now;

		reply.written(data.len() as u32);
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
		if let Some(ino) = state.handles.remove(&fh) {
			Self::cleanup_unlinked_inode_if_releasable(&mut state, ino);
		}
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
		if !state.inodes.contains_key(&ino) {
			return reply.error(Errno::ENOENT);
		}

		let Some(dir) = state.dirs.get(&ino) else {
			return reply.error(Errno::ENOTDIR);
		};

		for (i, (name, entry)) in dir.iter().enumerate().skip(offset as usize) {
			let inode = invariant_or_eio!(
				state.inodes.get(entry),
				reply,
				"directory entry points to missing inode: parent={ino:?}, name={name:?}, child={entry:?}"
			);

			if reply.add(*entry, i as u64 + 1, inode.kind, name) {
				break;
			}
		}

		reply.ok();
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
		reply.statfs(0, 0, 0, 0, 0, 512, 255, 0);
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

		if name.as_bytes().len() > state.max_name_len {
			return reply.error(Errno::ENAMETOOLONG);
		}

		if !state.inodes.contains_key(&parent) {
			return reply.error(Errno::ENOENT);
		}

		let Some(parent_dir_view) = state.dirs.get(&parent) else {
			return reply.error(Errno::ENOTDIR);
		};

		if parent_dir_view.contains_key(name) {
			return reply.error(Errno::EEXIST);
		}

		let inode_count = state.inodes.len();
		let Some(new_ino) = Self::alloc_ino_with_count(&mut state, inode_count) else {
			return reply.error(Errno::ENOSPC);
		};

		let now = SystemTime::now();

		let new_inode = Inode {
			ino: new_ino,
			kind: FileType::RegularFile,
			perm: ((mode & 0o7777) & !umask) as u16,
			uid: req.uid(),
			gid: req.gid(),
			size: 0,
			nlink: 1,
			atime: now,
			mtime: now,
			ctime: now,
			crtime: now,
		};

		let parent_dir = state
			.dirs
			.get_mut(&parent)
			.expect("validated parent directory must exist");
		parent_dir.insert(name.to_owned(), new_ino);

		state.inodes.insert(new_ino, new_inode);
		state.file_data.insert(new_ino, Vec::new());

		let file_handle = FileHandle(state.next_fh);
		let Some(next_fh) = state.next_fh.checked_add(1) else {
			return reply.error(Errno::ENFILE);
		};
		state.next_fh = next_fh;
		state.handles.insert(file_handle, new_ino);

		let parent_inode = state
			.inodes
			.get_mut(&parent)
			.expect("validated parent inode must exist");
		parent_inode.mtime = now;
		parent_inode.ctime = now;

		reply.created(
			&ONE_SEC,
			&new_inode.to_file_attr(),
			Generation(0),
			file_handle,
			FopenFlags::empty(),
		);
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
