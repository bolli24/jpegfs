#![no_main]

use std::{ffi::OsString, os::unix::ffi::OsStringExt};

use arbitrary::Arbitrary;
use fuser::{FileHandle, INodeNo};
use jpegfs::filesystem::{FileSystem, MAX_FILE_SIZE};
use libfuzzer_sys::fuzz_target;

const MAX_OPS: usize = 256;
const MAX_NAME_BYTES: usize = 96;
const MAX_WRITE_BYTES: usize = 2048;

#[derive(Arbitrary, Debug)]
struct Program {
	ops: Vec<Op>,
}

#[derive(Arbitrary, Debug)]
enum Op {
	Mkdir {
		parent_slot: u16,
		name: Vec<u8>,
		mode: u16,
		umask: u16,
	},
	Create {
		parent_slot: u16,
		name: Vec<u8>,
		mode: u16,
		umask: u16,
	},
	Open {
		inode_slot: u16,
	},
	Write {
		inode_slot: u16,
		fh_slot: u16,
		offset: u32,
		data: Vec<u8>,
	},
	Read {
		inode_slot: u16,
		fh_slot: u16,
		offset: u32,
		size: u16,
	},
	Release {
		fh_slot: u16,
	},
	Unlink {
		parent_slot: u16,
		name: Vec<u8>,
	},
	Rmdir {
		parent_slot: u16,
		name: Vec<u8>,
	},
	SetattrSize {
		inode_slot: u16,
		size: u32,
	},
	Readdir {
		inode_slot: u16,
		offset: u16,
	},
	Getattr {
		inode_slot: u16,
	},
	Statfs,
}

fn pick<T: Copy>(items: &[T], slot: u16) -> Option<T> {
	if items.is_empty() {
		return None;
	}
	Some(items[usize::from(slot) % items.len()])
}

fn fuzz_name(bytes: &[u8]) -> OsString {
	let mut name = bytes[..bytes.len().min(MAX_NAME_BYTES)].to_vec();
	if name.is_empty() {
		name.push(b'x');
	}
	OsString::from_vec(name)
}

fn refresh_pools(fs: &FileSystem, inodes: &mut Vec<INodeNo>, handles: &mut Vec<FileHandle>) {
	let state = fs.state.read();
	inodes.clear();
	handles.clear();
	inodes.extend(state.inodes.keys().copied());
	handles.extend(state.handles.keys().copied());
}

fuzz_target!(|program: Program| {
	let fs = FileSystem::new();
	let mut inodes = vec![INodeNo(1)];
	let mut handles = Vec::new();

	for op in program.ops.iter().take(MAX_OPS) {
		match op {
			Op::Mkdir {
				parent_slot,
				name,
				mode,
				umask,
			} => {
				if let Some(parent) = pick(&inodes, *parent_slot) {
					let _ = fs.op_mkdir(
						parent,
						&fuzz_name(name),
						u32::from(*mode),
						u32::from(*umask),
						1000,
						1000,
					);
				}
			}
			Op::Create {
				parent_slot,
				name,
				mode,
				umask,
			} => {
				if let Some(parent) = pick(&inodes, *parent_slot) {
					let _ = fs.op_create(
						parent,
						&fuzz_name(name),
						u32::from(*mode),
						u32::from(*umask),
						1000,
						1000,
					);
				}
			}
			Op::Open { inode_slot } => {
				if let Some(ino) = pick(&inodes, *inode_slot) {
					let _ = fs.op_open(ino);
				}
			}
			Op::Write {
				inode_slot,
				fh_slot,
				offset,
				data,
			} => {
				if let (Some(ino), Some(fh)) = (pick(&inodes, *inode_slot), pick(&handles, *fh_slot)) {
					let payload_len = data.len().min(MAX_WRITE_BYTES);
					let _ = fs.op_write(ino, fh, u64::from(*offset), &data[..payload_len]);
				}
			}
			Op::Read {
				inode_slot,
				fh_slot,
				offset,
				size,
			} => {
				if let (Some(ino), Some(fh)) = (pick(&inodes, *inode_slot), pick(&handles, *fh_slot)) {
					let _ = fs.op_read(ino, fh, u64::from(*offset), u32::from(*size));
				}
			}
			Op::Release { fh_slot } => {
				if let Some(fh) = pick(&handles, *fh_slot) {
					fs.op_release(fh);
				}
			}
			Op::Unlink { parent_slot, name } => {
				if let Some(parent) = pick(&inodes, *parent_slot) {
					let _ = fs.op_unlink(parent, &fuzz_name(name));
				}
			}
			Op::Rmdir { parent_slot, name } => {
				if let Some(parent) = pick(&inodes, *parent_slot) {
					let _ = fs.op_rmdir(parent, &fuzz_name(name));
				}
			}
			Op::SetattrSize { inode_slot, size } => {
				if let Some(ino) = pick(&inodes, *inode_slot) {
					let max = (MAX_FILE_SIZE as u64) + 1024;
					let requested = u64::from(*size) % max;
					let _ = fs.op_setattr_size(ino, requested);
				}
			}
			Op::Readdir { inode_slot, offset } => {
				if let Some(ino) = pick(&inodes, *inode_slot) {
					let _ = fs.op_readdir(ino, u64::from(*offset));
				}
			}
			Op::Getattr { inode_slot } => {
				if let Some(ino) = pick(&inodes, *inode_slot) {
					let _ = fs.op_getattr(ino);
				}
			}
			Op::Statfs => {
				let _ = fs.op_statfs();
			}
		}

		if let Err(msg) = fs.check_invariants() {
			panic!("invariant violation after {op:?}: {msg}");
		}

		refresh_pools(&fs, &mut inodes, &mut handles);
	}
});
