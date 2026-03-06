#![no_main]

use std::{
	collections::{BTreeMap, HashMap},
	ffi::OsString,
	os::unix::ffi::OsStringExt,
	time::UNIX_EPOCH,
};

use arbitrary::Arbitrary;
use fuser::{FileType, INodeNo};
use jpegfs::{inode::Inode, pager::Pager};
use libfuzzer_sys::fuzz_target;

const MAX_OPS: usize = 512;
const MAX_PAGES: usize = 6;
const MAX_NAME_BYTES: usize = 96;
const MAX_WRITE_BYTES: usize = 512;

#[derive(Arbitrary, Debug)]
struct Program {
	ops: Vec<Op>,
}

#[derive(Arbitrary, Debug)]
enum Op {
	InodeInsert(FuzzInode),
	InodeRemove {
		ino: u64,
	},
	InodeRead {
		ino: u64,
	},
	InodeMutateSize {
		ino: u64,
		delta: u16,
	},
	DirInsert {
		inode: u64,
		name: Vec<u8>,
		child: u64,
	},
	DirRemove {
		inode: u64,
		name: Vec<u8>,
	},
	DirRead {
		inode: u64,
		name: Vec<u8>,
	},
	DirClear {
		inode: u64,
	},
	BytesWrite {
		inode: u64,
		offset: u16,
		data: Vec<u8>,
	},
	BytesRead {
		inode: u64,
		offset: u16,
		size: u16,
	},
	BytesTruncate {
		inode: u64,
		len: u16,
	},
	BytesRemove {
		inode: u64,
	},
}

#[derive(Arbitrary, Debug, Clone, Copy)]
struct FuzzInode {
	ino: u64,
	kind: u8,
	perm: u16,
	uid: u32,
	gid: u32,
	size: u64,
	nlink: u32,
}

fn to_file_type(raw: u8) -> FileType {
	match raw % 7 {
		0 => FileType::Directory,
		1 => FileType::RegularFile,
		2 => FileType::Symlink,
		3 => FileType::BlockDevice,
		4 => FileType::CharDevice,
		5 => FileType::NamedPipe,
		_ => FileType::Socket,
	}
}

fn to_inode(input: FuzzInode) -> Inode {
	let ts = UNIX_EPOCH;
	Inode {
		kind: to_file_type(input.kind),
		perm: input.perm,
		uid: input.uid,
		gid: input.gid,
		size: input.size,
		nlink: input.nlink,
		atime: ts,
		mtime: ts,
		ctime: ts,
		crtime: ts,
	}
}

fn as_name(bytes: &[u8]) -> OsString {
	let mut out = bytes[..bytes.len().min(MAX_NAME_BYTES)].to_vec();
	if out.is_empty() {
		out.push(b'x');
	}
	OsString::from_vec(out)
}

fn model_bytes_write(file: &mut Vec<u8>, offset: usize, data: &[u8]) {
	if data.is_empty() {
		return;
	}
	let end = offset.saturating_add(data.len());
	if file.len() < end {
		file.resize(end, 0);
	}
	file[offset..end].copy_from_slice(data);
}

fn check_consistency(
	pager: &Pager,
	inodes: &HashMap<INodeNo, Inode>,
	dirs: &HashMap<INodeNo, BTreeMap<OsString, INodeNo>>,
	files: &HashMap<INodeNo, Vec<u8>>,
) {
	assert_eq!(pager.inodes_len(), inodes.len());
	assert!(pager.page_count() <= MAX_PAGES);

	for (ino, expected) in inodes {
		assert!(pager.inodes_contains(*ino));
		let got = pager.inode_get(*ino).expect("model inode must exist in pager");
		assert_eq!(*got, *expected);
	}

	for (ino, entries) in dirs {
		for (name, child) in entries {
			assert_eq!(pager.dir_entries_get(*ino, name.as_os_str()), Some(*child));
		}
		let pager_dir = pager.dir_entries_get_dir(*ino).unwrap_or_default();
		assert_eq!(pager_dir, *entries);
	}

	for (ino, bytes) in files {
		assert_eq!(pager.bytes_len(*ino), bytes.len());
		assert_eq!(pager.bytes_read(*ino, 0, bytes.len().saturating_add(8)), *bytes);
	}
}

fuzz_target!(|program: Program| {
	let mut pager = Pager::new(MAX_PAGES);
	let mut inode_model: HashMap<INodeNo, Inode> = HashMap::new();
	let mut dir_model: HashMap<INodeNo, BTreeMap<OsString, INodeNo>> = HashMap::new();
	let mut bytes_model: HashMap<INodeNo, Vec<u8>> = HashMap::new();

	for op in program.ops.into_iter().take(MAX_OPS) {
		match op {
			Op::InodeInsert(raw) => {
				let inode = to_inode(raw);
				let ino = INodeNo(raw.ino);
				let existed = inode_model.contains_key(&ino);
				let before_len = inode_model.len();

				match pager.inodes_insert(ino, inode) {
					Ok(()) => {
						inode_model.insert(ino, inode);
						if existed {
							assert_eq!(inode_model.len(), before_len);
						}
					}
					Err(()) => {
						assert!(!existed);
						assert_eq!(inode_model.len(), before_len);
					}
				}
			}
			Op::InodeRemove { ino } => {
				let ino = INodeNo(ino);
				let expected = inode_model.remove(&ino);
				let got = pager.inode_remove(ino);
				assert_eq!(got, expected);
			}
			Op::InodeRead { ino } => {
				let ino = INodeNo(ino);
				let expected = inode_model.get(&ino);
				let got = pager.inode_get(ino);
				assert_eq!(got, expected);
			}
			Op::InodeMutateSize { ino, delta } => {
				let ino = INodeNo(ino);
				let expected = inode_model.get_mut(&ino);
				let got = pager.inode_get_mut(ino);

				match (got, expected) {
					(Some(got_inode), Some(expected_inode)) => {
						let next = expected_inode.size.wrapping_add(u64::from(delta));
						expected_inode.size = next;
						got_inode.size = next;
					}
					(None, None) => {}
					(got, expected) => panic!("mutate mismatch for {ino:?}: pager={got:?} model={expected:?}"),
				}
			}
			Op::DirInsert { inode, name, child } => {
				let ino = INodeNo(inode);
				let name = as_name(&name);
				let child = INodeNo(child);
				if pager.dir_entries_insert(ino, name.clone(), child).is_ok() {
					dir_model.entry(ino).or_default().insert(name, child);
				}
			}
			Op::DirRemove { inode, name } => {
				let ino = INodeNo(inode);
				let name = as_name(&name);
				let got = pager.dir_entries_remove(ino, name.as_os_str());
				let expected = dir_model.get_mut(&ino).and_then(|entries| entries.remove(name.as_os_str()));
				if dir_model.get(&ino).is_some_and(BTreeMap::is_empty) {
					dir_model.remove(&ino);
				}
				assert_eq!(got, expected);
			}
			Op::DirRead { inode, name } => {
				let ino = INodeNo(inode);
				let name = as_name(&name);
				let got = pager.dir_entries_get(ino, name.as_os_str());
				let expected = dir_model.get(&ino).and_then(|entries| entries.get(name.as_os_str())).copied();
				assert_eq!(got, expected);
			}
			Op::DirClear { inode } => {
				let ino = INodeNo(inode);
				pager.dir_entries_clear(ino);
				dir_model.remove(&ino);
			}
			Op::BytesWrite { inode, offset, data } => {
				let ino = INodeNo(inode);
				let offset = usize::from(offset);
				let payload_len = data.len().min(MAX_WRITE_BYTES);
				let payload = &data[..payload_len];
				if pager.bytes_write(ino, offset, payload).is_ok() {
					let file = bytes_model.entry(ino).or_default();
					model_bytes_write(file, offset, payload);
				}
			}
			Op::BytesRead { inode, offset, size } => {
				let ino = INodeNo(inode);
				let offset = usize::from(offset);
				let size = usize::from(size);
				let got = pager.bytes_read(ino, offset, size);
				let expected = bytes_model
					.get(&ino)
					.map(|file| {
						if offset >= file.len() {
							Vec::new()
						} else {
							let end = offset.saturating_add(size).min(file.len());
							file[offset..end].to_vec()
						}
					})
					.unwrap_or_default();
				assert_eq!(got, expected);
			}
			Op::BytesTruncate { inode, len } => {
				let ino = INodeNo(inode);
				let len = usize::from(len);
				if pager.bytes_truncate(ino, len).is_ok() {
					let file = bytes_model.entry(ino).or_default();
					file.resize(len, 0);
				}
			}
			Op::BytesRemove { inode } => {
				let ino = INodeNo(inode);
				pager.bytes_remove(ino);
				bytes_model.remove(&ino);
			}
		}

		check_consistency(&pager, &inode_model, &dir_model, &bytes_model);
	}

	let encoded = pager.encode_blocks().expect("encoding pager blocks should succeed");
	pager = Pager::decode_blocks(&encoded, MAX_PAGES).expect("decoding pager blocks should succeed");
	check_consistency(&pager, &inode_model, &dir_model, &bytes_model);
});
