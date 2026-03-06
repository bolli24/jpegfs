#![no_main]

use std::{collections::HashMap, time::UNIX_EPOCH};

use arbitrary::Arbitrary;
use fuser::{FileType, INodeNo};
use jpegfs::{inode::Inode, pager::Pager};
use libfuzzer_sys::fuzz_target;

const MAX_OPS: usize = 512;
const MAX_PAGES: usize = 3;

#[derive(Arbitrary, Debug)]
struct Program {
	ops: Vec<Op>,
}

#[derive(Arbitrary, Debug)]
enum Op {
	Insert(FuzzInode),
	Remove { ino: u64 },
	Read { ino: u64 },
	MutateSize { ino: u64, delta: u16 },
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

fn check_consistency(pager: &Pager, model: &HashMap<INodeNo, Inode>) {
	assert_eq!(pager.inodes_len(), model.len());
	assert!(pager.page_count() <= MAX_PAGES);

	for (ino, expected) in model {
		assert!(pager.inodes_contains(*ino));
		let got = pager.inode_get(*ino).expect("model inode must exist in pager");
		assert_eq!(*got, *expected);
	}
}

fuzz_target!(|program: Program| {
	let mut pager = Pager::new(MAX_PAGES);
	let mut model: HashMap<INodeNo, Inode> = HashMap::new();

	for op in program.ops.into_iter().take(MAX_OPS) {
		match op {
			Op::Insert(raw) => {
				let inode = to_inode(raw);
				let ino = INodeNo(raw.ino);
				let existed = model.contains_key(&ino);
				let before_len = model.len();

				match pager.inodes_insert(ino, inode) {
					Ok(()) => {
						model.insert(ino, inode);
						if existed {
							assert_eq!(model.len(), before_len);
						}
					}
					Err(()) => {
						assert!(!existed);
						assert_eq!(model.len(), before_len);
					}
				}
			}
			Op::Remove { ino } => {
				let ino = INodeNo(ino);
				let expected = model.remove(&ino);
				let got = pager.inode_remove(ino);
				assert_eq!(got, expected);
			}
			Op::Read { ino } => {
				let ino = INodeNo(ino);
				let expected = model.get(&ino);
				let got = pager.inode_get(ino);
				assert_eq!(got, expected);
			}
			Op::MutateSize { ino, delta } => {
				let ino = INodeNo(ino);
				let expected = model.get_mut(&ino);
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
		}

		check_consistency(&pager, &model);
	}
});
