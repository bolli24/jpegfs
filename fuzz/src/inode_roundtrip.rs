#![no_main]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arbitrary::Arbitrary;
use fuser::{FileType, INodeNo};
use jpegfs::inode::{Inode, InodeRaw};
use libfuzzer_sys::fuzz_target;
use zerocopy::{IntoBytes, TryFromBytes};

const MAX_INODES: usize = 256;
const MAX_RAW_INPUTS: usize = 256;
const MAX_RAW_BYTES: usize = 256;

#[derive(Arbitrary, Debug)]
struct Program {
	inodes: Vec<FuzzInode>,
	raw_inputs: Vec<Vec<u8>>,
}

#[derive(Arbitrary, Debug)]
struct FuzzInode {
	ino: u64,
	kind: u8,
	perm: u16,
	uid: u32,
	gid: u32,
	size: u64,
	nlink: u32,
	atime_sec: i64,
	atime_nsec: u32,
	mtime_sec: i64,
	mtime_nsec: u32,
	ctime_sec: i64,
	ctime_nsec: u32,
	crtime_sec: i64,
	crtime_nsec: u32,
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

fn to_system_time(seconds: i64, nanos: u32) -> Option<SystemTime> {
	if nanos >= 1_000_000_000 {
		return None;
	}

	if seconds >= 0 {
		return Some(UNIX_EPOCH + Duration::from_secs(seconds as u64) + Duration::from_nanos(u64::from(nanos)));
	}

	let abs = seconds.unsigned_abs();
	let duration = if nanos == 0 {
		Duration::from_secs(abs)
	} else {
		Duration::from_secs(abs.saturating_sub(1)) + Duration::from_nanos(u64::from(1_000_000_000 - nanos))
	};
	UNIX_EPOCH.checked_sub(duration)
}

fn build_inode(input: FuzzInode) -> Option<Inode> {
	Some(Inode {
		kind: to_file_type(input.kind),
		perm: input.perm,
		uid: input.uid,
		gid: input.gid,
		size: input.size,
		nlink: input.nlink,
		atime: to_system_time(input.atime_sec, input.atime_nsec)?,
		mtime: to_system_time(input.mtime_sec, input.mtime_nsec)?,
		ctime: to_system_time(input.ctime_sec, input.ctime_nsec)?,
		crtime: to_system_time(input.crtime_sec, input.crtime_nsec)?,
	})
}

fuzz_target!(|program: Program| {
	for input in program.inodes.into_iter().take(MAX_INODES) {
		let ino = INodeNo(input.ino);
		let Some(inode) = build_inode(input) else {
			continue;
		};

		let raw = InodeRaw::from_parts(ino, &inode).expect("Inode -> InodeRaw conversion should succeed");
		let (restored_ino, restored) = raw.into_parts().expect("InodeRaw -> Inode conversion should succeed");
		assert_eq!(restored_ino, ino);
		assert_eq!(restored, inode);

		let raw_from_bytes = InodeRaw::try_read_from_bytes(raw.as_bytes()).expect("valid InodeRaw bytes should decode");
		let (ino_from_bytes, inode_from_bytes) = raw_from_bytes.into_parts().expect("decoded raw inode should convert");
		assert_eq!(ino_from_bytes, ino);
		assert_eq!(inode_from_bytes, inode);
	}

	for mut bytes in program.raw_inputs.into_iter().take(MAX_RAW_INPUTS) {
		bytes.truncate(MAX_RAW_BYTES);
		if let Ok(raw) = InodeRaw::try_read_from_bytes(&bytes) {
			if let Ok((ino, inode)) = raw.into_parts() {
				let raw2 = InodeRaw::from_parts(ino, &inode).expect("re-encoding decoded inode should succeed");
				let (_ino2, inode2) = raw2.into_parts().expect("decoded inode should stay valid");
				assert_eq!(inode2, inode);
			}
		}
	}
});
