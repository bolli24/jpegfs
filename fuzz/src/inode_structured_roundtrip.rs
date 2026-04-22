#![no_main]

use arbitrary::Arbitrary;
use fuser::INodeNo;
use jpegfs::inode::{FileType, Inode, InodeKindRaw, InodeRaw};
use libfuzzer_sys::fuzz_target;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zerocopy::{IntoBytes, TryFromBytes};

#[derive(Arbitrary, Debug)]
struct FuzzInode {
	ino: u64,
	kind: InodeKindRaw,
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

fn expected_file_type(kind: InodeKindRaw) -> FileType {
	match kind {
		InodeKindRaw::Directory => FileType::Directory,
		InodeKindRaw::Regular => FileType::RegularFile,
		InodeKindRaw::Symlink => FileType::Symlink,
		InodeKindRaw::BlockDevice => FileType::BlockDevice,
		InodeKindRaw::CharDevice => FileType::CharDevice,
		InodeKindRaw::NamedPipe => FileType::NamedPipe,
		InodeKindRaw::Socket => FileType::Socket,
	}
}

fn expected_system_time(seconds: i64, nanos: u32) -> Option<SystemTime> {
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

fn build_inode(input: FuzzInode) -> Option<(INodeNo, Inode)> {
	Some((
		INodeNo(input.ino),
		Inode {
			kind: expected_file_type(input.kind),
			perm: input.perm,
			uid: input.uid,
			gid: input.gid,
			size: input.size,
			nlink: input.nlink,
			atime: expected_system_time(input.atime_sec, input.atime_nsec)?,
			mtime: expected_system_time(input.mtime_sec, input.mtime_nsec)?,
			ctime: expected_system_time(input.ctime_sec, input.ctime_nsec)?,
			crtime: expected_system_time(input.crtime_sec, input.crtime_nsec)?,
		},
	))
}

fuzz_target!(|input: FuzzInode| {
	let Some((ino, inode)) = build_inode(input) else {
		return;
	};

	let raw = InodeRaw::from_parts(ino, &inode).expect("Inode -> InodeRaw conversion should succeed");
	let (restored_ino, restored) = raw.into_parts().expect("InodeRaw -> Inode conversion should succeed");
	assert_eq!(restored_ino, ino);
	assert_eq!(restored, inode);

	let raw_from_bytes = InodeRaw::try_read_from_bytes(raw.as_bytes()).expect("valid InodeRaw bytes should decode");
	let (ino_from_bytes, inode_from_bytes) = raw_from_bytes.into_parts().expect("decoded raw inode should convert");
	assert_eq!(ino_from_bytes, ino);
	assert_eq!(inode_from_bytes, inode);
});
