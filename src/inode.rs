use crate::ino::{self, INodeNo};
use arbitrary::Arbitrary;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum FileType {
	NamedPipe,
	CharDevice,
	BlockDevice,
	Directory,
	RegularFile,
	Symlink,
	Socket,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Inode {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InodeConversionError {
	#[error("timestamp conversion failed for seconds={seconds} nanos={nanos}")]
	InvalidTimestamp { seconds: i64, nanos: u32 },
	#[error("timestamp seconds out of range: {0}")]
	SecondsOutOfRange(u64),
}

#[derive(TryFromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct InodeRaw {
	pub ino: u64,
	pub size: u64,
	pub atime_sec: i64,
	pub mtime_sec: i64,
	pub ctime_sec: i64,
	pub crtime_sec: i64,
	pub uid: u32,
	pub gid: u32,
	pub nlink: u32,
	pub atime_nsec: u32,
	pub mtime_nsec: u32,
	pub ctime_nsec: u32,
	pub crtime_nsec: u32,
	pub perm: u16,
	pub kind: InodeKindRaw,
	pub _reserved0: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromBytes, IntoBytes, KnownLayout, Immutable, Arbitrary)]
#[repr(u8)]
pub enum InodeKindRaw {
	Directory = 1,
	Regular = 2,
	Symlink = 3,
	BlockDevice = 4,
	CharDevice = 5,
	NamedPipe = 6,
	Socket = 7,
}

fn encode_file_type(kind: FileType) -> InodeKindRaw {
	match kind {
		FileType::Directory => InodeKindRaw::Directory,
		FileType::RegularFile => InodeKindRaw::Regular,
		FileType::Symlink => InodeKindRaw::Symlink,
		FileType::BlockDevice => InodeKindRaw::BlockDevice,
		FileType::CharDevice => InodeKindRaw::CharDevice,
		FileType::NamedPipe => InodeKindRaw::NamedPipe,
		FileType::Socket => InodeKindRaw::Socket,
	}
}

pub fn decode_file_type(kind: InodeKindRaw) -> FileType {
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

fn encode_system_time(ts: SystemTime) -> Result<(i64, u32), InodeConversionError> {
	match ts.duration_since(UNIX_EPOCH) {
		Ok(duration) => {
			let secs = i64::try_from(duration.as_secs())
				.map_err(|_| InodeConversionError::SecondsOutOfRange(duration.as_secs()))?;
			Ok((secs, duration.subsec_nanos()))
		}
		Err(error) => {
			let duration = error.duration();
			let nanos = duration.subsec_nanos();
			if nanos == 0 {
				if duration.as_secs() == (i64::MAX as u64) + 1 {
					Ok((i64::MIN, 0))
				} else {
					let secs = i64::try_from(duration.as_secs())
						.map_err(|_| InodeConversionError::SecondsOutOfRange(duration.as_secs()))?;
					Ok((-secs, 0))
				}
			} else {
				let secs = i64::try_from(duration.as_secs())
					.map_err(|_| InodeConversionError::SecondsOutOfRange(duration.as_secs()))?;
				let encoded_secs = if secs == i64::MAX { i64::MIN } else { -(secs + 1) };
				Ok((encoded_secs, 1_000_000_000 - nanos))
			}
		}
	}
}

pub fn decode_system_time(seconds: i64, nanos: u32) -> Result<SystemTime, InodeConversionError> {
	if nanos >= 1_000_000_000 {
		return Err(InodeConversionError::InvalidTimestamp { seconds, nanos });
	}

	if seconds >= 0 {
		return Ok(UNIX_EPOCH + Duration::from_secs(seconds as u64) + Duration::from_nanos(u64::from(nanos)));
	}

	let abs = seconds.unsigned_abs();
	let duration = if nanos == 0 {
		Duration::from_secs(abs)
	} else {
		Duration::from_secs(abs.saturating_sub(1)) + Duration::from_nanos(u64::from(1_000_000_000 - nanos))
	};
	UNIX_EPOCH
		.checked_sub(duration)
		.ok_or(InodeConversionError::InvalidTimestamp { seconds, nanos })
}

impl InodeRaw {
	pub fn from_parts(ino: INodeNo, inode: &Inode) -> Result<Self, InodeConversionError> {
		let (atime_sec, atime_nsec) = encode_system_time(inode.atime)?;
		let (mtime_sec, mtime_nsec) = encode_system_time(inode.mtime)?;
		let (ctime_sec, ctime_nsec) = encode_system_time(inode.ctime)?;
		let (crtime_sec, crtime_nsec) = encode_system_time(inode.crtime)?;

		Ok(Self {
			ino: ino::ino_to_u64(ino),
			size: inode.size,
			atime_sec,
			mtime_sec,
			ctime_sec,
			crtime_sec,
			uid: inode.uid,
			gid: inode.gid,
			nlink: inode.nlink,
			atime_nsec,
			mtime_nsec,
			ctime_nsec,
			crtime_nsec,
			perm: inode.perm,
			kind: encode_file_type(inode.kind),
			_reserved0: 0,
		})
	}

	pub fn into_parts(&self) -> Result<(INodeNo, Inode), InodeConversionError> {
		Ok((
			ino::ino_from_u64(self.ino),
			Inode {
				kind: decode_file_type(self.kind),
				perm: self.perm,
				uid: self.uid,
				gid: self.gid,
				size: self.size,
				nlink: self.nlink,
				atime: decode_system_time(self.atime_sec, self.atime_nsec)?,
				mtime: decode_system_time(self.mtime_sec, self.mtime_nsec)?,
				ctime: decode_system_time(self.ctime_sec, self.ctime_nsec)?,
				crtime: decode_system_time(self.crtime_sec, self.crtime_nsec)?,
			},
		))
	}
}

#[cfg(all(test, unix))]
mod tests {
	use super::*;
	use crate::ino::ino_from_u64;

	#[test]
	fn inode_raw_roundtrip_preserves_inode_fields() {
		let inode = Inode {
			kind: FileType::RegularFile,
			perm: 0o644,
			uid: 1000,
			gid: 1000,
			size: 12345,
			nlink: 2,
			atime: UNIX_EPOCH + Duration::from_secs(1),
			mtime: UNIX_EPOCH + Duration::from_secs(1000) + Duration::from_nanos(123),
			ctime: UNIX_EPOCH + Duration::from_secs(9000),
			crtime: UNIX_EPOCH + Duration::from_secs(99_999),
		};
		let ino = ino_from_u64(42);

		let raw = InodeRaw::from_parts(ino, &inode).expect("inode -> raw conversion should succeed");
		let (restored_ino, restored) = raw.into_parts().expect("raw -> inode conversion should succeed");

		assert_eq!(restored_ino, ino);
		assert_eq!(restored, inode);
	}

	#[test]
	fn inode_raw_roundtrip_preserves_pre_epoch_timestamp() {
		let inode = Inode {
			kind: FileType::Directory,
			perm: 0o755,
			uid: 0,
			gid: 0,
			size: 0,
			nlink: 1,
			atime: UNIX_EPOCH - Duration::from_nanos(1),
			mtime: UNIX_EPOCH - Duration::from_secs(1),
			ctime: UNIX_EPOCH,
			crtime: UNIX_EPOCH + Duration::from_secs(5),
		};
		let ino = ino_from_u64(43);

		let raw = InodeRaw::from_parts(ino, &inode).expect("inode -> raw conversion should succeed");
		let (restored_ino, restored) = raw.into_parts().expect("raw -> inode conversion should succeed");

		assert_eq!(restored_ino, ino);
		assert_eq!(restored, inode);
	}

	#[test]
	fn inode_raw_roundtrip_preserves_minimum_negative_second_timestamp() {
		let inode = Inode {
			kind: FileType::Directory,
			perm: 0o755,
			uid: 0,
			gid: 0,
			size: 0,
			nlink: 1,
			atime: UNIX_EPOCH
				.checked_sub(Duration::from_secs((i64::MAX as u64) + 1))
				.expect("minimum raw second should be representable"),
			mtime: UNIX_EPOCH - Duration::from_nanos(1),
			ctime: UNIX_EPOCH - Duration::from_secs(i64::MAX as u64),
			crtime: UNIX_EPOCH + Duration::from_secs(5),
		};
		let ino = ino_from_u64(44);

		let raw = InodeRaw::from_parts(ino, &inode).expect("inode -> raw conversion should succeed");
		assert_eq!(raw.atime_sec, i64::MIN);
		assert_eq!(raw.atime_nsec, 0);

		let (restored_ino, restored) = raw.into_parts().expect("raw -> inode conversion should succeed");
		assert_eq!(restored_ino, ino);
		assert_eq!(restored, inode);
	}

	#[test]
	fn invalid_timestamp_error_display_uses_pager_style() {
		assert_eq!(
			InodeConversionError::InvalidTimestamp {
				seconds: -1,
				nanos: 1_000_000_000,
			}
			.to_string(),
			"timestamp conversion failed for seconds=-1 nanos=1000000000"
		);
	}
}
