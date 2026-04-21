use std::num::NonZeroU64;

/// Platform-appropriate inode number type.
/// On Unix this re-exports `fuser::INodeNo`
/// On other platforms a `NonZeroU64` newtype is used instead
/// so the rest of the library can compile without fuser
#[cfg(unix)]
pub use fuser::INodeNo;

#[cfg(not(unix))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Serialize, serde::Deserialize)]
pub struct INodeNo(pub NonZeroU64);

#[cfg(not(unix))]
impl INodeNo {
	pub const ROOT: Self = Self(NonZeroU64::MIN);
}

#[cfg(unix)]
#[inline]
pub(crate) fn ino_from_u64(n: u64) -> INodeNo {
	INodeNo(n)
}

#[cfg(not(unix))]
#[inline]
pub(crate) fn ino_from_u64(n: u64) -> INodeNo {
	INodeNo(NonZeroU64::new(n).expect("inode number must be nonzero"))
}

#[cfg(unix)]
#[inline]
pub(crate) fn ino_to_u64(ino: INodeNo) -> u64 {
	ino.0
}

#[cfg(not(unix))]
#[inline]
pub(crate) fn ino_to_u64(ino: INodeNo) -> u64 {
	ino.0.get()
}

#[cfg(unix)]
#[inline]
pub(crate) fn ino_to_nonzero(ino: INodeNo) -> NonZeroU64 {
	NonZeroU64::new(ino.0).expect("pager owner inode must be nonzero")
}

#[cfg(not(unix))]
#[inline]
pub(crate) fn ino_to_nonzero(ino: INodeNo) -> NonZeroU64 {
	ino.0
}

#[cfg(unix)]
#[inline]
pub(crate) fn ino_from_nonzero(nz: NonZeroU64) -> INodeNo {
	INodeNo(nz.get())
}

#[cfg(not(unix))]
#[inline]
pub(crate) fn ino_from_nonzero(nz: NonZeroU64) -> INodeNo {
	INodeNo(nz)
}
