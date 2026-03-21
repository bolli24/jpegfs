use crate::inode::InodeConversionError;
use crate::pager::{PageId, PageType};
use crate::store::Error as StoreError;
use fuser::{Errno, INodeNo};
use std::ffi::OsString;

#[derive(Debug, thiserror::Error)]
pub enum PagerCodecError {
	#[error("unable to read header from bytes: {0:?}")]
	HeaderDecodeError(Vec<u8>),
	#[error("invalid magic: {0:?}")]
	InvalidMagic([u8; 4]),
	#[error("unsupported version: {0}")]
	UnsupportedVersion(u16),
	#[error("reserved header field is non-zero: {0}")]
	ReservedFieldNonZero(u16),
	#[error("payload length {payload_len} exceeds capacity {capacity}")]
	PayloadTooLarge { payload_len: usize, capacity: usize },
	#[error("payload length {payload_len} does not match expected {expected} for {page_type:?}")]
	InvalidPayloadLength {
		page_type: PageType,
		payload_len: usize,
		expected: usize,
	},
	#[error("page CRC mismatch: expected {expected:#010x}, actual {actual:#010x}")]
	CrcMismatch { expected: u32, actual: u32 },
	#[error("{0:?} page header is missing owner inode")]
	MissingOwnerInHeader(PageType),
	#[error("inode page entry count ({0}) exceeds capacity")]
	InodesEntryCountTooLarge(usize),
	#[error("duplicate inode {0:?} while decoding inode pages")]
	DuplicateInode(INodeNo),
	#[error("duplicate page id {0:?}")]
	DuplicatePageId(PageId),
	#[error("decoded page id space exhausted")]
	PageIdSpaceExhausted,
	#[error("block padding bytes must be zero")]
	NonZeroPadding,
	#[error("inode payload is malformed")]
	MalformedInodesPayload,
	#[error("data page length {0} exceeds capacity")]
	DataPageLengthTooLarge(usize),
	#[error("missing bytes page at index {0}")]
	MissingDataPageIndex(usize),
	#[error("file pages for inode {ino:?} are not contiguous: expected {expected}, got {found}")]
	NonContiguousDataPages { ino: INodeNo, expected: u32, found: u32 },
	#[error("duplicate directory entry name {0:?} in one page")]
	DuplicateDirEntryName(OsString),
	#[error("too many pages to encode: {0}")]
	TooManyPages(usize),
	#[error("inodes page conversion failed: {0}")]
	InodeConversion(#[from] InodeConversionError),
	#[error("directory page decode failed: {0}")]
	Store(#[from] StoreError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PagerCapacityError {
	#[error("page limit exceeded")]
	PageLimitExceeded,
}

#[derive(Debug, thiserror::Error)]
pub enum PagerDirEntryError {
	#[error("page limit exceeded")]
	PageLimitExceeded,
	#[error("directory entry is too large to fit in a single page")]
	EntryTooLarge,
	#[error("missing directory entries page at index {index}")]
	MissingPage { index: usize },
	#[error("directory entry store failed: {0}")]
	Store(#[from] StoreError),
	#[error("directory entry replacement rollback failed after {original}; rollback error: {rollback}")]
	RollbackFailed {
		original: Box<PagerDirEntryError>,
		rollback: Box<PagerDirEntryError>,
	},
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PagerBytesError {
	#[error("byte range length overflow")]
	LengthOverflow,
	#[error("page limit exceeded")]
	PageLimitExceeded,
	#[error("missing byte page list for inode {ino:?}")]
	MissingPageList { ino: INodeNo },
	#[error("missing byte page pointer for inode {ino:?} at file page {page_no}")]
	MissingPagePointer { ino: INodeNo, page_no: usize },
	#[error("missing byte page at index {index}")]
	MissingPage { index: usize },
}

impl From<PagerCapacityError> for Errno {
	fn from(err: PagerCapacityError) -> Self {
		match err {
			PagerCapacityError::PageLimitExceeded => Errno::ENOSPC,
		}
	}
}

impl From<PagerDirEntryError> for Errno {
	fn from(err: PagerDirEntryError) -> Self {
		match err {
			PagerDirEntryError::PageLimitExceeded | PagerDirEntryError::EntryTooLarge => Errno::ENOSPC,
			PagerDirEntryError::MissingPage { .. }
			| PagerDirEntryError::Store(_)
			| PagerDirEntryError::RollbackFailed { .. } => Errno::EIO,
		}
	}
}

impl From<PagerBytesError> for Errno {
	fn from(err: PagerBytesError) -> Self {
		match err {
			PagerBytesError::PageLimitExceeded => Errno::ENOSPC,
			PagerBytesError::LengthOverflow => Errno::EFBIG,
			PagerBytesError::MissingPageList { .. }
			| PagerBytesError::MissingPagePointer { .. }
			| PagerBytesError::MissingPage { .. } => Errno::EIO,
		}
	}
}
