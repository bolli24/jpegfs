#![allow(unsafe_op_in_unsafe_fn)]

pub mod crypto;
pub mod f5_strategy;
#[cfg(unix)]
pub mod filesystem;
pub mod ino;
pub mod inode;
pub mod jpeg;
pub mod jpeg_file;
pub mod lsb;
pub mod pager;
pub mod pager_error;
pub mod persistence;
pub mod store;
pub mod strategy;
pub mod zigzag;

pub const MAGIC: [u8; 4] = *b"JPGF";
