#![allow(unsafe_op_in_unsafe_fn, dead_code)]

pub mod filesystem;
pub mod inode;
pub mod jpeg;
pub mod jpeg_file;
pub mod lsb;
pub mod pager;
pub mod persistence;
pub mod store;
pub mod zigzag;

use serde::{Deserialize, Serialize};

pub const MAGIC: [u8; 4] = *b"JPGF";

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Header {
	pub id: u32,
	pub capacity: usize,
}
