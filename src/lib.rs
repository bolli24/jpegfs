#![allow(unsafe_op_in_unsafe_fn, dead_code)]

pub mod file;
pub mod filesystem;
pub mod jpeg;
pub mod lsb;
pub mod zigzag;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Header {
	pub id: u32,
	pub capacity: usize,
}
