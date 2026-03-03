#![allow(unsafe_op_in_unsafe_fn, dead_code)]

pub mod file;
pub mod jpeg;
pub mod lsb;
pub mod zigzag;

use jpeg::{Block, BlockData};
use serde::{Deserialize, Serialize};

pub trait BlockWriter {
	fn write_block(&mut self, block: Block, coeffs: &mut BlockData);
}

pub trait BlockReader {
	fn read_block(&mut self, block: Block, coeffs: &BlockData);
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Header {
	pub id: u32,
	pub capacity: usize,
}
