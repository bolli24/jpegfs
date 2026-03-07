#![no_main]

use std::mem::size_of;

use arbitrary::Arbitrary;
use jpegfs::pager::PageId;
use jpegfs::store::{Error, Header, StoreBlock};
use libfuzzer_sys::fuzz_target;
use zerocopy::FromBytes;

const BLOCK_SIZE: usize = 512;
const MAX_VALUES: usize = 128;
const MAX_VALUE_BYTES: usize = 128;

#[derive(Arbitrary, Debug)]
struct Program {
	values: Vec<Vec<u8>>,
}

fn persisted_active_slots(block: &StoreBlock<Vec<u8>, BLOCK_SIZE>) -> u32 {
	let bytes = block.as_bytes();
	let header = Header::read_from_bytes(&bytes[..size_of::<Header>()]).expect("header bytes must always decode");
	header.active_slots
}

fuzz_target!(|program: Program| {
	let mut block = StoreBlock::<Vec<u8>, BLOCK_SIZE>::new(PageId(7));
	let mut expected = Vec::new();

	for value in program.values.into_iter().take(MAX_VALUES) {
		let value = value.into_iter().take(MAX_VALUE_BYTES).collect::<Vec<_>>();

		match block.try_store(value.clone()) {
			Ok(index) => {
				assert_eq!(index as usize, expected.len());
				expected.push(value);

				assert_eq!(persisted_active_slots(&block) as usize, expected.len());
			}
			Err(Error::NoSpace) => break,
			Err(err) => panic!("unexpected store error: {err:?}"),
		}
	}

	for (index, expected_value) in expected.iter().enumerate() {
		let got = block.get(index as u32).expect("stored value must round-trip");
		assert_eq!(got, *expected_value);
	}
});
