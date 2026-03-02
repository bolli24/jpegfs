#![no_main]

use jpegfs::{
	BlockReader, BlockWriter,
	jpeg::{Block, BlockData, CapacityReader},
	lsb::{LsbReader, LsbWriter},
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (BlockData, [u8; 5])| {
	let mut coeffs = input.0;
	let data = input.1;

	let capacity_block = Block {
		component_index: 0,
		row: 0,
		column: 0,
	};
	let mut capacity_reader = CapacityReader::default();
	capacity_reader.read_block(capacity_block, &coeffs);
	let capacities = capacity_reader.capacities;
	assert!(capacities[0] <= 64);
	assert_eq!(capacities[1], 0);
	assert_eq!(capacities[2], 0);

	if capacities[0] < data.len() * 8 {
		return;
	}

	let write_block = Block {
		component_index: 0,
		row: 0,
		column: 0,
	};

	let mut writer = LsbWriter::new(&data);

	writer.write_block(write_block, &mut coeffs);

	let read_block = Block {
		component_index: 0,
		row: 0,
		column: 0,
	};
	let mut reader = LsbReader::new(data.len());
	reader.read_block(read_block, &coeffs);
	let read_data = reader.finish();
	assert_eq!(read_data.len(), data.len());
	assert_eq!(read_data, data);
});
