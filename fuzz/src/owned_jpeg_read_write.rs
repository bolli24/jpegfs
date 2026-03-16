#![no_main]

use jpegfs::jpeg_file::JpegSession;
use jpegfs::{
	jpeg::OwnedJpeg,
	lsb::{get_lsb, read_bit_from_bytes, set_lsb, write_bit_to_bytes},
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (OwnedJpeg, [u8; 8], u16)| {
	let (mut owned, data, offset_seed) = input;
	let bit_slots = JpegSession::collect_bit_slots(&owned);
	let capacity_bytes = bit_slots.len() / 8;

	if capacity_bytes < data.len() {
		return;
	}

	let max_offset = capacity_bytes - data.len();
	let offset = usize::from(offset_seed) % (max_offset + 1);
	let start_bit = offset * 8;

	for data_bit in 0..(data.len() * 8) {
		let slot = bit_slots[start_bit + data_bit];
		let bit = read_bit_from_bytes(&data, data_bit).unwrap_or(0);
		let coeff = &mut owned.components[slot.component_index].blocks[slot.block_index][slot.coeff_index];
		*coeff = set_lsb(*coeff, bit);
	}

	let mut read_back = vec![0u8; data.len()];
	for data_bit in 0..(data.len() * 8) {
		let slot = bit_slots[start_bit + data_bit];
		let coeff = owned.components[slot.component_index].blocks[slot.block_index][slot.coeff_index];
		let bit = get_lsb(coeff);
		write_bit_to_bytes(&mut read_back, data_bit, bit);
	}

	assert_eq!(read_back, data);
});
