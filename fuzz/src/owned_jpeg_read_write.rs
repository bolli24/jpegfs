#![no_main]

use jpegfs::{
	jpeg::{OwnedJpeg, read_owned_jpeg, write_owned_jpeg},
	jpeg_file::JpegSession,
	lsb::{get_lsb, read_bit_from_bytes, set_lsb, write_bit_to_bytes},
};
use libfuzzer_sys::fuzz_target;

const TEMPLATE_JPEG: &[u8] = include_bytes!("../fixtures/tiny_crw_2609_16x8.jpg");

fn overwrite_bytes(owned: &mut OwnedJpeg, data: &[u8], offset: usize) {
	let bit_slots = JpegSession::collect_bit_slots(owned);
	let start_bit = offset * 8;

	for data_bit in 0..(data.len() * 8) {
		let slot = bit_slots[start_bit + data_bit];
		let bit = read_bit_from_bytes(data, data_bit).unwrap_or(0);
		let coeff = &mut owned.components[slot.component_index].blocks[slot.block_index][slot.coeff_index];
		*coeff = set_lsb(*coeff, bit);
	}
}

fn read_back_bytes(owned: &OwnedJpeg, len: usize, offset: usize) -> Vec<u8> {
	let bit_slots = JpegSession::collect_bit_slots(owned);
	let start_bit = offset * 8;
	let mut read_back = vec![0u8; len];

	for data_bit in 0..(len * 8) {
		let slot = bit_slots[start_bit + data_bit];
		let coeff = owned.components[slot.component_index].blocks[slot.block_index][slot.coeff_index];
		let bit = get_lsb(coeff);
		write_bit_to_bytes(&mut read_back, data_bit, bit);
	}

	read_back
}

fn assert_same_coefficients(expected: &OwnedJpeg, actual: &OwnedJpeg) {
	for (expected_component, actual_component) in expected.components.iter().zip(actual.components.iter()) {
		assert_eq!(expected_component.width_in_blocks, actual_component.width_in_blocks);
		assert_eq!(expected_component.height_in_blocks, actual_component.height_in_blocks);
		assert_eq!(expected_component.blocks, actual_component.blocks);
	}
}

fuzz_target!(|input: (Vec<u8>, u8)| {
	let (mut data, offset_seed) = input;
	let mut owned = unsafe { read_owned_jpeg(TEMPLATE_JPEG).expect("tiny template should decode") };
	for component in &owned.components {
		assert_eq!(component.width_in_blocks, 2);
		assert_eq!(component.height_in_blocks, 1);
	}

	let bit_slots = JpegSession::collect_bit_slots(&owned);
	let capacity_bytes = bit_slots.len() / 8;
	data.truncate(capacity_bytes);

	let max_offset = capacity_bytes - data.len();
	let offset = usize::from(offset_seed) % (max_offset + 1);
	overwrite_bytes(&mut owned, &data, offset);

	let encoded = unsafe { write_owned_jpeg(TEMPLATE_JPEG, &owned).expect("tiny template should encode") };
	let decoded = unsafe { read_owned_jpeg(&encoded).expect("encoded tiny template should decode") };

	assert_same_coefficients(&owned, &decoded);
	assert_eq!(read_back_bytes(&decoded, data.len(), offset), data);
});
