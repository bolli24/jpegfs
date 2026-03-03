#![no_main]

use jpegfs::{
	jpeg::OwnedJpeg,
	lsb::{get_lsb, is_embeddable_coeff, read_bit_from_bytes, set_lsb, write_bit_to_bytes},
	zigzag::ZIGZAG_INDICES,
};
use libfuzzer_sys::fuzz_target;

#[derive(Clone, Copy)]
struct BitSlot {
	component_index: usize,
	block_index: usize,
	coeff_index: usize,
}

fn collect_bit_slots(owned: &OwnedJpeg) -> Vec<BitSlot> {
	let mut bit_slots = Vec::new();
	for (component_index, component) in owned.components.iter().enumerate() {
		for (block_index, block) in component.blocks.iter().enumerate() {
			for &coeff_index in ZIGZAG_INDICES.iter().skip(5) {
				if is_embeddable_coeff(block[coeff_index]) {
					bit_slots.push(BitSlot {
						component_index,
						block_index,
						coeff_index,
					});
				}
			}
		}
	}
	bit_slots
}

fuzz_target!(|input: (OwnedJpeg, [u8; 8], u16)| {
	let (mut owned, data, offset_seed) = input;
	let bit_slots = collect_bit_slots(&owned);
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
