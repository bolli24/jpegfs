use crate::zigzag::ZIGZAG_INDICES;

pub fn set_lsb(coeff: i16, bit: u8) -> i16 {
	let is_skipped = |c: i16| matches!(c, -1..=1);
	let target = (bit & 1) as i16;
	let current = coeff & 1;

	if current == target && !is_skipped(coeff) {
		return coeff;
	}

	let down = coeff.checked_sub(1).filter(|c| !is_skipped(*c) && ((*c & 1) == target));
	let up = coeff.checked_add(1).filter(|c| !is_skipped(*c) && ((*c & 1) == target));

	match (down, up) {
		(Some(d), Some(u)) => {
			if (u as i32).abs() < (d as i32).abs() {
				u
			} else {
				d
			}
		}
		(Some(d), None) => d,
		(None, Some(u)) => u,
		(None, None) => unreachable!("set_lsb called with a skipped coefficient"),
	}
}

pub fn get_lsb(coeff: i16) -> u8 {
	(coeff & 1) as u8
}

pub fn is_embeddable_coeff(coeff: i16) -> bool {
	!matches!(coeff, -1..=1)
}

pub fn block_capacity_bits(coeffs: &[i16; 64]) -> usize {
	ZIGZAG_INDICES
		.iter()
		.skip(5)
		.filter(|&&idx| is_embeddable_coeff(coeffs[idx]))
		.count()
}

pub fn read_bit_from_bytes(data: &[u8], bit_index: usize) -> Option<u8> {
	let byte_index = bit_index / 8;
	if byte_index >= data.len() {
		return None;
	}
	let bit_in_byte = (bit_index % 8) as u8;
	Some((data[byte_index] >> (7 - bit_in_byte)) & 1)
}

pub fn write_bit_to_bytes(data: &mut [u8], bit_index: usize, bit: u8) {
	let byte_index = bit_index / 8;
	let bit_in_byte = (bit_index % 8) as u8;
	let mask = 1u8 << (7 - bit_in_byte);
	if (bit & 1) == 1 {
		data[byte_index] |= mask;
	} else {
		data[byte_index] &= !mask;
	}
}

pub fn ensure_byte_aligned(bit_offset: usize) -> anyhow::Result<()> {
	if !bit_offset.is_multiple_of(8) {
		anyhow::bail!("bit offset {} is not byte-aligned", bit_offset);
	}
	Ok(())
}
