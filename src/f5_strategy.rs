#![allow(dead_code, unused_variables)]
use crate::{
	jpeg::OwnedJpeg,
	jpeg_file::BitSlot,
	strategy::{EmbeddingStrategy, EmbeddingStrategyId},
};

pub struct F5Strategy;

impl EmbeddingStrategy for F5Strategy {
	fn id(&self) -> EmbeddingStrategyId {
		EmbeddingStrategyId::F5
	}

	fn capacity_bytes(&self, slots_count: usize) -> usize {
		todo!()
	}

	fn read(
		&self,
		jpeg: &OwnedJpeg,
		slots: &[BitSlot],
		start_slot: usize,
		byte_offset: usize,
		out: &mut [u8],
	) -> usize {
		todo!()
	}

	fn write(
		&self,
		jpeg: &mut OwnedJpeg,
		slots: &[BitSlot],
		start_slot: usize,
		byte_offset: usize,
		data: &[u8],
	) -> usize {
		todo!()
	}
}

#[cfg(test)]
mod test {
	use crate::jpeg_file::JpegSession;

	#[test]
	pub fn f5_capacity() {
		let image_bytes = include_bytes!("../test/CRW_2614_(Elsterflutbecken).jpg");
		let jpeg_session = JpegSession::in_memory(image_bytes.to_vec()).unwrap();
		println!("Loaded image of {} bytes", image_bytes.len());

		let coeff_count = jpeg_session
			.components()
			.iter()
			.map(|comp| comp.blocks.len() * 64)
			.sum::<usize>();
		let mut one = 0;
		let mut zero = 0;

		for (i, &c) in jpeg_session
			.components()
			.iter()
			.flat_map(|comp| comp.blocks.iter())
			.flat_map(|block| block.iter().enumerate())
		{
			if i == 0 {
				continue;
			}
			if c == 1 || c == -1 {
				one += 1;
			}
			if c == 0 {
				zero += 1;
			}
		}

		let large = coeff_count - zero - one - coeff_count / 64;
		let expected = large + ((0.49 * one as f64) as usize);

		println!("zero={zero}\tone={one}\tlarge={large}");
		println!("expected capacity: {expected} bits");
		println!("expected capacity with");

		for i in 1..8 {
			let n = (1 << i) - 1;
			let usable = (expected * i / n - expected * i / n % n) / 8;
			let mut changed = large - large % (n + 1);
			changed = (changed + one + one / 2 - one / (n + 1)) / (n + 1);

			if usable == 0 {
				break;
			}
			if i == 1 {
				print!("default");
			} else {
				print!("(1, {n}, {i})");
			}

			println!(
				" code: {usable} bytes (efficiency {:.1} bits per change)",
				(usable * 8) as f64 / changed as f64
			)
		}
	}
}
