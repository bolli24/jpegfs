use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use jpegfs::jpeg::{BlockData, OwnedJpeg, read_owned_jpeg};
use jpegfs::jpeg_file::{BitSlot, BitSlotSearchStart};
use jpegfs::lsb::{get_lsb, is_embeddable_coeff, read_bit_from_bytes, set_lsb};
use jpegfs::strategy::{EmbeddingStrategy, LsbStrategy, iter_coefficients, iter_coefficients_mut};
use jpegfs::zigzag::RESERVED_ZIGZAG_COEFFS;

fn iter_capacity_bytes(jpeg: &OwnedJpeg) -> usize {
	let mut bit_count = 0usize;
	iter_coefficients(
		jpeg,
		BitSlotSearchStart::default(),
		RESERVED_ZIGZAG_COEFFS,
		|block: &BlockData, _, _, coeff_index| {
			if is_embeddable_coeff(block[coeff_index]) {
				bit_count += 1;
			}
			true
		},
	);
	bit_count / 8
}

fn iter_read_lsb(jpeg: &OwnedJpeg, out: &mut [u8]) -> usize {
	out.fill(0);
	let bit_limit = out.len() * 8;
	let mut bit_index = 0usize;

	iter_coefficients(
		jpeg,
		BitSlotSearchStart::default(),
		RESERVED_ZIGZAG_COEFFS,
		|block: &BlockData, _, _, coeff_index| {
			if !is_embeddable_coeff(block[coeff_index]) {
				return true;
			}

			if bit_index == bit_limit {
				return false;
			}

			if get_lsb(block[coeff_index]) == 1 {
				let byte_index = bit_index / 8;
				let bit_in_byte = bit_index % 8;
				out[byte_index] |= 1 << (7 - bit_in_byte);
			}
			bit_index += 1;
			true
		},
	);

	bit_index / 8
}

fn iter_write_lsb(jpeg: &mut OwnedJpeg, data: &[u8]) -> usize {
	let bit_limit = data.len() * 8;
	let mut bit_index = 0usize;

	iter_coefficients_mut(
		jpeg,
		BitSlotSearchStart::default(),
		RESERVED_ZIGZAG_COEFFS,
		|block: &mut BlockData, _, _, coeff_index| {
			if !is_embeddable_coeff(block[coeff_index]) {
				return true;
			}

			if bit_index == bit_limit {
				return false;
			}

			let bit = read_bit_from_bytes(data, bit_index).unwrap_or(0);
			block[coeff_index] = set_lsb(block[coeff_index], bit);
			bit_index += 1;
			true
		},
	);

	bit_index / 8
}

fn bench_lsb_embedding(c: &mut Criterion) {
	let jpeg = include_bytes!("../test/CRW_2614_(Elsterflutbecken).jpg");
	let owned_jpeg = unsafe { read_owned_jpeg(jpeg).expect("fixture should parse") };
	let strategy = LsbStrategy;
	let slots = strategy.collect_bit_slots(&owned_jpeg, BitSlotSearchStart::default());
	let capacity = strategy.capacity_bytes(slots.len());
	assert_eq!(capacity, iter_capacity_bytes(&owned_jpeg));

	let payload = vec![0x5au8; capacity];
	let mut group = c.benchmark_group("lsb_embedding CRW_2614");

	group.bench_function("bitslots", |b| {
		b.iter_batched(
			|| (owned_jpeg.clone(), vec![0u8; capacity]),
			|(mut jpeg, mut out)| {
				let slots: Vec<BitSlot> = strategy.collect_bit_slots(
					std::hint::black_box(&jpeg),
					std::hint::black_box(BitSlotSearchStart::default()),
				);
				let capacity = strategy.capacity_bytes(std::hint::black_box(slots.len()));
				let decoded = strategy.read(&jpeg, &slots, &mut out[..capacity]);
				let written = strategy.write(&mut jpeg, &slots, &payload[..capacity]);
				std::hint::black_box((capacity, decoded, written, jpeg));
			},
			BatchSize::SmallInput,
		);
	});

	group.bench_function("iter_coefficients", |b| {
		b.iter_batched(
			|| (owned_jpeg.clone(), vec![0u8; capacity]),
			|(mut jpeg, mut out)| {
				let capacity = iter_capacity_bytes(std::hint::black_box(&jpeg));
				let decoded = iter_read_lsb(&jpeg, &mut out[..capacity]);
				let written = iter_write_lsb(&mut jpeg, &payload[..capacity]);
				std::hint::black_box((capacity, decoded, written, jpeg));
			},
			BatchSize::SmallInput,
		);
	});

	group.finish();
}

criterion_group!(benches, bench_lsb_embedding);
criterion_main!(benches);
