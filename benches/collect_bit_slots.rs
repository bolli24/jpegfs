use criterion::{Criterion, criterion_group, criterion_main};
use jpegfs::jpeg::read_owned_jpeg;
use jpegfs::jpeg_file::BitSlotSearchStart;
use jpegfs::strategy::collect_lsb_bit_slots;

fn bench_collect_bit_slots(c: &mut Criterion) {
	let jpeg = include_bytes!("../test/CRW_2614_(Elsterflutbecken).jpg");
	let owned_jpeg = unsafe { read_owned_jpeg(jpeg).expect("fixture should parse") };

	c.bench_function("collect_bit_slots CRW_2614", |b| {
		b.iter(|| {
			collect_lsb_bit_slots(
				std::hint::black_box(&owned_jpeg),
				std::hint::black_box(BitSlotSearchStart::default()),
				0,
			)
		});
	});
}

criterion_group!(benches, bench_collect_bit_slots);
criterion_main!(benches);
