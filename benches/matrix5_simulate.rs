use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use jpegfs::crypto::STRATEGY_MARKER_SIZE;
use jpegfs::jpeg_file::JpegSession;
use jpegfs::persistence::JpegBlockStore;
use jpegfs::strategy::EmbeddingStrategyId;
use rand::{Rng, SeedableRng};

const FIXTURE: &[u8] = include_bytes!("../test/CRW_2614_(Elsterflutbecken).jpg");
const STRATEGY: EmbeddingStrategyId = EmbeddingStrategyId::Matrix5;

fn payload_embed_len() -> usize {
	let mut session = JpegSession::new(FIXTURE.to_vec()).expect("fixture should parse");
	session.write_strategy_marker_lsb(u8::from(STRATEGY));
	let embedding_session = session.into_embedding_session(STRATEGY, [0u8; 32]);
	let jpeg_capacity = STRATEGY_MARKER_SIZE + embedding_session.remaining_bytes();
	let embed_len = JpegBlockStore::persisted_embed_len(jpeg_capacity).expect("fixture should have store capacity");
	embed_len.saturating_sub(STRATEGY_MARKER_SIZE)
}

fn encode_random_payload(jpeg_bytes: Vec<u8>, random_bytes: &[u8]) -> Vec<u8> {
	let mut session = JpegSession::new(jpeg_bytes).expect("fixture should parse");
	session.write_strategy_marker_lsb(u8::from(STRATEGY));
	let mut embedding_session = session.into_embedding_session(STRATEGY, [0u8; 32]);
	embedding_session
		.write_data(random_bytes)
		.expect("random payload should fit");
	embedding_session.to_jpeg_bytes().expect("fixture should re-encode")
}

fn bench_matrix5_simulate(c: &mut Criterion) {
	let payload_len = payload_embed_len();
	let mut rng = rand::rngs::StdRng::seed_from_u64(0);
	let mut payload = vec![0u8; payload_len];
	rng.fill_bytes(&mut payload);

	let mut group = c.benchmark_group("matrix5_simulate CRW_2614");
	group.throughput(Throughput::Bytes(payload_len as u64));
	group.bench_function("encode_random_payload", |b| {
		b.iter_batched(
			|| (FIXTURE.to_vec(), payload.clone()),
			|(jpeg_bytes, random_bytes)| {
				std::hint::black_box(encode_random_payload(
					std::hint::black_box(jpeg_bytes),
					std::hint::black_box(&random_bytes),
				));
			},
			BatchSize::SmallInput,
		)
	});
	group.finish();
}

criterion_group!(benches, bench_matrix5_simulate);
criterion_main!(benches);
