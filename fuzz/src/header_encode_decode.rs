#![no_main]

use jpegfs::Header;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (u32, usize)| {
	let header = Header {
		id: input.0,
		capacity: input.1,
	};

	let data = postcard::to_stdvec(&header).expect("header serialization should succeed");
	let decoded_header: Header = postcard::from_bytes(&data).expect("header deserialization should succeed");
	assert_eq!(decoded_header, header);
});
