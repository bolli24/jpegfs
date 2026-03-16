#![no_main]

use jpegfs::inode::InodeRaw;
use libfuzzer_sys::fuzz_target;
use zerocopy::TryFromBytes;

fuzz_target!(|bytes: Vec<u8>| {
	if let Ok(raw) = InodeRaw::try_read_from_bytes(&bytes) {
		if let Ok((ino, inode)) = raw.into_parts() {
			let raw2 = InodeRaw::from_parts(ino, &inode).expect("re-encoding decoded inode should succeed");
			let (_ino2, inode2) = raw2.into_parts().expect("decoded inode should stay valid");
			assert_eq!(inode2, inode);
		}
	}
});
