#[rustfmt::skip]
pub const ZIGZAG_INDICES: [usize; 64] = [
     0,  1,  8, 16,  9,  2,  3, 10,
    17, 24, 32, 25, 18, 11,  4,  5,
    12, 19, 26, 33, 40, 48, 41, 34,
    27, 20, 13,  6,  7, 14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36,
    29, 22, 15, 23, 30, 37, 44, 51,
    58, 59, 52, 45, 38, 31, 39, 46,
    53, 60, 61, 54, 47, 55, 62, 63,
];

pub struct ZigZagMut<'a> {
	ptr: *mut i16,
	pos: usize,
	_marker: std::marker::PhantomData<&'a mut i16>,
}

impl<'a> Iterator for ZigZagMut<'a> {
	type Item = &'a mut i16;

	fn next(&mut self) -> Option<Self::Item> {
		if self.pos >= 64 {
			return None;
		}

		let idx = ZIGZAG_INDICES[self.pos];

		self.pos += 1;

		// SAFETY: ZIGZAG_INDICES contains 64 unique, in-bounds indices.
		// It is impossible to yield overlapping mutable references.
		unsafe { Some(&mut *self.ptr.add(idx)) }
	}
}

pub trait ZigZagExt {
	fn zigzag(&self) -> impl Iterator<Item = &i16>;
	fn into_zigzag(self) -> impl Iterator<Item = i16>;
	fn zigzag_mut(&mut self) -> ZigZagMut<'_>;
}

impl ZigZagExt for [i16; 64] {
	fn zigzag(&self) -> impl Iterator<Item = &i16> {
		ZIGZAG_INDICES.iter().map(move |&i| &self[i])
	}

	fn into_zigzag(self) -> impl Iterator<Item = i16> {
		ZIGZAG_INDICES.into_iter().map(move |i| self[i])
	}

	fn zigzag_mut(&mut self) -> ZigZagMut<'_> {
		ZigZagMut {
			ptr: self.as_mut_ptr(),
			pos: 0,
			_marker: std::marker::PhantomData,
		}
	}
}
