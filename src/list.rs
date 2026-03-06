use crate::store::Error;
use binrw::{BinRead, BinReaderExt, BinWrite, BinWriterExt};
use std::io::Cursor;
use std::mem::size_of;

#[derive(BinRead, BinWrite)]
#[repr(C)]
pub struct ListHeader {
	pub block_id: u32,
	pub free_slots: u32,
	pub current_slot: u32,
}

pub trait FixedBin {
	const WIRE_SIZE: usize;
}

macro_rules! impl_fixed_bin_primitive {
	($($t:ty),* $(,)?) => {
		$(
			impl FixedBin for $t {
				const WIRE_SIZE: usize = size_of::<$t>();
			}
		)*
	};
}

impl_fixed_bin_primitive!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128, f32, f64);

pub struct ListBlock<T, const SIZE: usize>
where
	T: FixedBin + BinWrite + BinRead,
	for<'a> <T as BinWrite>::Args<'a>: Default,
	for<'a> <T as BinRead>::Args<'a>: Default,
{
	header: ListHeader,
	data: [u8; SIZE],
	phantom: std::marker::PhantomData<T>,
}

impl<T, const SIZE: usize> ListBlock<T, SIZE>
where
	T: FixedBin + BinWrite + BinRead,
	for<'a> <T as BinWrite>::Args<'a>: Default,
	for<'a> <T as BinRead>::Args<'a>: Default,
{
	pub fn new(block_id: u32) -> Self {
		const {
			assert!(SIZE >= size_of::<ListHeader>());
			assert!(T::WIRE_SIZE > 0);
		}

		let mut new_block = Self {
			header: ListHeader {
				block_id,
				free_slots: ((SIZE - size_of::<ListHeader>()) / T::WIRE_SIZE) as u32,
				current_slot: 0,
			},
			data: [0; SIZE],
			phantom: std::marker::PhantomData,
		};

		new_block
			.store_header()
			.expect("Header bytes must always encode during StoreBlock initialization.");
		new_block
	}

	fn store_header(&mut self) -> Result<(), Error> {
		let mut out = Cursor::new(&mut self.data[0..size_of::<ListHeader>()]);
		out.write_le(&self.header).map_err(Error::Binary)
	}

	fn entry_offset(&self) -> usize {
		size_of::<ListHeader>() + self.header.current_slot as usize * T::WIRE_SIZE
	}

	fn entry_at(&self, index: u32) -> usize {
		size_of::<ListHeader>() + index as usize * T::WIRE_SIZE
	}

	pub fn try_store(&mut self, value: T) -> Result<u32, Error> {
		if self.header.free_slots == 0 {
			return Err(Error::NoSpace);
		}

		let entry_offset = self.entry_offset();

		let mut writer = Cursor::new(&mut self.data[entry_offset..entry_offset + T::WIRE_SIZE]);
		writer.write_le(&value).map_err(Error::Binary)?;
		let written = writer.position() as usize;
		if written != T::WIRE_SIZE {
			return Err(Error::InvalidValueSize {
				expected: T::WIRE_SIZE,
				actual: written,
			});
		}

		self.header.free_slots -= 1;
		self.header.current_slot += 1;
		self.store_header()?;

		Ok(self.header.current_slot - 1)
	}

	pub fn get(&self, index: u32) -> Result<T, Error> {
		if index >= self.header.current_slot {
			return Err(Error::NoEntry);
		}

		let entry_offset = self.entry_at(index);
		let mut reader = Cursor::new(&self.data[entry_offset..entry_offset + T::WIRE_SIZE]);
		let value = reader.read_le().map_err(Error::Binary)?;
		let read = reader.position() as usize;
		if read != T::WIRE_SIZE {
			return Err(Error::InvalidValueSize {
				expected: T::WIRE_SIZE,
				actual: read,
			});
		}
		Ok(value)
	}

	pub fn as_bytes(&self) -> &[u8; SIZE] {
		&self.data
	}
}
