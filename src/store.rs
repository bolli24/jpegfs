use serde::{Serialize, de::DeserializeOwned};
use std::mem::size_of;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct Header {
	pub block_id: u32,
	pub active_slots: u32,
	pub free_space_offset: u32,
	pub free_space: u32,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct Entry {
	offset: u32,
	length: u32,
}

pub struct StoreBlock<T, const SIZE: usize>
where
	T: Serialize + DeserializeOwned,
{
	header: Header,
	data: [u8; SIZE],
	phantom: std::marker::PhantomData<T>,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
	#[error("Not enough free space to store entry.")]
	NoSpace,

	#[error("Unable to serialize.")]
	Serialize(postcard::Error),

	#[error("Unable to deserialize.")]
	Deserialize(postcard::Error),

	#[error("Index out of bounds")]
	NoEntry,
}

impl<T, const SIZE: usize> StoreBlock<T, SIZE>
where
	T: Serialize + DeserializeOwned,
{
	pub fn new(block_id: u32) -> Self {
		assert!(
			SIZE >= size_of::<Header>(),
			"StoreBlock SIZE ({SIZE}) must be at least Header size ({})",
			size_of::<Header>()
		);
		assert!(
			u32::try_from(SIZE).is_ok(),
			"StoreBlock SIZE ({SIZE}) exceeds u32 addressable range"
		);

		let mut new_block = Self {
			header: Header {
				block_id,
				active_slots: 0,
				free_space_offset: SIZE as u32,
				free_space: (SIZE - size_of::<Header>()) as u32,
			},
			data: [0; SIZE],
			phantom: std::marker::PhantomData,
		};

		new_block.store_header();
		new_block
	}

	fn store_header(&mut self) {
		self.header
			.write_to(&mut self.data[0..size_of::<Header>()])
			.expect("Sizes of source and destination are equal.");
	}

	fn entry_offset(&self) -> usize {
		size_of::<Header>() + self.header.active_slots as usize * size_of::<Entry>()
	}

	fn entry_at(&self, index: u32) -> usize {
		size_of::<Header>() + index as usize * size_of::<Entry>()
	}

	pub fn try_store(&mut self, value: T) -> Result<u32, Error> {
		let value_bytes = postcard::to_stdvec(&value).map_err(Error::Serialize)?;
		let value_len_u32 = u32::try_from(value_bytes.len()).map_err(|_| Error::NoSpace)?;
		let entry_size_u32 = u32::try_from(size_of::<Entry>()).expect("Entry size must fit into u32");
		let available_data_space = self
			.header
			.free_space
			.checked_sub(entry_size_u32)
			.ok_or(Error::NoSpace)?;

		if value_len_u32 > available_data_space {
			return Err(Error::NoSpace);
		}

		self.header.free_space_offset -= value_len_u32;
		self.header.free_space -= value_len_u32 + entry_size_u32;

		let value_offset = self.header.free_space_offset as usize;
		let value_len = value_len_u32 as usize;

		value_bytes
			.write_to(&mut self.data[value_offset..value_offset + value_len])
			.expect("Sizes of source and destination are equal.");

		let entry_offset = self.entry_offset();
		Entry {
			offset: self.header.free_space_offset,
			length: value_len_u32,
		}
		.write_to(&mut self.data[entry_offset..entry_offset + size_of::<Entry>()])
		.expect("Sizes of source and destination are equal.");

		self.header.active_slots += 1;
		self.store_header();

		Ok(self.header.active_slots - 1)
	}

	pub fn get(&self, index: u32) -> Result<T, Error> {
		if index >= self.header.active_slots {
			return Err(Error::NoEntry);
		}

		let entry_offset = self.entry_at(index);
		let entry = Entry::read_from_bytes(&self.data[entry_offset..entry_offset + size_of::<Entry>()])
			.expect("Sizes of source and destination are equal and data is valid.");

		let start = entry.offset as usize;
		let len = entry.length as usize;
		postcard::from_bytes(&self.data[start..start + len]).map_err(Error::Deserialize)
	}

	pub fn as_bytes(&self) -> &[u8; SIZE] {
		&self.data
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn test_store() {
		let mut store = StoreBlock::<String, 1024>::new(0);

		let a = store
			.try_store("Hello world".to_owned())
			.expect("Store should not fail");
		let b = store
			.try_store("Lorem Ipsum".to_owned())
			.expect("Store should not fail");

		println!("B: {}", store.get(b).unwrap());
		println!("A: {}", store.get(a).unwrap());
	}
}
