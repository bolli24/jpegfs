use crate::pager::PageId;
use serde::{Serialize, de::DeserializeOwned};
use std::mem::size_of;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct Header {
	pub page_id: PageId,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct StoreSlot(u32);

impl StoreSlot {
	pub const fn from_raw(raw: u32) -> Self {
		Self(raw)
	}

	pub const fn into_raw(self) -> u32 {
		self.0
	}
}

/// Data structure to hold list of variable length items (e.g. directory entry names)
/// Guarantees that its data plus header does not exceed SIZE
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
	#[error("not enough free space to store entry")]
	NoSpace,

	#[error("store block smaller than header")]
	BlockSmallerThanHeader,
	#[error("unable to parse header")]
	HeaderDecode,
	#[error("entry table overflow")]
	EntryTableOverflow,
	#[error("entry table exceeds block")]
	EntryTableExceedsBlock,
	#[error("free space offset out of bounds")]
	FreeSpaceOffsetOutOfBounds,
	#[error("free space does not match layout")]
	FreeSpaceMismatch,
	#[error("unable to parse slot entry")]
	SlotEntryDecode,
	#[error("slot range overflow")]
	SlotRangeOverflow,
	#[error("slot payload out of bounds")]
	SlotPayloadOutOfBounds,

	#[error("serialize failed: {0}")]
	Serialize(postcard::Error),

	#[error("deserialize failed: {0}")]
	Deserialize(postcard::Error),

	#[error("index out of bounds")]
	NoEntry,
}

impl<T, const SIZE: usize> StoreBlock<T, SIZE>
where
	T: Serialize + DeserializeOwned,
{
	pub fn new(page_id: PageId) -> Self {
		const {
			assert!(
				SIZE >= size_of::<Header>(),
				"StoreBlock SIZE must be at least Header size.",
			);
			assert!(
				SIZE <= u32::MAX as usize,
				"StoreBlock SIZE exceeds u32 addressable range"
			);
		}

		let mut new_block = Self {
			header: Header {
				page_id,
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

	fn entry_at(&self, slot: StoreSlot) -> usize {
		size_of::<Header>() + slot.into_raw() as usize * size_of::<Entry>()
	}

	pub fn try_store(&mut self, value: T) -> Result<StoreSlot, Error> {
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

		Ok(StoreSlot::from_raw(self.header.active_slots - 1))
	}

	pub fn get(&self, slot: StoreSlot) -> Result<T, Error> {
		if slot.into_raw() >= self.header.active_slots {
			return Err(Error::NoEntry);
		}

		let entry_offset = self.entry_at(slot);
		let entry = Entry::read_from_bytes(&self.data[entry_offset..entry_offset + size_of::<Entry>()])
			.expect("Sizes of source and destination are equal and data is valid.");

		let start = entry.offset as usize;
		let len = entry.length as usize;
		postcard::from_bytes(&self.data[start..start + len]).map_err(Error::Deserialize)
	}

	/// Removes one slot and returns the value plus an optional `(from, to)` remap
	/// when swap-remove moves the former last slot into the removed slot's position.
	pub fn remove(&mut self, slot: StoreSlot) -> Result<(T, Option<(StoreSlot, StoreSlot)>), Error> {
		if slot.into_raw() >= self.header.active_slots {
			return Err(Error::NoEntry);
		}

		let entry_offset = self.entry_at(slot);
		let removed_entry = Entry::read_from_bytes(&self.data[entry_offset..entry_offset + size_of::<Entry>()])
			.expect("Sizes of source and destination are equal and data is valid.");
		let removed_start = removed_entry.offset as usize;
		let removed_len = removed_entry.length as usize;
		let removed_end = removed_start + removed_len;
		let removed = postcard::from_bytes(&self.data[removed_start..removed_end]).map_err(Error::Deserialize)?;

		let old_free_space_offset = self.header.free_space_offset as usize;
		if old_free_space_offset < removed_start {
			self.data.copy_within(
				old_free_space_offset..removed_start,
				old_free_space_offset + removed_len,
			);
		}

		for current_slot in (0..self.header.active_slots).map(StoreSlot::from_raw) {
			if current_slot == slot {
				continue;
			}
			let slot_offset = self.entry_at(current_slot);
			let mut entry = Entry::read_from_bytes(&self.data[slot_offset..slot_offset + size_of::<Entry>()])
				.expect("Sizes of source and destination are equal and data is valid.");
			if (entry.offset as usize) < removed_start {
				entry.offset = entry
					.offset
					.checked_add(removed_entry.length)
					.expect("entry offset must stay in range");
				entry
					.write_to(&mut self.data[slot_offset..slot_offset + size_of::<Entry>()])
					.expect("Sizes of source and destination are equal.");
			}
		}

		let last_slot = StoreSlot::from_raw(self.header.active_slots - 1);
		let remap = if slot != last_slot {
			let last_entry_offset = self.entry_at(last_slot);
			let moved_entry =
				Entry::read_from_bytes(&self.data[last_entry_offset..last_entry_offset + size_of::<Entry>()])
					.expect("Sizes of source and destination are equal and data is valid.");
			moved_entry
				.write_to(&mut self.data[entry_offset..entry_offset + size_of::<Entry>()])
				.expect("Sizes of source and destination are equal.");
			Some((last_slot, slot))
		} else {
			None
		};

		let entry_size_u32 = u32::try_from(size_of::<Entry>()).expect("Entry size must fit into u32");
		self.header.active_slots -= 1;
		self.header.free_space_offset = self
			.header
			.free_space_offset
			.checked_add(removed_entry.length)
			.expect("free space offset must stay in range");
		self.header.free_space = self
			.header
			.free_space
			.checked_add(removed_entry.length + entry_size_u32)
			.expect("free space must stay in range");
		self.store_header();

		Ok((removed, remap))
	}

	#[cfg(test)]
	pub(crate) fn test_set_slot_length(&mut self, slot: StoreSlot, length: u32) {
		assert!(
			slot.into_raw() < self.header.active_slots,
			"test helper requires an active slot"
		);
		let entry_offset = self.entry_at(slot);
		let mut entry = Entry::read_from_bytes(&self.data[entry_offset..entry_offset + size_of::<Entry>()])
			.expect("Sizes of source and destination are equal and data is valid.");
		entry.length = length;
		entry
			.write_to(&mut self.data[entry_offset..entry_offset + size_of::<Entry>()])
			.expect("Sizes of source and destination are equal.");
	}

	pub fn as_bytes(&self) -> &[u8; SIZE] {
		&self.data
	}

	pub fn active_slots(&self) -> u32 {
		self.header.active_slots
	}

	pub fn slots(&self) -> impl Iterator<Item = StoreSlot> {
		let active_slots = self.header.active_slots;
		(0..active_slots).map(StoreSlot::from_raw)
	}

	/// Initialize a StoreBlock from raw bytes, validating its invariants:
	/// - block is large enough to contain header
	/// - header is valid
	/// - entry count does not overflow table
	/// - entry table does not exceed block
	/// - free space offset is within table bounds
	/// - free space does match actual free space
	/// - each slot decodes correctly
	/// - each slot value deserializes correctly
	/// - slot paylod is within bounds
	pub fn from_bytes(data: [u8; SIZE]) -> Result<Self, Error> {
		if SIZE < size_of::<Header>() {
			return Err(Error::BlockSmallerThanHeader);
		}

		let header = Header::read_from_bytes(&data[..size_of::<Header>()]).map_err(|_| Error::HeaderDecode)?;

		let entry_bytes = size_of::<Entry>();
		let header_bytes = size_of::<Header>();
		let active_slots = header.active_slots as usize;
		let entry_table_end = header_bytes
			.checked_add(active_slots.checked_mul(entry_bytes).ok_or(Error::EntryTableOverflow)?)
			.ok_or(Error::EntryTableOverflow)?;
		if entry_table_end > SIZE {
			return Err(Error::EntryTableExceedsBlock);
		}

		let free_space_offset = header.free_space_offset as usize;
		if free_space_offset < entry_table_end || free_space_offset > SIZE {
			return Err(Error::FreeSpaceOffsetOutOfBounds);
		}

		let expected_free_space = free_space_offset - entry_table_end;
		if header.free_space as usize != expected_free_space {
			return Err(Error::FreeSpaceMismatch);
		}

		for i in 0..header.active_slots {
			let entry_offset = header_bytes + i as usize * entry_bytes;
			let entry = Entry::read_from_bytes(&data[entry_offset..entry_offset + entry_bytes])
				.map_err(|_| Error::SlotEntryDecode)?;

			let start = entry.offset as usize;
			let len = entry.length as usize;
			let end = start.checked_add(len).ok_or(Error::SlotRangeOverflow)?;
			if start < free_space_offset || end > SIZE {
				return Err(Error::SlotPayloadOutOfBounds);
			}

			let _value: T = postcard::from_bytes(&data[start..end]).map_err(Error::Deserialize)?;
		}

		Ok(Self {
			header,
			data,
			phantom: std::marker::PhantomData,
		})
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn test_store() {
		let mut store = StoreBlock::<String, 1024>::new(PageId(0));

		let a = store
			.try_store("Hello world".to_owned())
			.expect("Store should not fail");
		let b = store
			.try_store("Lorem Ipsum".to_owned())
			.expect("Store should not fail");

		println!("B: {}", store.get(b).unwrap());
		println!("A: {}", store.get(a).unwrap());
	}

	#[test]
	fn remove_compacts_payload_and_slots() {
		let mut store = StoreBlock::<u64, 256>::new(PageId(0));
		let a = store.try_store(11).expect("insert should succeed");
		let b = store.try_store(22).expect("insert should succeed");
		let c = store.try_store(33).expect("insert should succeed");
		assert_eq!(
			(a, b, c),
			(StoreSlot::from_raw(0), StoreSlot::from_raw(1), StoreSlot::from_raw(2),)
		);

		let (removed, remap) = store.remove(StoreSlot::from_raw(1)).expect("remove should succeed");
		assert_eq!(removed, 22);
		assert_eq!(remap, Some((StoreSlot::from_raw(2), StoreSlot::from_raw(1))));
		assert_eq!(store.active_slots(), 2);
		assert_eq!(store.get(StoreSlot::from_raw(0)).expect("slot 0 should exist"), 11);
		assert_eq!(
			store
				.get(StoreSlot::from_raw(1))
				.expect("slot 1 should now be old slot 2"),
			33
		);
		assert!(matches!(store.get(StoreSlot::from_raw(2)), Err(Error::NoEntry)));

		let d = store.try_store(44).expect("insert after remove should succeed");
		assert_eq!(d, StoreSlot::from_raw(2));
		assert_eq!(store.get(StoreSlot::from_raw(2)).expect("slot 2 should exist"), 44);
	}

	#[test]
	fn remove_last_slot_reports_no_remap() {
		let mut store = StoreBlock::<u64, 256>::new(PageId(0));
		store.try_store(11).expect("insert should succeed");
		let b = store.try_store(22).expect("insert should succeed");

		let (removed, remap) = store.remove(b).expect("remove should succeed");
		assert_eq!(removed, 22);
		assert_eq!(remap, None);
		assert_eq!(store.active_slots(), 1);
		assert_eq!(store.get(StoreSlot::from_raw(0)).expect("slot 0 should exist"), 11);
	}

	#[test]
	fn error_display_uses_pager_style() {
		assert_eq!(Error::NoSpace.to_string(), "not enough free space to store entry");
	}

	#[test]
	fn deserialize_error_display_includes_source_detail() {
		let source = postcard::from_bytes::<u8>(&[]).expect_err("empty input should fail to deserialize");
		let source_text = source.to_string();

		assert_eq!(
			Error::Deserialize(source).to_string(),
			format!("deserialize failed: {source_text}")
		);
	}

	#[test]
	fn slots_iterate_in_order_after_swap_remove() {
		let mut store = StoreBlock::<u64, 256>::new(PageId(0));
		store.try_store(11).expect("insert should succeed");
		store.try_store(22).expect("insert should succeed");
		store.try_store(33).expect("insert should succeed");

		let _ = store.remove(StoreSlot::from_raw(1)).expect("remove should succeed");

		let slots = store.slots().collect::<Vec<_>>();
		assert_eq!(slots, vec![StoreSlot::from_raw(0), StoreSlot::from_raw(1)]);
		assert_eq!(store.get(slots[0]).expect("slot 0 should exist"), 11);
		assert_eq!(store.get(slots[1]).expect("slot 1 should exist"), 33);
	}
}
