use std::io::{Seek, Write};
use std::path::{Path, PathBuf};
use std::{fs, fs::File, io::Read};

use anyhow::{Context, bail};
use sha256::digest;

use crate::jpeg::{get_capacity, process_jpeg_blocks, read_jpeg_blocks};
use crate::lsb::{LsbReader, LsbWriter};

pub fn init_file(path: &Path) -> anyhow::Result<FileHandle> {
	let mut file = File::open(path).context("Error opening input file.")?;

	let content = FileHandle::read_all_from_file(&mut file)?;
	let capacity = get_capacity(&content).context("Error getting capacity.")?;
	println!("Opened file '{}' capacity: {}", path.display(), capacity);

	Ok(FileHandle {
		file,
		path: path.to_owned(),
		capacity,
	})
}

pub struct FileHandle {
	file: File,
	path: PathBuf,
	capacity: usize,
}

impl FileHandle {
	pub fn capacity(&self) -> usize {
		self.capacity
	}

	fn read_all_from_file(file: &mut File) -> anyhow::Result<Vec<u8>> {
		file.rewind().context("Error rewinding input file")?;
		let mut content = Vec::<u8>::new();
		file.read_to_end(&mut content).context("Error reading input file")?;
		Ok(content)
	}

	fn read_all(&mut self) -> anyhow::Result<Vec<u8>> {
		Self::read_all_from_file(&mut self.file)
	}

	pub fn copy_to(&self, target_path: &Path) -> anyhow::Result<FileHandle> {
		fs::copy(&self.path, target_path).with_context(|| {
			format!(
				"Error copying '{}' to '{}'.",
				self.path.display(),
				target_path.display()
			)
		})?;
		init_file(target_path)
	}

	pub fn write_data(&mut self, data: &[u8]) -> anyhow::Result<()> {
		if data.len() > self.capacity {
			bail!(
				"Not enough capacity to write {} KiB. Only {} KiB available.",
				data.len() / 1024,
				self.capacity / 1024
			);
		}

		let mut writer = LsbWriter::new(data);

		let input_jpeg = self.read_all()?;

		let output_jpeg = unsafe { process_jpeg_blocks(&input_jpeg, &mut writer)? };

		let mut output_file =
			File::create(&self.path).with_context(|| format!("Error creating '{}'.", self.path.display()))?;
		output_file
			.write_all(&output_jpeg)
			.context("Error writing output file.")?;

		println!("Wrote '{}': {}KiB", self.path.display(), output_jpeg.len() / 1024);
		println!("SHA256: {}", digest(output_jpeg));

		Ok(())
	}

	pub fn read_data(&mut self, len: usize) -> anyhow::Result<Vec<u8>> {
		if len > self.capacity {
			bail!(
				"Requested {} KiB exceeds available capacity of {} KiB.",
				len / 1024,
				self.capacity / 1024
			);
		}

		let mut reader = LsbReader::new(len);

		let input_jpeg = self.read_all()?;

		unsafe { read_jpeg_blocks(&input_jpeg, &mut reader)? };

		Ok(reader.finish())
	}
}
