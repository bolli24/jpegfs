#![allow(unsafe_op_in_unsafe_fn, dead_code)]

use std::io::Write;
use std::{fs::File, io::Read};
use std::{panic, ptr};

use libc::{c_uchar, c_ulong, c_void, free};
use mozjpeg_sys::*;

use anyhow::{Context, bail};
use sha256::digest;

use crate::zigzag::ZigZagExt;

pub mod zigzag;

const INPUT_PATH: &str = "./test/CRW_2614_(Elsterflutbecken).jpg";
const OUTPUT_PATH: &str = "./test/output.jpg";

fn main() -> anyhow::Result<()> {
	let mut file = File::open(INPUT_PATH).context("Error opening input file.")?;
	let mut content = Vec::<u8>::new();
	file.read_to_end(&mut content).context("Error reading input file.")?;

	println!("Read '{}': {}KiB", INPUT_PATH, content.len() / 1024);
	println!("SHA256: {}", digest(&content));
	let capacity = get_capacity(&content).context("Error getting capacity.")?;
	println!("Capacity: {} KiB", capacity / 1024);

	let modified_content = add_one(&content)?;

	let mut modified = File::create(OUTPUT_PATH).context("Error creating output file.")?;
	modified
		.write_all(&modified_content)
		.context("Error writing output file.")?;

	println!("Wrote '{}': {}KiB", OUTPUT_PATH, modified_content.len() / 1024);
	println!("SHA256: {}", digest(modified_content));

	Ok(())
}

pub fn add_one(jpeg_data: &[u8]) -> anyhow::Result<Vec<u8>> {
	let mut modified = 0;

	let add = |_: Block, coeffs: &mut BlockData| {
		for c in coeffs.zigzag_mut().skip(5) {
			if *c != -1 && *c != 0 && *c != 1 {
				*c = c.saturating_add(1);
				modified += 1;
			}
		}
	};

	let result = unsafe { process_jpeg_blocks(jpeg_data, add) };

	println!("Modified {modified} bits");
	result
}

pub fn get_capacity(jpeg_data: &[u8]) -> anyhow::Result<usize> {
	Ok(get_component_capacity(jpeg_data)?.iter().sum())
}

pub fn get_component_capacity(jpeg_data: &[u8]) -> anyhow::Result<[usize; 3]> {
	let mut capacity = [0, 0, 0];

	let non_null_coeefs = |block: Block, coeffs: &BlockData| {
		for c in coeffs.zigzag().skip(5) {
			if *c != -1 && *c != 0 && *c != 1 {
				capacity[block.component_index] += 1;
			}
		}
	};

	unsafe {
		read_jpeg_blocks(jpeg_data, non_null_coeefs)?;
	}

	Ok([capacity[0] / 8, capacity[1] / 8, capacity[2] / 8])
}

pub struct Block {
	pub component_index: usize,
	pub row: usize,
	pub column: usize,
}

pub type BlockData = [i16; 64];

// JMSG_LENGTH_MAX is typically 200 in libjpeg
const JMSG_LENGTH_MAX: usize = 200;

extern "C-unwind" fn custom_error_exit(cinfo: &mut jpeg_common_struct) {
	unsafe {
		let err = cinfo.err;
		let msg_code = (*err).msg_code;

		// mozjpeg-sys strictly expects an 80-byte array here
		let mut buffer: [u8; 80] = [0; 80];

		// Pass the references directly; no raw pointer casting needed
		((*err).format_message.unwrap())(cinfo, &mut buffer);

		// Find the C-string null terminator to avoid printing trailing zeros
		let null_pos = buffer.iter().position(|&b| b == 0).unwrap_or(80);
		let error_msg = String::from_utf8_lossy(&buffer[..null_pos]).into_owned();

		panic!("libjpeg error {}: {}", msg_code, error_msg);
	}
}

fn handle_jpeg_panic<T>(result: std::thread::Result<T>) -> anyhow::Result<T> {
	match result {
		Ok(value) => Ok(value),
		Err(err) => {
			if let Some(msg) = err.downcast_ref::<String>() {
				bail!(msg.clone());
			} else if let Some(msg) = err.downcast_ref::<&str>() {
				bail!(msg.to_string());
			} else {
				bail!("Unknown libjpeg panic occurred");
			}
		}
	}
}

unsafe fn with_decompressor<T, C, F>(jpeg_data: &[u8], err: &mut jpeg_error_mgr, mut configure: C, mut body: F) -> T
where
	C: FnMut(&mut jpeg_decompress_struct),
	F: FnMut(&mut jpeg_decompress_struct, *mut *mut jvirt_barray_control) -> T,
{
	let mut srcinfo: jpeg_decompress_struct = std::mem::zeroed();
	srcinfo.common.err = err;
	jpeg_create_decompress(&mut srcinfo);

	jpeg_mem_src(&mut srcinfo, jpeg_data.as_ptr(), jpeg_data.len() as c_ulong);
	configure(&mut srcinfo);
	jpeg_read_header(&mut srcinfo, 1);

	let coef_arrays = jpeg_read_coefficients(&mut srcinfo);
	let output = body(&mut srcinfo, coef_arrays);

	jpeg_finish_decompress(&mut srcinfo);
	jpeg_destroy_decompress(&mut srcinfo);

	output
}

unsafe fn for_each_block_ptr<F>(
	srcinfo: &mut jpeg_decompress_struct,
	coef_arrays: *mut *mut jvirt_barray_control,
	writable: bool,
	mut visit: F,
) where
	F: FnMut(Block, *mut BlockData),
{
	for comp_idx in 0..srcinfo.num_components {
		let comp_info = srcinfo.comp_info.add(comp_idx as usize);
		let height_in_blocks = (*comp_info).height_in_blocks;
		let width_in_blocks = (*comp_info).width_in_blocks;
		let comp_coef_array = *coef_arrays.add(comp_idx as usize);

		for row in 0..height_in_blocks {
			let block_row = (*srcinfo.common.mem).access_virt_barray.unwrap()(
				&mut srcinfo.common,
				comp_coef_array,
				row,
				1,
				if writable { 1 } else { 0 },
			);

			for col in 0..width_in_blocks {
				let block_ptr = (*block_row).add(col as usize);
				visit(
					Block {
						component_index: comp_idx as usize,
						row: row as usize,
						column: col as usize,
					},
					block_ptr,
				);
			}
		}
	}
}

pub unsafe fn process_jpeg_blocks<F>(jpeg_data: &[u8], mut process_block: F) -> anyhow::Result<Vec<u8>>
where
	F: FnMut(Block, &mut BlockData),
{
	let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
		let mut err: jpeg_error_mgr = std::mem::zeroed();
		jpeg_std_error(&mut err);

		// 1. Override the fatal error exit function
		err.error_exit = Some(custom_error_exit);

		with_decompressor(
			jpeg_data,
			&mut err,
			|srcinfo| {
				// Save the COM (Comment) marker
				jpeg_save_markers(srcinfo, 0xFE, 0xFFFF);
				// Save all APP0 through APP15 markers (0xE0 to 0xEF)
				for m in 0..16 {
					jpeg_save_markers(srcinfo, 0xE0 + m, 0xFFFF);
				}
			},
			|srcinfo: &mut jpeg_decompress_struct, coef_arrays| {
				// 3. Setup Destination (Compressor)
				let mut dstinfo: jpeg_compress_struct = std::mem::zeroed();

				dstinfo.common.err = srcinfo.common.err;
				jpeg_create_compress(&mut dstinfo);

				// Setup output buffer for the new JPEG
				let mut out_buffer: *mut c_uchar = ptr::null_mut();
				let mut out_size: c_ulong = 0;

				jpeg_mem_dest(&mut dstinfo, &mut out_buffer, &mut out_size);

				// Copy tables and parameters to prevent re-quantization
				jpeg_copy_critical_parameters(srcinfo, &mut dstinfo);

				// Start the compressor and link the arrays.
				// This writes the SOI marker and readies the writing of data.
				jpeg_write_coefficients(&mut dstinfo, coef_arrays);

				// Walk the linked list of saved markers and write them to the compressor
				// in order to preserve the input image's metadata
				let mut marker = srcinfo.marker_list;
				while !marker.is_null() {
					jpeg_write_marker(
						&mut dstinfo,
						(*marker).marker as libc::c_int,
						(*marker).data,
						(*marker).data_length,
					);
					marker = (*marker).next;
				}

				for_each_block_ptr(srcinfo, coef_arrays, true, |block, block_ptr| {
					process_block(block, &mut *block_ptr);
				});

				jpeg_finish_compress(&mut dstinfo);
				jpeg_destroy_compress(&mut dstinfo);

				// Copy the C-allocated buffer to a Rust Vec, then free the C buffer
				let result_vec = std::slice::from_raw_parts(out_buffer, out_size as usize).to_vec();
				free(out_buffer as *mut c_void);

				result_vec
			},
		)
	}));

	handle_jpeg_panic(result)
}

pub unsafe fn read_jpeg_blocks<F>(jpeg_data: &[u8], mut process_block: F) -> anyhow::Result<()>
where
	F: FnMut(Block, &BlockData),
{
	let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
		let mut err: jpeg_error_mgr = std::mem::zeroed();
		jpeg_std_error(&mut err);

		// 1. Override the fatal error exit function
		err.error_exit = Some(custom_error_exit);

		with_decompressor(
			jpeg_data,
			&mut err,
			|_| {},
			|srcinfo: &mut jpeg_decompress_struct, coef_arrays| {
				if srcinfo.num_components != 3 {
					panic!("Only 3-component JPEGs are supported, found {}", srcinfo.num_components);
				}

				for_each_block_ptr(srcinfo, coef_arrays, false, |block, block_ptr| {
					process_block(block, &*block_ptr);
				});
			},
		);
	}));

	handle_jpeg_panic(result)
}
