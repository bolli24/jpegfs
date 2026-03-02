#![allow(unsafe_op_in_unsafe_fn, dead_code)]

use std::io::Write;
use std::{fs::File, io::Read};
use std::{panic, ptr};

use libc::{c_uchar, c_ulong, c_void, free};
use mozjpeg_sys::*;

use anyhow::{Context, bail};
use sha256::digest;

const INPUT_PATH: &str = "./test/CRW_2614_(Elsterflutbecken).jpg";
const OUTPUT_PATH: &str = "output.jpg";

fn main() -> anyhow::Result<()> {
	let mut file = File::open(INPUT_PATH).context("Error opening input file.")?;
	let mut content = Vec::<u8>::new();
	file.read_to_end(&mut content).context("Error reading input file.")?;

	println!("Read '{}': {}KiB", INPUT_PATH, content.len() / 1024);
	println!("SHA256: {}", digest(&content));

	let no_op = |_: Block| {};

	let modified_content = unsafe { process_jpeg_blocks(&content, no_op) }?;

	let mut modified = File::create(OUTPUT_PATH).context("Error creating output file.")?;
	modified
		.write_all(&modified_content)
		.context("Error writing output file.")?;

	println!("Wrote '{}': {}KiB", OUTPUT_PATH, modified_content.len() / 1024);
	println!("SHA256: {}", digest(modified_content));

	Ok(())
}

pub struct Block<'a> {
	component_index: usize,
	row: usize,
	column: usize,
	data: &'a mut [i16; 64],
}

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

pub unsafe fn process_jpeg_blocks<F>(jpeg_data: &[u8], mut process_block: F) -> anyhow::Result<Vec<u8>>
where
	F: FnMut(Block),
{
	let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
		let mut err: jpeg_error_mgr = std::mem::zeroed();
		jpeg_std_error(&mut err);

		// 1. Override the fatal error exit function
		err.error_exit = Some(custom_error_exit);

		// 2. Setup Source (Decompressor)
		let mut srcinfo: jpeg_decompress_struct = std::mem::zeroed();
		srcinfo.common.err = &mut err;
		jpeg_create_decompress(&mut srcinfo);

		jpeg_mem_src(&mut srcinfo, jpeg_data.as_ptr(), jpeg_data.len() as c_ulong);

		// Save the COM (Comment) marker
		jpeg_save_markers(&mut srcinfo, 0xFE, 0xFFFF);
		// Save all APP0 through APP15 markers (0xE0 to 0xEF)
		for m in 0..16 {
			jpeg_save_markers(&mut srcinfo, 0xE0 + m, 0xFFFF);
		}

		jpeg_read_header(&mut srcinfo, 1);

		// Read coefficients into virtual arrays
		let coef_arrays = jpeg_read_coefficients(&mut srcinfo);

		// 3. Setup Destination (Compressor)
		let mut dstinfo: jpeg_compress_struct = std::mem::zeroed();

		dstinfo.common.err = &mut err;
		jpeg_create_compress(&mut dstinfo);

		// Setup output buffer for the new JPEG
		let mut out_buffer: *mut c_uchar = ptr::null_mut();
		let mut out_size: c_ulong = 0;

		jpeg_mem_dest(&mut dstinfo, &mut out_buffer, &mut out_size);

		// Copy tables and parameters to prevent re-quantization
		jpeg_copy_critical_parameters(&srcinfo, &mut dstinfo);

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

		// 3. Modify the Coefficients
		for comp_idx in 0..srcinfo.num_components {
			let comp_info = srcinfo.comp_info.add(comp_idx as usize);
			let height_in_blocks = (*comp_info).height_in_blocks;
			let width_in_blocks = (*comp_info).width_in_blocks;
			let comp_coef_array = *coef_arrays.add(comp_idx as usize);

			for row in 0..height_in_blocks {
				// Pass 1 (TRUE) to request WRITE access to the virtual array
				let block_row =
					(*srcinfo.common.mem).access_virt_barray.unwrap()(&mut srcinfo.common, comp_coef_array, row, 1, 1);

				for col in 0..width_in_blocks {
					let block_ptr = (*block_row).add(col as usize);
					// Yield the block and its coordinates to the provided closure
					process_block(Block {
						component_index: comp_idx as usize,
						row: row as usize,
						column: col as usize,
						data: &mut *block_ptr,
					});
				}
			}
		}

		// 4. Finish pipelines
		jpeg_finish_compress(&mut dstinfo);
		jpeg_destroy_compress(&mut dstinfo);
		jpeg_finish_decompress(&mut srcinfo);
		jpeg_destroy_decompress(&mut srcinfo);

		// 5. Copy the C-allocated buffer to a Rust Vec, then free the C buffer
		let result_vec = std::slice::from_raw_parts(out_buffer, out_size as usize).to_vec();
		free(out_buffer as *mut c_void);

		result_vec
	}));

	match result {
		Ok(vec) => Ok(vec),
		Err(err) => {
			// Downcast the panic payload to extract the string we sent from custom_error_exit
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
