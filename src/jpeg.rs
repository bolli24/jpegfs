use std::{panic, ptr};

use arbitrary::{Arbitrary, Unstructured};
use libc::{c_uchar, c_ulong, c_void, free};
use mozjpeg_sys::*;
use thiserror::Error;

use crate::lsb::block_capacity_bits;

pub type BlockData = [i16; 64];

#[derive(Clone, Debug)]
pub struct OwnedComponent {
	pub width_in_blocks: usize,
	pub height_in_blocks: usize,
	pub blocks: Vec<BlockData>,
}

impl OwnedComponent {
	fn index(&self, row: usize, column: usize) -> usize {
		row * self.width_in_blocks + column
	}
}

#[derive(Clone, Debug)]
pub struct OwnedJpeg {
	pub components: [OwnedComponent; 3],
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum JpegError {
	#[error("only 3-component JPEGs are supported, found {found}")]
	UnsupportedComponentCount { found: i32 },
	#[error(
		"component {component_index} dimensions mismatch: template={template_width}x{template_height}, owned={owned_width}x{owned_height}"
	)]
	ComponentDimensionsMismatch {
		component_index: usize,
		template_width: usize,
		template_height: usize,
		owned_width: usize,
		owned_height: usize,
	},
	#[error("{0}")]
	Libjpeg(String),
	#[error("unknown libjpeg panic")]
	UnknownLibjpegPanic,
}

impl<'a> Arbitrary<'a> for OwnedComponent {
	fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
		let width_in_blocks = usize::from(u.int_in_range::<u8>(1..=8)?);
		let height_in_blocks = usize::from(u.int_in_range::<u8>(1..=8)?);
		let block_count = width_in_blocks * height_in_blocks;
		let mut blocks = Vec::with_capacity(block_count);
		for _ in 0..block_count {
			blocks.push(<BlockData as Arbitrary>::arbitrary(u)?);
		}
		Ok(Self {
			width_in_blocks,
			height_in_blocks,
			blocks,
		})
	}
}

impl<'a> Arbitrary<'a> for OwnedJpeg {
	fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
		Ok(Self {
			components: [
				OwnedComponent::arbitrary(u)?,
				OwnedComponent::arbitrary(u)?,
				OwnedComponent::arbitrary(u)?,
			],
		})
	}
}

impl OwnedJpeg {
	pub fn capacity(&self) -> usize {
		let total_bits = self
			.components
			.iter()
			.flat_map(|component| component.blocks.iter())
			.map(block_capacity_bits)
			.sum::<usize>();
		total_bits / 8
	}

	pub fn component_capacity(&self) -> [usize; 3] {
		let mut component_bits = [0usize; 3];
		for (idx, component) in self.components.iter().enumerate() {
			component_bits[idx] = component.blocks.iter().map(block_capacity_bits).sum::<usize>() / 8;
		}
		component_bits
	}
}

pub fn get_capacity(jpeg_data: &[u8]) -> Result<usize, JpegError> {
	let owned = unsafe { read_owned_jpeg(jpeg_data)? };
	Ok(owned.capacity())
}

pub fn get_component_capacity(jpeg_data: &[u8]) -> Result<[usize; 3], JpegError> {
	let owned = unsafe { read_owned_jpeg(jpeg_data)? };
	Ok(owned.component_capacity())
}

pub unsafe fn read_owned_jpeg(jpeg_data: &[u8]) -> Result<OwnedJpeg, JpegError> {
	let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
		let mut err: jpeg_error_mgr = std::mem::zeroed();
		jpeg_std_error(&mut err);
		err.error_exit = Some(custom_error_exit);

		with_decompressor(
			jpeg_data,
			&mut err,
			|_| {},
			|srcinfo: &mut jpeg_decompress_struct, coef_arrays| {
				if srcinfo.num_components != 3 {
					panic::panic_any(JpegError::UnsupportedComponentCount {
						found: srcinfo.num_components,
					});
				}

				let mut components = std::array::from_fn(|comp_idx| {
					let comp_info = srcinfo.comp_info.add(comp_idx);
					let width_in_blocks = (*comp_info).width_in_blocks as usize;
					let height_in_blocks = (*comp_info).height_in_blocks as usize;
					OwnedComponent {
						width_in_blocks,
						height_in_blocks,
						blocks: vec![[0; 64]; width_in_blocks * height_in_blocks],
					}
				});

				for_each_block_ptr(
					srcinfo,
					coef_arrays,
					false,
					|component_index, row, column, block_ptr| {
						let component = &mut components[component_index];
						let idx = component.index(row, column);
						component.blocks[idx] = *block_ptr;
					},
				);

				OwnedJpeg { components }
			},
		)
	}));

	handle_jpeg_panic(result)
}

pub unsafe fn write_owned_jpeg(template_jpeg: &[u8], owned_jpeg: &OwnedJpeg) -> Result<Vec<u8>, JpegError> {
	let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
		let mut err: jpeg_error_mgr = std::mem::zeroed();
		jpeg_std_error(&mut err);
		err.error_exit = Some(custom_error_exit);

		with_decompressor(
			template_jpeg,
			&mut err,
			|srcinfo| {
				jpeg_save_markers(srcinfo, 0xFE, 0xFFFF);
				for m in 0..16 {
					jpeg_save_markers(srcinfo, 0xE0 + m, 0xFFFF);
				}
			},
			|srcinfo: &mut jpeg_decompress_struct, coef_arrays| {
				if srcinfo.num_components != 3 {
					panic::panic_any(JpegError::UnsupportedComponentCount {
						found: srcinfo.num_components,
					});
				}

				for comp_idx in 0..3usize {
					let comp_info = srcinfo.comp_info.add(comp_idx);
					let width_in_blocks = (*comp_info).width_in_blocks as usize;
					let height_in_blocks = (*comp_info).height_in_blocks as usize;
					let expected = &owned_jpeg.components[comp_idx];
					if width_in_blocks != expected.width_in_blocks || height_in_blocks != expected.height_in_blocks {
						panic::panic_any(JpegError::ComponentDimensionsMismatch {
							component_index: comp_idx,
							template_width: width_in_blocks,
							template_height: height_in_blocks,
							owned_width: expected.width_in_blocks,
							owned_height: expected.height_in_blocks,
						});
					}
				}

				let mut dstinfo: jpeg_compress_struct = std::mem::zeroed();

				dstinfo.common.err = srcinfo.common.err;
				jpeg_create_compress(&mut dstinfo);

				let mut out_buffer: *mut c_uchar = ptr::null_mut();
				let mut out_size: c_ulong = 0;

				jpeg_mem_dest(&mut dstinfo, &mut out_buffer, &mut out_size);

				jpeg_copy_critical_parameters(srcinfo, &mut dstinfo);
				// Force baseline/sequential encoding; avoids progressive AC first/refine passes.
				// 6x performance
				jpeg_c_set_int_param(
					&mut dstinfo,
					J_INT_PARAM::JINT_COMPRESS_PROFILE,
					JINT_COMPRESS_PROFILE_VALUE::JCP_FASTEST as libc::c_int,
				);
				dstinfo.num_scans = 0;
				dstinfo.scan_info = ptr::null();
				dstinfo.optimize_coding = 0;
				jpeg_c_set_bool_param(&mut dstinfo, J_BOOLEAN_PARAM::JBOOLEAN_OPTIMIZE_SCANS, 0);
				jpeg_write_coefficients(&mut dstinfo, coef_arrays);

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

				for_each_block_ptr(srcinfo, coef_arrays, true, |component_index, row, column, block_ptr| {
					let component = &owned_jpeg.components[component_index];
					let idx = component.index(row, column);
					*block_ptr = component.blocks[idx];
				});

				jpeg_finish_compress(&mut dstinfo);
				jpeg_destroy_compress(&mut dstinfo);

				let result_vec = std::slice::from_raw_parts(out_buffer, out_size as usize).to_vec();
				free(out_buffer as *mut c_void);

				result_vec
			},
		)
	}));

	handle_jpeg_panic(result)
}

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

		panic::panic_any(JpegError::Libjpeg(format!("libjpeg error {}: {}", msg_code, error_msg)));
	}
}

fn handle_jpeg_panic<T>(result: std::thread::Result<T>) -> Result<T, JpegError> {
	match result {
		Ok(value) => Ok(value),
		Err(err) => {
			if let Some(err) = err.downcast_ref::<JpegError>() {
				Err(err.clone())
			} else if let Some(msg) = err.downcast_ref::<String>() {
				Err(JpegError::Libjpeg(msg.clone()))
			} else if let Some(msg) = err.downcast_ref::<&str>() {
				Err(JpegError::Libjpeg((*msg).to_string()))
			} else {
				Err(JpegError::UnknownLibjpegPanic)
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
	F: FnMut(usize, usize, usize, *mut BlockData),
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
				visit(comp_idx as usize, row as usize, col as usize, block_ptr);
			}
		}
	}
}
