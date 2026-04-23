use std::ptr;

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

// ---------- platform error-handling strategy ----------
//
// On non-MSVC platforms (Linux, macOS, MinGW) we use setjmp/longjmp.
// This is So that errors work with panic=abort (eg. fuzz targets)
//
// On MSVC x64 we use panic/catch_unwind instead because MSVC's _setjmp requires a frame-pointer (cant get that in Rust)
// fuzzing is unix only anyway

#[cfg(not(target_env = "msvc"))]
mod error_impl {
	use std::cell::Cell;

	use libc::{c_int, c_ulong};
	use mozjpeg_sys::*;

	use super::{DecompressGuard, JpegError};

	/// Platform-specific jmp_buf storage.
	/// Oversized to 512 bytes to accommodate different libc across all Linux architectures.
	#[repr(C, align(16))]
	pub struct JmpBuf(pub [u8; 512]);

	unsafe extern "C" {
		pub fn _setjmp(env: *mut JmpBuf) -> c_int;
		fn longjmp(env: *mut JmpBuf, val: c_int) -> !;
	}

	/// Custom mozjpeg error manager. The `mgr` field MUST be first so that C
	/// can cast `cinfo->err` back to `*mut JpegErrorMgr`.
	#[repr(C)]
	pub struct JpegErrorMgr {
		pub mgr: jpeg_error_mgr,
		pub jmp_buf: JmpBuf,
	}

	thread_local! {
		/// Receives the formatted libjpeg error message set just before `longjmp`.
		static JPEG_ERROR: Cell<Option<String>> = const { Cell::new(None) };
	}

	pub unsafe extern "C-unwind" fn jpeg_error_exit(cinfo: &mut jpeg_common_struct) {
		let err = cinfo.err;
		let msg_code = (*err).msg_code;

		let mut buffer = [0u8; 80];
		if let Some(fmt) = (*err).format_message {
			// mozjpeg_sys binds the buffer as `&[u8; 80]` but C writes into it;
			// transmute to the correct mutable signature at the call site.
			let fmt_mut: unsafe extern "C-unwind" fn(&mut jpeg_common_struct, &mut [u8; 80]) = std::mem::transmute(fmt);
			fmt_mut(cinfo, &mut buffer);
		}
		let end = buffer.iter().position(|&b| b == 0).unwrap_or(80);
		let msg = String::from_utf8_lossy(&buffer[..end]).into_owned();
		JPEG_ERROR.with(|e| e.set(Some(format!("libjpeg error {}: {}", msg_code, msg))));

		let err_mgr = cinfo.err as *mut JpegErrorMgr;
		longjmp(&raw mut (*err_mgr).jmp_buf, 1);
	}

	/// Sets up a mozjpeg decompressor, reads DCT coefficients from `jpeg_data`, and calls `body`
	/// Rust objects allocated inside `body` before the error will leak because `longjmp` bypasses drop
	pub unsafe fn with_decompressor<T, C, F>(jpeg_data: &[u8], configure: C, body: F) -> Result<T, JpegError>
	where
		C: FnOnce(&mut jpeg_decompress_struct),
		F: FnOnce(&mut jpeg_decompress_struct, *mut *mut jvirt_barray_control) -> Result<T, JpegError>,
	{
		let mut err_mgr: JpegErrorMgr = std::mem::zeroed();
		jpeg_std_error(&mut err_mgr.mgr);
		err_mgr.mgr.error_exit = Some(jpeg_error_exit);

		let mut srcinfo: jpeg_decompress_struct = std::mem::zeroed();
		srcinfo.common.err = &mut err_mgr.mgr;

		// setjmp before jpeg_create_decompress
		// All libjpeg errors longjmp here so jpeg_destroy_decompress can always be called safely.
		if _setjmp(&raw mut err_mgr.jmp_buf) != 0 {
			jpeg_destroy_decompress(&mut srcinfo);
			let msg = JPEG_ERROR.with(|e| e.take()).unwrap_or_default();
			return Err(JpegError::Libjpeg(msg));
		}

		jpeg_create_decompress(&mut srcinfo);
		// longjmp bypasses drop, so this guard only fires on the normal return path.
		// The setjmp branch above handles cleanup when longjmp is called.
		let _decompress_guard = DecompressGuard(&mut srcinfo as *mut _);
		jpeg_mem_src(&mut srcinfo, jpeg_data.as_ptr(), jpeg_data.len() as c_ulong);
		configure(&mut srcinfo);
		jpeg_read_header(&mut srcinfo, 1);
		let coef_arrays = jpeg_read_coefficients(&mut srcinfo);

		let output = body(&mut srcinfo, coef_arrays);

		if output.is_ok() {
			jpeg_finish_decompress(&mut srcinfo);
		}
		// _decompress_guard drops here, calling jpeg_destroy_decompress.
		output
	}
}

#[cfg(target_env = "msvc")]
mod error_impl {
	use std::cell::Cell;

	use libc::c_ulong;
	use mozjpeg_sys::*;

	use super::{DecompressGuard, JpegError};

	/// Panic payload used to signal a libjpeg error through `catch_unwind`.
	pub struct JpegPanic;

	/// Suppresses the default stderr output for [`JpegPanic`] panics.
	/// Those are controlled errors caught immediately by `catch_unwind`.
	/// Call once at program startup.
	pub fn suppress_jpeg_panic_output() {
		let prev = std::panic::take_hook();
		std::panic::set_hook(Box::new(move |info| {
			if info.payload().downcast_ref::<JpegPanic>().is_none() {
				prev(info);
			}
		}));
	}

	thread_local! {
		static JPEG_PANIC_MSG: Cell<Option<String>> = const { Cell::new(None) };
	}

	pub unsafe extern "C-unwind" fn jpeg_error_exit(cinfo: &mut jpeg_common_struct) {
		let err = cinfo.err;
		let msg_code = (*err).msg_code;

		let mut buffer = [0u8; 80];
		if let Some(fmt) = (*err).format_message {
			let fmt_mut: unsafe extern "C-unwind" fn(&mut jpeg_common_struct, &mut [u8; 80]) = std::mem::transmute(fmt);
			fmt_mut(cinfo, &mut buffer);
		}
		let end = buffer.iter().position(|&b| b == 0).unwrap_or(80);
		let msg = String::from_utf8_lossy(&buffer[..end]).into_owned();
		JPEG_PANIC_MSG.with(|cell| cell.set(Some(format!("libjpeg error {}: {}", msg_code, msg))));
		std::panic::panic_any(JpegPanic);
	}

	pub unsafe fn with_decompressor<T, C, F>(jpeg_data: &[u8], configure: C, body: F) -> Result<T, JpegError>
	where
		C: FnOnce(&mut jpeg_decompress_struct),
		F: FnOnce(&mut jpeg_decompress_struct, *mut *mut jvirt_barray_control) -> Result<T, JpegError>,
	{
		let mut err_mgr: jpeg_error_mgr = std::mem::zeroed();
		jpeg_std_error(&mut err_mgr);
		err_mgr.error_exit = Some(jpeg_error_exit);

		let mut srcinfo: jpeg_decompress_struct = std::mem::zeroed();
		srcinfo.common.err = &mut err_mgr;

		let p = &mut srcinfo as *mut jpeg_decompress_struct;

		let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
			jpeg_create_decompress(&mut *p);
			// Guard fires on both the normal return and panic-unwind paths.
			let _decompress_guard = DecompressGuard(p);
			jpeg_mem_src(&mut *p, jpeg_data.as_ptr(), jpeg_data.len() as c_ulong);
			configure(&mut *p);
			jpeg_read_header(&mut *p, 1);
			let coef_arrays = jpeg_read_coefficients(&mut *p);

			let output = body(&mut *p, coef_arrays);

			if output.is_ok() {
				jpeg_finish_decompress(&mut *p);
			}
			// _decompress_guard drops here on the normal path.
			output
		}));

		match result {
			Ok(output) => output,
			Err(payload) => {
				// _decompress_guard already ran jpeg_destroy_decompress during unwind.
				let msg = JPEG_PANIC_MSG.with(|cell| cell.take());
				if let Some(msg) = msg {
					Err(JpegError::Libjpeg(msg))
				} else {
					std::panic::resume_unwind(payload)
				}
			}
		}
	}
}

#[cfg(target_env = "msvc")]
pub use error_impl::suppress_jpeg_panic_output;

struct CompressGuard(*mut jpeg_compress_struct);

impl Drop for CompressGuard {
	fn drop(&mut self) {
		unsafe { jpeg_destroy_compress(&mut *self.0) }
	}
}

struct DecompressGuard(*mut jpeg_decompress_struct);

impl Drop for DecompressGuard {
	fn drop(&mut self) {
		unsafe { jpeg_destroy_decompress(&mut *self.0) }
	}
}

unsafe fn with_decompressor<T, C, F>(jpeg_data: &[u8], configure: C, body: F) -> Result<T, JpegError>
where
	C: FnOnce(&mut jpeg_decompress_struct),
	F: FnOnce(&mut jpeg_decompress_struct, *mut *mut jvirt_barray_control) -> Result<T, JpegError>,
{
	error_impl::with_decompressor(jpeg_data, configure, body)
}

pub unsafe fn read_owned_jpeg(jpeg_data: &[u8]) -> Result<OwnedJpeg, JpegError> {
	with_decompressor(
		jpeg_data,
		|_| {},
		|srcinfo, coef_arrays| {
			if srcinfo.num_components != 3 {
				return Err(JpegError::UnsupportedComponentCount {
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

			Ok(OwnedJpeg { components })
		},
	)
}

pub unsafe fn write_owned_jpeg(template_jpeg: &[u8], owned_jpeg: &OwnedJpeg) -> Result<Vec<u8>, JpegError> {
	with_decompressor(
		template_jpeg,
		|srcinfo| {
			jpeg_save_markers(srcinfo, 0xFE, 0xFFFF);
			for m in 0..16 {
				jpeg_save_markers(srcinfo, 0xE0 + m, 0xFFFF);
			}
		},
		|srcinfo, coef_arrays| {
			if srcinfo.num_components != 3 {
				return Err(JpegError::UnsupportedComponentCount {
					found: srcinfo.num_components,
				});
			}

			for comp_idx in 0..3usize {
				let comp_info = srcinfo.comp_info.add(comp_idx);
				let width_in_blocks = (*comp_info).width_in_blocks as usize;
				let height_in_blocks = (*comp_info).height_in_blocks as usize;
				let expected = &owned_jpeg.components[comp_idx];
				if width_in_blocks != expected.width_in_blocks || height_in_blocks != expected.height_in_blocks {
					return Err(JpegError::ComponentDimensionsMismatch {
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
			// Guard ensures jpeg_destroy_compress is called even if a mozjpeg error panics below.
			let _compress_guard = CompressGuard(&mut dstinfo as *mut _);

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

			let result_vec = std::slice::from_raw_parts(out_buffer, out_size as usize).to_vec();
			free(out_buffer as *mut c_void);

			// _compress_guard drops here, calling jpeg_destroy_compress.
			Ok(result_vec)
		},
	)
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

#[cfg(test)]
mod tests {
	use super::*;

	const TINY_JPEG: &[u8] = include_bytes!("../fuzz/fixtures/tiny_crw_2609_16x8.jpg");

	#[test]
	fn malformed_jpeg_empty() {
		let err = unsafe { read_owned_jpeg(&[]) }.unwrap_err();
		assert!(matches!(err, JpegError::Libjpeg(_)), "unexpected error: {err}");
	}

	#[test]
	fn malformed_jpeg_truncated_soi() {
		// Just the SOI marker, no further segments
		let err = unsafe { read_owned_jpeg(&[0xFF, 0xD8]) }.unwrap_err();
		assert!(matches!(err, JpegError::Libjpeg(_)), "unexpected error: {err}");
	}

	#[test]
	fn malformed_jpeg_random_garbage() {
		let err = unsafe { read_owned_jpeg(&[0x00, 0x01, 0x02, 0x03, 0xDE, 0xAD]) }.unwrap_err();
		assert!(matches!(err, JpegError::Libjpeg(_)), "unexpected error: {err}");
	}

	#[test]
	fn malformed_jpeg_corrupted_first_byte() {
		let mut corrupted = TINY_JPEG.to_vec();
		corrupted[0] = 0x00; // destroy the 0xFF SOI marker
		let err = unsafe { read_owned_jpeg(&corrupted) }.unwrap_err();
		assert!(matches!(err, JpegError::Libjpeg(_)), "unexpected error: {err}");
	}
}
