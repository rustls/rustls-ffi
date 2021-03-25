#![crate_type = "staticlib"]
#![allow(non_camel_case_types)]
use libc::{c_char, size_t};
use std::cmp::min;
use std::io::ErrorKind::ConnectionAborted;
use std::sync::Arc;
use std::{io, mem, slice};

mod cipher;
mod client;
mod enums;
mod error;
mod panic;
mod rslice;
mod server;
mod session;

use crate::panic::PanicOrDefault;

// Keep in sync with Cargo.toml.
const RUSTLS_CRATE_VERSION: &str = "0.19.0";

/// CastPtr represents the relationship between a snake case type (like rustls_client_session)
/// and the corresponding Rust type (like ClientSession). For each matched pair of types, there
/// should be an `impl CastPtr for foo_bar { RustTy = FooBar }`.
///
/// This allows us to avoid using `as` in most places, and ensure that when we cast, we're
/// preserving const-ness, and casting between the correct types.
/// Implementing this is required in order to use `try_ref_from_ptr!` or
/// `try_mut_from_ptr!`.
pub(crate) trait CastPtr {
    type RustType;

    fn cast_const_ptr(ptr: *const Self) -> *const Self::RustType {
        ptr as *const _
    }

    fn cast_mut_ptr(ptr: *mut Self) -> *mut Self::RustType {
        ptr as *mut _
    }
}

#[macro_export]
macro_rules! try_slice {
    ( $ptr:expr, $count:expr ) => {
        if $ptr.is_null() {
            return crate::panic::NullParameterOrDefault::value();
        } else {
            unsafe { slice::from_raw_parts($ptr, $count as usize) }
        }
    };
}

#[macro_export]
macro_rules! try_mut_slice {
    ( $ptr:expr, $count:expr ) => {
        if $ptr.is_null() {
            return crate::panic::NullParameterOrDefault::value();
        } else {
            unsafe { slice::from_raw_parts_mut($ptr, $count as usize) }
        }
    };
}

/// Turn a raw const pointer into a reference. This is a generic function
/// rather than part of the CastPtr trait because (a) const pointers can't act
/// as "self" for trait methods, and (b) we want to rely on type inference
/// against T (the cast-to type) rather than across F (the from type).
pub(crate) fn try_from<'a, F, T>(from: *const F) -> Option<&'a T>
where
    F: CastPtr<RustType = T>,
{
    unsafe { F::cast_const_ptr(from).as_ref() }
}

/// Turn a raw mut pointer into a mutable reference.
pub(crate) fn try_from_mut<'a, F, T>(from: *mut F) -> Option<&'a mut T>
where
    F: CastPtr<RustType = T>,
{
    unsafe { F::cast_mut_ptr(from).as_mut() }
}

impl CastPtr for size_t {
    type RustType = size_t;
}

/// If the provided pointer is non-null, convert it to a reference.
/// Otherwise, return NullParameter, or an appropriate default (false, 0, NULL)
/// based on the context;
/// Example:
///   let config: &mut ClientConfig = try_ref_from_ptr!(builder);
#[macro_export]
macro_rules! try_ref_from_ptr {
    ( $var:ident ) => {
        match crate::try_from($var) {
            Some(c) => c,
            None => return crate::panic::NullParameterOrDefault::value(),
        }
    };
}

#[macro_export]
macro_rules! try_mut_from_ptr {
    ( $var:ident ) => {
        match crate::try_from_mut($var) {
            Some(c) => c,
            None => return crate::panic::NullParameterOrDefault::value(),
        }
    };
}

/// Write the version of the crustls C bindings and rustls itself into the
/// provided buffer, up to a max of `len` bytes. Output is UTF-8 encoded
/// and NUL terminated. Returns the number of bytes written before the NUL.
#[no_mangle]
pub extern "C" fn rustls_version(buf: *mut c_char, len: size_t) -> size_t {
    ffi_panic_boundary! {
        let write_buf: &mut [u8] = unsafe {
            if buf.is_null() {
                return 0;
            }
            slice::from_raw_parts_mut(buf as *mut u8, len as usize)
        };
        let version: String = format!(
            "crustls/{}/rustls/{}",
            env!("CARGO_PKG_VERSION"),
            RUSTLS_CRATE_VERSION,
        );
        let version: &[u8] = version.as_bytes();
        let len: usize = min(write_buf.len() - 1, version.len());
        write_buf[..len].copy_from_slice(&version[..len]);
        write_buf[len] = 0;
        len
    }
}

/// In rustls_server_config_builder_build, and rustls_client_config_builder_build,
/// we create an Arc, then call `into_raw` and return the resulting raw pointer
/// to C. C can then call rustls_server_session_new multiple times using that
/// same raw pointer. On each call, we need to reconstruct the Arc. But once we reconstruct the Arc,
/// its reference count will be decremented on drop. We need to reference count to stay at 1,
/// because the C code is holding a copy. This function turns the raw pointer back into an Arc,
/// clones it to increment the reference count (which will make it 2 in this particular case), and
/// mem::forgets the clone. The mem::forget prevents the reference count from being decremented when
/// we exit this function, so it will stay at 2 as long as we are in Rust code. Once the caller
/// drops its Arc, the reference count will go back down to 1, indicating the C code's copy.
///
/// Unsafety:
///
/// v must be a non-null pointer that resulted from previously calling `Arc::into_raw`.
unsafe fn arc_with_incref_from_raw<T>(v: *const T) -> Arc<T> {
    let r = Arc::from_raw(v);
    let val = Arc::clone(&r);
    mem::forget(r);
    val
}

pub(crate) fn is_close_notify(e: &io::Error) -> bool {
    e.kind() == ConnectionAborted && e.to_string().contains("CloseNotify")
}
