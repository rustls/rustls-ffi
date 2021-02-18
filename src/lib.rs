#![crate_type = "staticlib"]
use libc::{c_char, size_t};
use std::{cmp::min, sync::Arc};
use std::{mem, slice};

mod base;
mod cipher;
mod client;
mod error;
mod server;

// Keep in sync with Cargo.toml.
const RUSTLS_CRATE_VERSION: &str = "0.19.0";

#[macro_export]
macro_rules! ffi_panic_boundary_generic {
    ( $retval:expr, $($tt:tt)* ) => {
        match ::std::panic::catch_unwind(|| {
            $($tt)*
        }) {
            Ok(ret) => ret,
            Err(_) => return $retval,
        }
    }
}

#[macro_export]
macro_rules! ffi_panic_boundary {
    ( $($tt:tt)* ) => {
        match ::std::panic::catch_unwind(|| {
            $($tt)*
        }) {
            Ok(ret) => ret,
            Err(_) => return rustls_result::Panic,
        }
  }
}

#[macro_export]
macro_rules! ffi_panic_boundary_size_t {
    ( $($tt:tt)* ) => {
        ffi_panic_boundary_generic!(0, $($tt)*)
    }
}

#[macro_export]
macro_rules! ffi_panic_boundary_bool {
    ( $($tt:tt)* ) => {
        ffi_panic_boundary_generic!(false, $($tt)*)
    }
}

#[macro_export]
macro_rules! ffi_panic_boundary_ptr {
    ( $($tt:tt)* ) => {
        ffi_panic_boundary_generic!(std::ptr::null_mut(), $($tt)*)
    }
}

#[macro_export]
macro_rules! ffi_panic_boundary_unit {
    ( $($tt:tt)* ) => {
        ffi_panic_boundary_generic!((), $($tt)*)
    }
}

/// If the provided pointer is non-null, convert it to the reference
/// type in the second argument.
/// Otherwise, return NullParameter (in the two-argument form) or the provided
/// value (in the three-argument form).
/// Examples:
///   let config: &mut ClientConfig = try_ref_from_ptr!(builder, &mut ClientConfig,
///        null::<rustls_client_config>());
///   let session: &ClientSession = try_ref_from_ptr!(session, &ClientSession);
///
#[macro_export]
macro_rules! try_ref_from_ptr {
    ( $var:ident, & $typ:ty ) => {
        try_ref_from_ptr!($var, &$typ, rustls_result::NullParameter)
    };
    ( $var:ident, & $typ:ty, $retval: expr ) => {
        unsafe {
            match ($var as *const $typ).as_ref() {
                Some(c) => c,
                None => return $retval,
            }
        };
    };
    ( $var:ident, &mut $typ:ty ) => {
        try_ref_from_ptr!($var, &mut $typ, rustls_result::NullParameter)
    };
    ( $var:ident, &mut $typ:ty, $retval:expr ) => {
        unsafe {
            match ($var as *mut $typ).as_mut() {
                Some(c) => c,
                None => return $retval,
            }
        };
    };
}

/// Write the version of the crustls C bindings and rustls itself into the
/// provided buffer, up to a max of `len` bytes. Output is UTF-8 encoded
/// and NUL terminated. Returns the number of bytes written before the NUL.
#[no_mangle]
pub extern "C" fn rustls_version(buf: *mut c_char, len: size_t) -> size_t {
    ffi_panic_boundary_size_t! {
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
