#![crate_type = "staticlib"]
use libc::{c_char, size_t};
use std::cmp::min;
use std::slice;

mod client;
mod error;

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
