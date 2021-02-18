use libc::{c_char, size_t};
use std::{marker::PhantomData, os::raw::{c_ushort}};

/// A read-only view on a Rust byte slice.
///
/// This is used to pass data from crustls to callback functions provided
/// by the user of the API.
/// `len` indicates the number of bytes than can be safely read.
/// A `len` of 0 is used to represent a missing value OR an empty slice.
///
/// The memory exposed is available for the duration of the call (e.g.
/// when passed to a callback) and must be copied if the values are
/// needed for longer.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct rustls_slice_bytes<'a> {
    data: *const u8,
    len: size_t,
    phantom: PhantomData<&'a [u8]>,
}

impl<'a> From<&'a [u8]> for rustls_slice_bytes<'a> {
    fn from(s: &[u8]) -> Self {
        rustls_slice_bytes {
            data: s.as_ptr() as *const u8,
            len: s.len() as size_t,
            phantom: PhantomData,
        }
    }
}

/// A read-only view on a vector of Rust byte slices.
///
/// This is used to pass data from crustls to callback functions provided
/// by the user of the API. The `data` is an array of `rustls_slice_bytes`
/// structures with `len` elements.
///
/// The memory exposed is available for the duration of the call (e.g.
/// when passed to a callback) and must be copied if the values are
/// needed for longer.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct rustls_vec_slice_bytes<'a> {
    data: *const rustls_slice_bytes<'a>,
    len: size_t,
}

impl<'a> From<&'a [&[u8]]> for rustls_vec_slice_bytes<'a> {
    fn from(input: &'a [&[u8]]) -> Self {
        let mut output: Vec<rustls_slice_bytes> = vec![];
        for b in input {
            let b: &[u8] = b;
            output.push(b.into());
        }
        rustls_vec_slice_bytes {
            data: output.as_ptr(),
            len: output.len(),
        }
    }
}

/// A read-only view on a Rust utf-8 string slice.
/// This is used to pass data from crustls to callback functions provided
/// by the user of the API. The `data` is not NUL-terminated.
/// `len` indicates the number of bytes than can be safely read.
/// A `len` of 0 is used to represent a missing value OR an empty string.
///
/// The memory exposed is available for the duration of the call (e.g.
/// when passed to a callback) and must be copied if the values are
/// needed for longer.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct rustls_str<'a> {
    data: *const c_char,
    len: size_t,
    phantom: PhantomData<&'a str>,
}

impl<'a> From<&'a str> for rustls_str<'a> {
    fn from(s: &str) -> Self {
        rustls_str {
            data: s.as_ptr() as *const c_char,
            len: s.len() as size_t,
            phantom: PhantomData,
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct rustls_vec_str<'a> {
    data: *const rustls_str<'a>,
    len: size_t,
}

impl<'a> From<&'a [String]> for rustls_vec_str<'a> {
    fn from(input: &'a [String]) -> Self {
        let mut output: Vec<rustls_str> = vec![];
        for b in input {
            let b: &str = b;
            output.push(b.into());
        }
        rustls_vec_str {
            data: output.as_ptr(),
            len: output.len(),
        }
    }
}

/// A read-only view on a list of Rust owned unsigned short values.
/// This is used to pass data from crustls to callback functions provided
/// by the user of the API. The `data` is an array of `len` 16 bit values.
///
/// The memory exposed is available for the duration of the call (e.g.
/// when passed to a callback) and must be copied if the values are
/// needed for longer.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct rustls_vec_ushort {
    data: *const c_ushort,
    len: size_t,
}

impl From<&Vec<u16>> for rustls_vec_ushort {
    fn from(values: &Vec<u16>) -> Self {
        rustls_vec_ushort {
            data: values.as_ptr(),
            len: values.len(),
        }
    }
}
