use libc::{c_char, size_t};
use std::{marker::PhantomData, os::raw::c_ushort};

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

/// Internal struct that keeps the actual slice_byte data from which
/// we show pointers to in C API callbacks.
///
/// While we indicate with lifetimes that the bytes we point to should live
/// as long as this struct, the rustls_vec_slice_bytes view exposes an
/// array of `rustls_slice_bytes` which does not exist before the view is created.
///
/// Since we do not want to expose the Vec<> itself in the struct, but need
/// to announce all its members to C (so it has a known size), we create a `keeper`
/// around it that holds all necessary, but not visible information.
pub(crate) struct rustls_vec_slice_bytes_keeper<'a> {
    #[allow(dead_code)]
    data: Vec<rustls_slice_bytes<'a>>,
    pub view: rustls_vec_slice_bytes<'a>,
}

impl<'a> rustls_vec_slice_bytes_keeper<'a> {
    pub fn new(slice_data: Vec<rustls_slice_bytes>) -> rustls_vec_slice_bytes_keeper {
        let view = rustls_vec_slice_bytes {
            data: slice_data.as_ptr(),
            len: slice_data.len(),
        };
        rustls_vec_slice_bytes_keeper {
            data: slice_data,
            view: view,
        }
    }
}

impl<'a> From<&'a [&[u8]]> for rustls_vec_slice_bytes_keeper<'a> {
    fn from(input: &'a [&[u8]]) -> Self {
        let mut slice_data: Vec<rustls_slice_bytes> = vec![];
        for b in input {
            let b: &[u8] = b;
            slice_data.push(b.into());
        }
        rustls_vec_slice_bytes_keeper::new(slice_data)
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

/// Internal struct that keeps the actual str data from which
/// we show pointers to in C API callbacks.
pub(crate) struct rustls_vec_str_keeper<'a> {
    #[allow(dead_code)]
    data: Vec<rustls_str<'a>>,
    pub view: rustls_vec_str<'a>,
}

impl<'a> rustls_vec_str_keeper<'a> {
    pub fn new(str_data: Vec<rustls_str>) -> rustls_vec_str_keeper {
        let view = rustls_vec_str {
            data: str_data.as_ptr(),
            len: str_data.len(),
        };
        rustls_vec_str_keeper {
            data: str_data,
            view: view,
        }
    }
}

impl<'a> From<&'a [String]> for rustls_vec_str_keeper<'a> {
    fn from(input: &'a [String]) -> Self {
        let mut output: Vec<rustls_str> = vec![];
        for b in input {
            let b: &str = b;
            output.push(b.into());
        }
        rustls_vec_str_keeper::new(output)
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

impl<'a> From<&'a [u16]> for rustls_vec_ushort {
    fn from(values: &[u16]) -> Self {
        rustls_vec_ushort {
            data: values.as_ptr(),
            len: values.len(),
        }
    }
}

// Should not be necessary, according to:
// https://github.com/abetterinternet/crustls/pull/50#discussion_r578720430
impl<'a> From<&'a Vec<u16>> for rustls_vec_ushort {
    fn from(values: &Vec<u16>) -> Self {
        rustls_vec_ushort {
            data: values.as_ptr(),
            len: values.len(),
        }
    }
}
