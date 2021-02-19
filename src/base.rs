use libc::size_t;
use std::os::raw::{c_char, c_uchar, c_ushort};

/// A read-only view on a Rust utf-8 string.
/// This is used to pass strings from crustls to callback functions provided
/// by the user of the API. The `data` is not NUL-terminated.
/// `len` indicates the number of utf-8 bytes than can be safely read.
/// A `len` of 0 is used to represent a missing value.
///
/// The memmory exposed is available for the duration of the call (e.g.
/// when passed to a callback) and must be copied if the values are
/// needed for longer.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct rustls_string {
    data: *const c_char,
    len: size_t,
}

impl<'a> From<&'a str> for rustls_string {
    fn from(s: &str) -> Self {
        rustls_string {
            data: s.as_ptr() as *const c_char,
            len: s.len() as size_t,
        }
    }
}

/// A read-only view on a Rust slice of bytes.
/// This is used to pass data from crustls to callback functions provided
/// by the user of the API. `len` indicates the number of bytes than can
/// be safely read. A `len` of 0 is used to represent a missing value.
///
/// The memmory exposed is available for the duration of the call (e.g.
/// when passed to a callback) and must be copied if the values are
/// needed for longer.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct rustls_bytes {
    data: *const c_uchar,
    len: size_t,
}

impl<'a> From<&'a [u8]> for rustls_bytes {
    fn from(s: &[u8]) -> Self {
        rustls_bytes {
            data: s.as_ptr() as *const c_uchar,
            len: s.len() as size_t,
        }
    }
}

pub(crate) fn rustls_bytes_vec_from_slices<'a>(
    values: Option<&'a [&'a [u8]]>,
) -> Vec<rustls_bytes> {
    let mut strings: Vec<rustls_bytes> = Vec::new();
    match values {
        Some(values) => {
            for entry in values.iter() {
                strings.push(rustls_bytes::from(*entry))
            }
        }
        None => (),
    };
    strings
}

/// A read-only view on a list of Rust bytes.
/// This is used to pass data from crustls to callback functions provided
/// by the user of the API. The `data` is an array of `rustls_bytes`
/// structures with `len` elements.
///
/// The memmory exposed is available for the duration of the call (e.g.
/// when passed to a callback) and must be copied if the values are
/// needed for longer.
///
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct rustls_vec_bytes {
    data: *const rustls_bytes,
    len: size_t,
}

impl<'a> From<&'a Vec<rustls_bytes>> for rustls_vec_bytes {
    fn from(values: &Vec<rustls_bytes>) -> Self {
        rustls_vec_bytes {
            data: values.as_ptr(),
            len: values.len(),
        }
    }
}

/// A read-only view on a list of Rust owned unsigned short values.
/// This is used to pass data from crustls to callback functions provided
/// by the user of the API. The `data` is an array of `len` 16 bit values.
///
/// The memmory exposed is available for the duration of the call (e.g.
/// when passed to a callback) and must be copied if the values are
/// needed for longer.
///
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
