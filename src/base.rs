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
    pub data: *const u8,
    pub len: size_t,
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
pub struct rustls_slice_slice_bytes<'a> {
    pub data: *const rustls_slice_bytes<'a>,
    pub len: size_t,
}

/// An immutable slice of slices of bytes that can be read in Rust and C.  
///
/// The Rust `&[&[u8]]` primitive is translated into a `rustls_slice_slice_bytes`
/// view of the same data for C. This involves additional allocation that are
/// kept in the translation, preserving the lifetime of everything involved.
///
/// Note: Rust does not track `x.as_ptr()` which means that usages of the pointer
/// are not counted and `x` is seemingly no longer used afterwards. We pass around
/// a pointer to things in `model_for_c` and need to preserve it. However, for the
/// Rust analyzer this is only dead code.
pub(crate) struct BytesSlicesSliceTranslation<'a> {
    #[allow(dead_code)]
    pub in_rust: &'a [&'a [u8]],
    pub in_c: rustls_slice_slice_bytes<'a>,
    #[allow(dead_code)]
    model_for_c: Vec<rustls_slice_bytes<'a>>,
}

impl<'a> BytesSlicesSliceTranslation<'a> {
    pub fn new(slices: &'a [&'a [u8]]) -> Self {
        let mut model_for_c: Vec<rustls_slice_bytes> = vec![];
        for b in slices {
            let b: &[u8] = b;
            model_for_c.push(b.into());
        }
        BytesSlicesSliceTranslation {
            in_rust: slices,
            in_c: rustls_slice_slice_bytes {
                data: model_for_c.as_ptr(),
                len: model_for_c.len(),
            },
            model_for_c,
        }
    }
}

impl<'a> From<&'a [&[u8]]> for BytesSlicesSliceTranslation<'a> {
    fn from(input: &'a [&[u8]]) -> Self {
        BytesSlicesSliceTranslation::new(input)
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
    pub data: *const c_char,
    pub len: size_t,
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
pub struct rustls_slice_str<'a> {
    pub data: *const rustls_str<'a>,
    pub len: size_t,
}

/// An immutable slice of `str` that can be read in Rust and C.  
///
/// The Rust `&[&str]` primitive is translated into a `rustls_slice_str`
/// view of the same data for C. This involves additional allocation that are
/// kept in the translation, preserving the lifetime of everything involved.
///
/// Note: Rust does not track `x.as_ptr()` which means that usages of the pointer
/// are not counted and `x` is seemingly no longer used afterwards. We pass around
/// a pointer to things in `model_for_c` and need to preserve it. However, for the
/// Rust analyzer this is only dead code.
/// Internal struct that keeps the actual str data from which
/// we show pointers to in C API callbacks.
pub(crate) struct StrSliceTranslation<'a> {
    pub in_rust: &'a [&'a str],
    pub in_c: rustls_slice_str<'a>,
    #[allow(dead_code)]
    model_for_c: Vec<rustls_str<'a>>,
}

impl<'a> StrSliceTranslation<'a> {
    pub fn new(slice: &'a [&'a str]) -> StrSliceTranslation {
        let mut model_for_c: Vec<rustls_str> = vec![];
        for b in slice {
            let b: &str = b;
            model_for_c.push(b.into());
        }
        StrSliceTranslation {
            in_rust: slice,
            in_c: rustls_slice_str {
                data: model_for_c.as_ptr(),
                len: model_for_c.len(),
            },
            model_for_c,
        }
    }
}

impl<'a> From<&'a [&'a str]> for StrSliceTranslation<'a> {
    fn from(input: &'a [&str]) -> Self {
        StrSliceTranslation::new(input)
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
