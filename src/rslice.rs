use libc::{c_char, size_t};
use std::marker::PhantomData;
use std::{
    convert::{TryFrom, TryInto},
    ptr::null,
};

/// A read-only view on a Rust byte slice.
///
/// This is used to pass data from crustls to callback functions provided
/// by the user of the API.
/// `len` indicates the number of bytes than can be safely read.
///
/// The memory exposed is available as specified by the function
/// using this in its signature. For instance, when this is a parameter to a
/// callback, the lifetime will usually be the duration of the callback.
/// Functions that receive one of these must not dereference the data pointer
/// beyond the allowed lifetime.
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

/// A read-only view of a slice of Rust byte slices.
///
/// This is used to pass data from crustls to callback functions provided
/// by the user of the API. Because Vec and slice are not `#[repr(C)]`, we
/// provide access via a pointer to an opaque struct and an accessor method
/// that acts on that struct to get entries of type `rustls_slice_bytes`.
/// Internally, the pointee is a `&[&[u8]]`.
///
/// The memory exposed is available as specified by the function
/// using this in its signature. For instance, when this is a parameter to a
/// callback, the lifetime will usually be the duration of the callback.
/// Functions that receive one of these must not call its methods beyond the
/// allowed lifetime.
pub struct rustls_slice_slice_bytes<'a> {
    phantom: PhantomData<&'a [&'a [u8]]>,
}

/// Return a pointer to a rustls_slice_slice_bytes representing an input slice.
pub(crate) fn rustls_slice_slice_bytes_new<'a>(
    input: &'a [&'a [u8]],
) -> *const rustls_slice_slice_bytes {
    let output: &&[&[u8]] = &input;
    let output: *const &[&[u8]] = output;
    output as *const rustls_slice_slice_bytes
}

/// Retrieve the nth element from the input slice of slices. If the input
/// pointer is NULL, returns 0.
#[no_mangle]
pub extern "C" fn rustls_slice_slice_bytes_len(input: *const rustls_slice_slice_bytes) -> usize {
    unsafe {
        match (input as *const &[&[u8]]).as_ref() {
            Some(c) => c.len(),
            None => 0,
        }
    }
}

/// Retrieve the nth element from the input slice of slices. If the input
/// pointer is NULL, or n is greater than the length of the
/// rustls_slice_slice_bytes, returns rustls_slice_bytes{NULL, 0}.
#[no_mangle]
pub extern "C" fn rustls_slice_slice_bytes_get(
    input: *const rustls_slice_slice_bytes,
    n: usize,
) -> rustls_slice_bytes {
    let input: &&[&[u8]] = unsafe {
        match (input as *const &[&[u8]]).as_ref() {
            Some(c) => c,
            None => {
                return rustls_slice_bytes {
                    data: null(),
                    len: 0,
                    phantom: PhantomData,
                }
            }
        }
    };
    match input.get(n) {
        Some(rsb) => (*rsb).into(),
        None => rustls_slice_bytes {
            data: null(),
            len: 0,
            phantom: PhantomData,
        },
    }
}

/// A read-only view on a Rust `&str`. The contents are guaranteed to be valid
/// UTF-8. As an additional guarantee on top of Rust's normal UTF-8 guarantee,
/// a `rustls_str` is guaranteed not to contain internal NUL bytes, so it is
/// safe to interpolate into a C string or compare using strncmp. Keep in mind
/// that it is not NUL-terminated.
///
/// The memory exposed is available as specified by the function
/// using this in its signature. For instance, when this is a parameter to a
/// callback, the lifetime will usually be the duration of the callback.
/// Functions that receive one of these must not dereference the data pointer
/// beyond the allowed lifetime.
#[repr(C)]
pub struct rustls_str<'a> {
    pub data: *const c_char,
    pub len: size_t,
    phantom: PhantomData<&'a str>,
}

/// NulByte represents an error converting `&str` to `rustls_str` when the &str
/// contains a NUL.
pub struct NulByte {}

impl<'a> TryFrom<&'a str> for rustls_str<'a> {
    type Error = NulByte;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if s.contains('\0') {
            return Err(NulByte {});
        }
        Ok(rustls_str {
            data: s.as_ptr() as *const c_char,
            len: s.len() as size_t,
            phantom: PhantomData,
        })
    }
}

/// A read-only view of a slice of Rust `&str`.
///
/// This is used to pass data from crustls to callback functions provided
/// by the user of the API. Because Vec and slice are not `#[repr(C)]`, we
/// can't provide a straightforward `data` and `len` structure. Instead, we
/// provide access via a pointer to an opaque struct and accessor methods.
/// Internally, the pointee is a `&[&str]`.
///
/// The memory exposed is available as specified by the function
/// using this in its signature. For instance, when this is a parameter to a
/// callback, the lifetime will usually be the duration of the callback.
/// Functions that receive one of these must not call its methods beyond the
/// allowed lifetime.
pub struct rustls_slice_str<'a> {
    phantom: PhantomData<&'a [&'a str]>,
}

/// Return a pointer to a rustls_slice_str representing a an input slice.
/// If any element of the input slice doesn't mean the `rustls_str` invariant
/// of having no NUL bytes, return NULL.
pub(crate) fn rustls_slice_str_new<'a>(input: &'a [&'a str]) -> *const rustls_slice_str<'a> {
    for &s in input {
        if let Err(NulByte {}) = rustls_str::try_from(s) {
            return null();
        }
    }
    let output: &&[&str] = &input;
    let output: *const &[&str] = output;
    output as *const rustls_slice_str
}

/// Retrieve the nth element from the input slice of slices. If the input
/// pointer is NULL, returns 0.
#[no_mangle]
pub extern "C" fn rustls_slice_str_len(input: *const rustls_slice_str) -> usize {
    unsafe {
        match (input as *const &[&str]).as_ref() {
            Some(c) => c.len(),
            None => 0,
        }
    }
}

/// Retrieve the nth element from the input slice of slices. If the input
/// pointer is NULL, or n is greater than the length of the
/// rustls_slice_slice_bytes, returns rustls_str{NULL, 0}.
#[no_mangle]
pub extern "C" fn rustls_slice_str_get(input: *const rustls_slice_str, n: usize) -> rustls_str {
    let input: &&[&str] = unsafe {
        match (input as *const &[&str]).as_ref() {
            Some(c) => c,
            None => {
                return rustls_str {
                    data: null(),
                    len: 0,
                    phantom: PhantomData,
                }
            }
        }
    };
    input
        .get(n)
        .and_then(|&s| s.try_into().ok())
        .unwrap_or(rustls_str {
            data: null(),
            len: 0,
            phantom: PhantomData,
        })
}

/// A read-only view on a Rust slice of 16-bit integers in platform endianness.
///
/// This is used to pass data from crustls to callback functions provided
/// by the user of the API.
/// `len` indicates the number of bytes than can be safely read.
///
/// The memory exposed is available as specified by the function
/// using this in its signature. For instance, when this is a parameter to a
/// callback, the lifetime will usually be the duration of the callback.
/// Functions that receive one of these must not dereference the data pointer
/// beyond the allowed lifetime.
#[repr(C)]
pub struct rustls_slice_u16<'a> {
    pub data: *const u16,
    pub len: size_t,
    phantom: PhantomData<&'a [u16]>,
}

impl<'a> From<&'a [u16]> for rustls_slice_u16<'a> {
    fn from(s: &[u16]) -> Self {
        rustls_slice_u16 {
            data: s.as_ptr() as *const u16,
            len: s.len() as size_t,
            phantom: PhantomData,
        }
    }
}
