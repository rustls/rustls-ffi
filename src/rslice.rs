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
            data: s.as_ptr(),
            len: s.len(),
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
pub struct rustls_slice_slice_bytes<'a>{
    pub inner: &'a [&'a [u8]],
}

/// Retrieve the nth element from the input slice of slices. If the input
/// pointer is NULL, returns 0.
#[no_mangle]
pub extern "C" fn rustls_slice_slice_bytes_len(input: *const rustls_slice_slice_bytes) -> size_t {
    unsafe {
        match input.as_ref() {
            Some(c) => c.inner.len(),
            None => 0,
        }
    }
}

/// Retrieve the nth element from the input slice of slices. If the input
/// pointer is NULL, or n is greater than the length of the
/// rustls_slice_slice_bytes, returns rustls_slice_bytes{NULL, 0}.
#[no_mangle]
pub extern "C" fn rustls_slice_slice_bytes_get<'a>(
    input: *const rustls_slice_slice_bytes<'a>,
    n: size_t,
) -> rustls_slice_bytes<'a> {
    let input: &rustls_slice_slice_bytes = unsafe {
        match input.as_ref() {
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
    match input.inner.get(n) {
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
            len: s.len(),
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
pub struct rustls_slice_str<'a>{
    pub inner: &'a [&'a str],
}

/// Retrieve the nth element from the input slice of slices. If the input
/// pointer is NULL, returns 0.
#[no_mangle]
pub extern "C" fn rustls_slice_str_len(input: *const rustls_slice_str) -> size_t {
    unsafe {
        match input.as_ref() {
            Some(c) => c.inner.len(),
            None => 0,
        }
    }
}

/// Retrieve the nth element from the input slice of slices. If the input
/// pointer is NULL, or n is greater than the length of the
/// rustls_slice_str, returns rustls_str{NULL, 0}.
#[no_mangle]
pub extern "C" fn rustls_slice_str_get(input: *const rustls_slice_str, n: size_t) -> rustls_str {
    let input: &rustls_slice_str = unsafe {
        match input.as_ref() {
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
        .inner
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
            data: s.as_ptr(),
            len: s.len(),
            phantom: PhantomData,
        }
    }
}
