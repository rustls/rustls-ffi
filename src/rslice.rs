use libc::{c_char, size_t};
use std::convert::{TryFrom, TryInto};
use std::marker::PhantomData;

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

/// An owned Vec<rustls_slice_bytes>, where the inner slices have lifetime 'a.
/// If we want to share a view of a `Vec<Vec<_>>` with C, we can't do it
/// directly because `Vec` is not #[repr(C)]. So we build a new Vec containing
/// rustls_slice_bytes<'a> as an owned object. We can then expose slices of
/// that Vec to C.
pub(crate) struct VecSliceBytes<'a>(Vec<rustls_slice_bytes<'a>>);

impl<'a> VecSliceBytes<'a> {
    /// Build a VecSliceBytes that refers to `input` and can live as long as
    /// it does.
    fn new(input: &'a Vec<Vec<u8>>) -> Self {
        let mut vv: Vec<rustls_slice_bytes> = vec![];
        for v in input {
            let v: &[u8] = v.as_ref();
            vv.push(v.into());
        }
        VecSliceBytes(vv)
    }
}

/// A read-only view of a slice of Rust byte slices.
///
/// This is used to pass data from crustls to callback functions provided
/// by the user of the API. The `data` is an array of `rustls_slice_bytes`
/// structures with `len` elements.
///
/// The memory exposed is available as specified by the function
/// using this in its signature. For instance, when this is a parameter to a
/// callback, the lifetime will usually be the duration of the callback.
/// Functions that receive one of these must not dereference any of the
/// involved data pointers beyond the allowed lifetime.
#[repr(C)]
pub struct rustls_slice_slice_bytes<'a> {
    data: *const rustls_slice_bytes<'a>,
    len: size_t,
    phantom: PhantomData<&'a [rustls_slice_bytes<'a>]>,
}

impl<'a> From<&'a VecSliceBytes<'a>> for rustls_slice_slice_bytes<'a> {
    fn from(input: &'a VecSliceBytes<'a>) -> Self {
        rustls_slice_slice_bytes {
            data: input.0.as_ptr(),
            len: input.0.len(),
            phantom: PhantomData,
        }
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

impl<'a> TryFrom<&'a str> for rustls_str<'a> {
    type Error = ();

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if s.contains('\0') {
            return Err(());
        }
        Ok(rustls_str {
            data: s.as_ptr() as *const c_char,
            len: s.len() as size_t,
            phantom: PhantomData,
        })
    }
}

/// An owned Vec<rustls_str>, where the inner slices have lifetime 'a.
/// See comment on VecSliceBytes for more information.
pub(crate) struct VecStr<'a>(Vec<rustls_str<'a>>);

impl<'a> VecStr<'a> {
    /// Build a VecStr that refers to `input` and can live as long as it does.
    fn new(input: &'a Vec<&str>) -> Result<Self, ()> {
        let mut vs: Vec<rustls_str> = vec![];
        for v in input {
            let v: &str = v.as_ref();
            vs.push(v.try_into()?);
        }
        Ok(VecStr(vs))
    }
}

/// A read-only view of a slice of Rust `&str`
///
/// This is used to pass data from crustls to callback functions provided
/// by the user of the API. The `data` is an array of `rustls_str`
/// structures with `len` elements.
///
/// The memory exposed is available as specified by the function
/// using this in its signature. For instance, when this is a parameter to a
/// callback, the lifetime will usually be the duration of the callback.
/// Functions that receive one of these must not dereference any of the
/// involved pointers beyond the allowed lifetime.
#[repr(C)]
pub struct rustls_slice_str<'a> {
    pub data: *const rustls_str<'a>,
    pub len: size_t,
    phantom: PhantomData<&'a [rustls_str<'a>]>,
}

impl<'a> From<&'a VecStr<'a>> for rustls_slice_str<'a> {
    fn from(input: &'a VecStr<'a>) -> Self {
        rustls_slice_str {
            data: input.0.as_ptr(),
            len: input.0.len(),
            phantom: PhantomData,
        }
    }
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
