use libc::{c_char, size_t};
use std::fmt;
use std::marker::PhantomData;
use std::ptr::null;
use std::slice;
use std::str;

/// A read-only view on a Rust byte slice.
///
/// This is used to pass data from rustls-ffi to callback functions provided
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

impl<'a> Default for rustls_slice_bytes<'a> {
    fn default() -> rustls_slice_bytes<'a> {
        Self {
            data: &[0u8; 0] as *const u8,
            len: 0,
            phantom: PhantomData,
        }
    }
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

#[test]
fn test_rustls_slice_bytes() {
    let bytes = b"abcd";
    let rsb: rustls_slice_bytes = bytes.as_ref().into();
    unsafe {
        assert_eq!(*rsb.data, b'a');
        assert_eq!(*rsb.data.offset(3), b'd');
        assert_eq!(rsb.len, 4);
    }
}

/// A read-only view of a slice of Rust byte slices.
///
/// This is used to pass data from rustls-ffi to callback functions provided
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
    pub(crate) inner: &'a [&'a [u8]],
}

/// Return the length of the outer slice. If the input pointer is NULL,
/// returns 0.
#[no_mangle]
pub extern "C" fn rustls_slice_slice_bytes_len(input: *const rustls_slice_slice_bytes) -> size_t {
    match unsafe { input.as_ref() } {
        Some(c) => c.inner.len(),
        None => 0,
    }
}

/// Retrieve the nth element from the input slice of slices.
///
/// If the input pointer is NULL, or n is greater than the length
/// of the `rustls_slice_slice_bytes`, returns rustls_slice_bytes{NULL, 0}.
#[no_mangle]
pub extern "C" fn rustls_slice_slice_bytes_get(
    input: *const rustls_slice_slice_bytes,
    n: size_t,
) -> rustls_slice_bytes {
    let input = {
        match unsafe { input.as_ref() } {
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

#[test]
fn test_rustls_slice_slice_bytes() {
    let many_bytes: Vec<&[u8]> = vec![b"abcd", b"", b"xyz"];
    let rssb = rustls_slice_slice_bytes { inner: &many_bytes };

    assert_eq!(rustls_slice_slice_bytes_len(&rssb), 3);

    assert_eq!(rustls_slice_slice_bytes_get(&rssb, 0).len, 4);
    assert_eq!(rustls_slice_slice_bytes_get(&rssb, 1).len, 0);
    assert_ne!(rustls_slice_slice_bytes_get(&rssb, 1).data, null());
    assert_eq!(rustls_slice_slice_bytes_get(&rssb, 2).len, 3);
    assert_eq!(rustls_slice_slice_bytes_get(&rssb, 3).len, 0);
    assert_eq!(rustls_slice_slice_bytes_get(&rssb, 3).data, null());

    unsafe {
        assert_eq!(*rustls_slice_slice_bytes_get(&rssb, 0).data, b'a');
        assert_eq!(*rustls_slice_slice_bytes_get(&rssb, 0).data.offset(3), b'd');
        assert_eq!(*rustls_slice_slice_bytes_get(&rssb, 2).data, b'x');
        assert_eq!(*rustls_slice_slice_bytes_get(&rssb, 2).data.offset(2), b'z');
    }
}

/// A read-only view on a Rust `&str`.
///
/// The contents are guaranteed to be valid UTF-8.
///
/// As an additional guarantee on top of Rust's normal UTF-8 guarantee,
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
#[derive(Debug)]
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

impl Default for rustls_str<'_> {
    fn default() -> rustls_str<'static> {
        Self::from_str_unchecked("")
    }
}

/// rustls_str represents a string that can be passed to C code.
///
/// The string should not have any internal NUL bytes and is not NUL terminated.
/// C code should not create rustls_str objects, they should only be created in Rust
/// code.
impl rustls_str<'_> {
    pub fn from_str_unchecked(s: &'static str) -> rustls_str<'static> {
        rustls_str {
            data: s.as_ptr() as *const _,
            len: s.len(),
            phantom: PhantomData,
        }
    }

    /// Change a rustls_str's lifetime to 'static.
    ///
    /// This doesn't actually change how long the pointed-to data lives, but
    /// is necessary when returning a rustls_str (as opposed to passing it
    /// into a callback), because Rust can't figure out the "real" lifetime.
    ///
    /// # Safety
    ///
    /// The caller is responsible for requiring (usually via
    /// documentation) that nothing uses the resulting rustls_str past its
    /// actual validity period. The validity period is somewhat ill-defined
    /// at present, but the Stacked Borrows experiment provides one definition,
    /// by which a shared reference is valid until a mutable reference (to
    /// the object or a parent object) is created.
    pub unsafe fn into_static(self) -> rustls_str<'static> {
        std::mem::transmute(self)
    }

    /// Change a rustls_str back to a &str.
    ///
    /// # Safety
    ///
    /// The caller must ensure the rustls_str data is valid utf8
    pub unsafe fn to_str(&self) -> &str {
        str::from_utf8_unchecked(slice::from_raw_parts(self.data as *const u8, self.len))
    }
}

// If the assertion about Rust code being the only creator of rustls_str objects
// changes, you must change this Debug impl, since the assertion in it no longer
// holds.
impl fmt::Debug for rustls_str<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let raw = unsafe {
            // Despite the use of "unsafe", we know that this is safe because:
            // - self.data is a u8, and single bytes are aligned
            // - the entire memory range is a single allocated object, because
            // we always build rustls_str objects from a slice (though this may
            // change if we accept rustls_str objects from C code)
            // - all values are properly initialized because we only init
            // rustls_str objects inside of Rust code
            // - not larger than isize::MAX because, again, it's coming from Rust
            slice::from_raw_parts(self.data as *const u8, self.len)
        };
        let s = str::from_utf8(raw).unwrap_or("%!(ERROR)");
        f.debug_struct("rustls_str")
            .field("data", &s)
            .field("len", &self.len)
            .finish()
    }
}

#[test]
fn test_rustls_str() {
    let s = "abcd";
    let rs: rustls_str = s.try_into().unwrap();
    assert_eq!(rs.len, 4);
    unsafe {
        assert_eq!(*rs.data, 'a' as c_char);
        assert_eq!(*rs.data.offset(3), 'd' as c_char);
    }
    let rs = unsafe { rs.to_str() };
    assert_eq!(rs, s);
}

#[cfg(test)]
mod tests {
    use crate::rslice::*;

    #[test]
    fn test_rustls_str_debug() {
        let s = "abcd";
        let rs: rustls_str = s.try_into().unwrap();
        assert_eq!(
            format!("{:?}", rs),
            r#"rustls_str { data: "abcd", len: 4 }"#
        );
    }
}

#[test]
fn test_rustls_str_rejects_nul() {
    assert!(matches!(rustls_str::try_from("\0"), Err(NulByte {})));
    assert!(matches!(rustls_str::try_from("abc\0"), Err(NulByte {})));
    assert!(matches!(rustls_str::try_from("ab\0cd"), Err(NulByte {})));
}

/// A read-only view of a slice of multiple Rust `&str`'s (that is, multiple
/// strings).
///
/// Like `rustls_str`, this guarantees that each string contains
/// UTF-8 and no NUL bytes. Strings are not NUL-terminated.
///
/// This is used to pass data from rustls-ffi to callback functions provided
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
    pub(crate) inner: &'a [&'a str],
}

/// Return the length of the outer slice.
///
/// If the input pointer is NULL, returns 0.
#[no_mangle]
pub extern "C" fn rustls_slice_str_len(input: *const rustls_slice_str) -> size_t {
    unsafe {
        match input.as_ref() {
            Some(c) => c.inner.len(),
            None => 0,
        }
    }
}

/// Retrieve the nth element from the input slice of `&str`s.
///
/// If the input pointer is NULL, or n is greater than the length of the
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

#[test]
fn test_rustls_slice_str() {
    let many_strings = vec!["abcd", "", "xyz"];
    let rss = rustls_slice_str {
        inner: &many_strings,
    };

    assert_eq!(rustls_slice_str_len(&rss), 3);

    assert_eq!(rustls_slice_str_get(&rss, 0).len, 4);
    assert_eq!(rustls_slice_str_get(&rss, 1).len, 0);
    assert_ne!(rustls_slice_str_get(&rss, 1).data, null());
    assert_eq!(rustls_slice_str_get(&rss, 2).len, 3);
    assert_eq!(rustls_slice_str_get(&rss, 3).len, 0);
    assert_eq!(rustls_slice_str_get(&rss, 3).data, null());

    unsafe {
        assert_eq!(*rustls_slice_str_get(&rss, 0).data, 'a' as c_char);
        assert_eq!(*rustls_slice_str_get(&rss, 0).data.offset(3), 'd' as c_char);
        assert_eq!(*rustls_slice_str_get(&rss, 2).data, 'x' as c_char);
        assert_eq!(*rustls_slice_str_get(&rss, 2).data.offset(2), 'z' as c_char);
    }
}

/// A read-only view on a Rust slice of 16-bit integers in platform endianness.
///
/// This is used to pass data from rustls-ffi to callback functions provided
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

#[test]
fn test_rustls_slice_u16() {
    let u16s = vec![101, 314, 2718];
    let rsu: rustls_slice_u16 = (&*u16s).into();
    assert_eq!(rsu.len, 3);
    unsafe {
        assert_eq!(*rsu.data, 101);
        assert_eq!(*rsu.data.offset(1), 314);
        assert_eq!(*rsu.data.offset(2), 2718);
    }
}
