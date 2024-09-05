use std::io::{Error, IoSlice, Read, Result, Write};

use libc::{c_void, size_t};

use crate::error::rustls_io_result;

/// A callback for `rustls_connection_read_tls`.
///
/// An implementation of this callback should attempt to read up to n bytes from the
/// network, storing them in `buf`. If any bytes were stored, the implementation should
/// set out_n to the number of bytes stored and return 0.
///
/// If there was an error, the implementation should return a nonzero rustls_io_result,
/// which will be passed through to the caller.
///
/// On POSIX systems, returning `errno` is convenient.
///
/// On other systems, any appropriate error code works.
///
/// It's best to make one read attempt to the network per call. Additional reads will
/// be triggered by subsequent calls to one of the `_read_tls` methods.
///
/// `userdata` is set to the value provided to `rustls_connection_set_userdata`.
/// In most cases that should be a struct that contains, at a minimum, a file descriptor.
///
/// The buf and out_n pointers are borrowed and should not be retained across calls.
pub type rustls_read_callback = Option<
    unsafe extern "C" fn(
        userdata: *mut c_void,
        buf: *mut u8,
        n: size_t,
        out_n: *mut size_t,
    ) -> rustls_io_result,
>;

pub(crate) type ReadCallback = unsafe extern "C" fn(
    userdata: *mut c_void,
    buf: *mut u8,
    n: size_t,
    out_n: *mut size_t,
) -> rustls_io_result;

pub(crate) struct CallbackReader {
    pub callback: ReadCallback,
    pub userdata: *mut c_void,
}

impl Read for CallbackReader {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut out_n = 0;
        let cb = self.callback;
        let result = unsafe { cb(self.userdata, buf.as_mut_ptr(), buf.len(), &mut out_n) };
        match result.0 {
            0 => Ok(out_n),
            e => Err(Error::from_raw_os_error(e)),
        }
    }
}

/// A callback for `rustls_connection_write_tls` or `rustls_accepted_alert_write_tls`.
///
/// An implementation of this callback should attempt to write the `n` bytes in buf
/// to the network.
///
/// If any bytes were written, the implementation should set `out_n` to the number of
/// bytes stored and return 0.
///
/// If there was an error, the implementation should return a nonzero `rustls_io_result`,
/// which will be passed through to the caller.
///
/// On POSIX systems, returning `errno` is convenient.
///
/// On other systems, any appropriate error code works.
///
/// It's best to make one write attempt to the network per call. Additional writes will
/// be triggered by subsequent calls to rustls_connection_write_tls.
///
/// `userdata` is set to the value provided to `rustls_connection_set_userdata`. In most
/// cases that should be a struct that contains, at a minimum, a file descriptor.
///
/// The buf and out_n pointers are borrowed and should not be retained across calls.
pub type rustls_write_callback = Option<
    unsafe extern "C" fn(
        userdata: *mut c_void,
        buf: *const u8,
        n: size_t,
        out_n: *mut size_t,
    ) -> rustls_io_result,
>;

pub(crate) type WriteCallback = unsafe extern "C" fn(
    userdata: *mut c_void,
    buf: *const u8,
    n: size_t,
    out_n: *mut size_t,
) -> rustls_io_result;

pub(crate) struct CallbackWriter {
    pub callback: WriteCallback,
    pub userdata: *mut c_void,
}

impl Write for CallbackWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut out_n = 0;
        let cb = self.callback;
        let result = unsafe { cb(self.userdata, buf.as_ptr(), buf.len(), &mut out_n) };
        match result.0 {
            0 => Ok(out_n),
            e => Err(Error::from_raw_os_error(e)),
        }
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// An alias for `struct iovec` from uio.h (on Unix) or `WSABUF` on Windows.
///
/// You should cast `const struct rustls_iovec *` to `const struct iovec *` on
/// Unix, or `const *LPWSABUF` on Windows. See [`std::io::IoSlice`] for details
/// on interoperability with platform specific vectored IO.
pub struct rustls_iovec {
    _private: [u8; 0],
}

/// A callback for `rustls_connection_write_tls_vectored`.
///
/// An implementation of this callback should attempt to write the bytes in
/// the given `count` iovecs to the network.
///
/// If any bytes were written, the implementation should set out_n to the number of
/// bytes written and return 0.
///
/// If there was an error, the implementation should return a nonzero rustls_io_result,
/// which will be passed through to the caller.
///
/// On POSIX systems, returning `errno` is convenient.
///
/// On other systems, any appropriate error code works.
///
/// It's best to make one write attempt to the network per call. Additional write will
/// be triggered by subsequent calls to one of the `_write_tls` methods.
///
/// `userdata` is set to the value provided to `rustls_*_session_set_userdata`. In most
/// cases that should be a struct that contains, at a minimum, a file descriptor.
///
/// The iov and out_n pointers are borrowed and should not be retained across calls.
pub type rustls_write_vectored_callback = Option<
    unsafe extern "C" fn(
        userdata: *mut c_void,
        iov: *const rustls_iovec,
        count: size_t,
        out_n: *mut size_t,
    ) -> rustls_io_result,
>;

pub(crate) type VectoredWriteCallback = unsafe extern "C" fn(
    userdata: *mut c_void,
    iov: *const rustls_iovec,
    count: size_t,
    out_n: *mut size_t,
) -> rustls_io_result;

pub(crate) struct VectoredCallbackWriter {
    pub callback: VectoredWriteCallback,
    pub userdata: *mut c_void,
}

impl Write for VectoredCallbackWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.write_vectored(&[IoSlice::new(buf)])
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> Result<usize> {
        let mut out_n = 0;
        let cb = self.callback;
        let result = unsafe {
            cb(
                self.userdata,
                // This cast is sound because IoSlice is documented to by ABI-compatible with
                // iovec on Unix, and with WSABUF on Windows.
                bufs.as_ptr() as *const rustls_iovec,
                bufs.len(),
                &mut out_n,
            )
        };
        match result.0 {
            0 => Ok(out_n),
            e => Err(Error::from_raw_os_error(e)),
        }
    }
}
