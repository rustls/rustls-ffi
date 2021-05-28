use std::io::{Error, Read, Result, Write};

use libc::{c_void, size_t};

use crate::error::rustls_io_result;

/// A callback for rustls_server_session_read_tls or rustls_client_session_read_tls.
/// An implementation of this callback should attempt to read up to n bytes from the
/// network, storing them in `buf`. If any bytes were stored, the implementation should
/// set out_n to the number of bytes stored and return 0. If there was an error,
/// the implementation should return a nonzero rustls_io_result, which will be
/// passed through to the caller. On POSIX systems, returning `errno` is convenient.
/// On other systems, any appropriate error code works.
/// It's best to make one read attempt to the network per call. Additional reads will
/// be triggered by subsequent calls to one of the `_read_tls` methods.
/// `userdata` is set to the value provided to `rustls_*_session_set_userdata`. In most
/// cases that should be a struct that contains, at a minimum, a file descriptor.
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
        let mut out_n: usize = 0;
        let cb = self.callback;
        let result = unsafe { cb(self.userdata, buf.as_mut_ptr(), buf.len(), &mut out_n) };
        match result.0 {
            0 => Ok(out_n),
            e => Err(Error::from_raw_os_error(e)),
        }
    }
}

/// A callback for rustls_server_session_write_tls or rustls_client_session_write_tls.
/// An implementation of this callback should attempt to write the `n` bytes in buf
/// to the network. If any bytes were written, the implementation should
/// set out_n to the number of bytes stored and return 0. If there was an error,
/// the implementation should return a nonzero rustls_io_result, which will be
/// passed through to the caller. On POSIX systems, returning `errno` is convenient.
/// On other systems, any appropriate error code works.
/// (including EAGAIN or EWOULDBLOCK), the implementation should return `errno`.
/// It's best to make one write attempt to the network per call. Additional write will
/// be triggered by subsequent calls to one of the `_write_tls` methods.
/// `userdata` is set to the value provided to `rustls_*_session_set_userdata`. In most
/// cases that should be a struct that contains, at a minimum, a file descriptor.
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
        let mut out_n: usize = 0;
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
