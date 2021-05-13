use std::io::{Error, Read, Result, Write};

use libc::{c_void, size_t};

use crate::{error::rustls_io_error, userdata_get};

/// A callback for rustls_server_session_read_tls or rustls_client_session_read_tls.
/// An implementation of this callback should attempt to read up to n bytes from the
/// network, storing them in `buf`. If any bytes were stored, the implementation should
/// set out_n to the number of bytes stored and return 0. If there was an error,
/// (including EAGAIN or EWOULDBLOCK), the implementation should return `errno`.
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
        out_n: *mut usize,
    ) -> rustls_io_error,
>;

pub(crate) type ReadCallback = unsafe extern "C" fn(
    userdata: *mut c_void,
    buf: *mut u8,
    n: size_t,
    out_n: *mut usize,
) -> rustls_io_error;

pub(crate) struct CallbackReader(pub(crate) ReadCallback);

impl Read for CallbackReader {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let userdata = userdata_get().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Other, "internal error getting userdata")
        })?;
        let mut out_n: usize = 0;
        let result = unsafe { self.0(userdata, buf.as_mut_ptr(), buf.len(), &mut out_n) };
        match result.0 {
            0 => Ok(out_n),
            e => Err(Error::from_raw_os_error(e)),
        }
    }
}

/// A callback for rustls_server_session_write_tls or rustls_client_session_write_tls.
/// An implementation of this callback should attempt to write the `n` bytes in buf
/// to the network. If any bytes were written, the implementation should set out_n
/// to the number of bytes written and return 0. If there was an error,
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
        out_n: *mut usize,
    ) -> rustls_io_error,
>;

pub(crate) type WriteCallback = unsafe extern "C" fn(
    userdata: *mut c_void,
    buf: *const u8,
    n: size_t,
    out_n: *mut usize,
) -> rustls_io_error;

pub(crate) struct CallbackWriter(pub(crate) WriteCallback);

impl Write for CallbackWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let userdata = userdata_get().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Other, "internal error getting userdata")
        })?;
        let mut out_n: usize = 0;
        let result = unsafe { self.0(userdata, buf.as_ptr(), buf.len(), &mut out_n) };
        match result.0 {
            0 => Ok(out_n),
            e => Err(Error::from_raw_os_error(e)),
        }
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}
