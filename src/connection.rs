use std::ffi::c_void;

use libc::{size_t, EIO};
use rustls::Session;

use crate::error::rustls_io_error;
use crate::io::{CallbackReader, CallbackWriter, ReadCallback, WriteCallback};

// Call Session::read_tls, providing an &mut dyn Write implemented with a C callback.
pub(crate) fn read_tls(
    session: &mut dyn Session,
    callback: ReadCallback,
    userdata: *mut c_void,
    out_n: &mut size_t,
) -> rustls_io_error {
    let mut reader = CallbackReader { callback, userdata };
    let n_read: usize = match session.read_tls(&mut reader) {
        Ok(n) => n,
        Err(e) => return rustls_io_error(e.raw_os_error().unwrap_or(EIO)),
    };
    *out_n = n_read;

    rustls_io_error(0)
}

// Call Session::write_tls, providing an &mut dyn Write implemented with a C callback.
pub(crate) fn write_tls(
    session: &mut dyn Session,
    callback: WriteCallback,
    userdata: *mut c_void,
    out_n: &mut size_t,
) -> rustls_io_error {
    let mut writer = CallbackWriter { callback, userdata };
    let n_written: usize = match session.write_tls(&mut writer) {
        Ok(n) => n,
        Err(e) => return rustls_io_error(e.raw_os_error().unwrap_or(EIO)),
    };
    *out_n = n_written;

    rustls_io_error(0)
}
