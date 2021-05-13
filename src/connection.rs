use std::ffi::c_void;

use libc::{size_t, EINVAL, EIO};
use rustls::Session;

use crate::error::rustls_io_error;
use crate::io::{CallbackReader, CallbackWriter, ReadCallback, WriteCallback};
use crate::userdata_push;

pub(crate) fn read_tls(
    session: &mut dyn Session,
    callback: ReadCallback,
    userdata: *mut c_void,
    out_n: &mut size_t,
) -> rustls_io_error {
    let guard = match userdata_push(userdata) {
        Ok(g) => g,
        Err(_) => return rustls_io_error(EINVAL),
    };

    let mut reader = CallbackReader(callback);
    let n_read: usize = match session.read_tls(&mut reader) {
        Ok(n) => n,
        Err(e) => return rustls_io_error(e.raw_os_error().unwrap_or(EIO)),
    };
    *out_n = n_read;

    match guard.try_drop() {
        Ok(()) => rustls_io_error(0),
        Err(_) => rustls_io_error(EINVAL),
    }
}

/// https://docs.rs/rustls/0.19.0/rustls/trait.Session.html#tymethod.write_tls
pub(crate) fn write_tls(
    session: &mut dyn Session,
    callback: WriteCallback,
    userdata: *mut c_void,
    out_n: &mut size_t,
) -> rustls_io_error {
    let guard = match userdata_push(userdata) {
        Ok(g) => g,
        Err(_) => return rustls_io_error(EINVAL),
    };

    let mut writer = CallbackWriter(callback);
    let n_written: usize = match session.write_tls(&mut writer) {
        Ok(n) => n,
        Err(e) => return rustls_io_error(e.raw_os_error().unwrap_or(EIO)),
    };
    *out_n = n_written;

    match guard.try_drop() {
        Ok(()) => rustls_io_error(0),
        Err(_) => rustls_io_error(EINVAL),
    }
}
