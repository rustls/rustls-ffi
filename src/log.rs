use std::convert::TryInto;

use libc::c_void;

use crate::{log_callback_get, rslice::rustls_str};

struct Logger {}

impl log::Log for Logger {
    fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, record: &log::Record<'_>) {
        if let Ok((Some(cb), userdata)) = log_callback_get() {
            let message = format!("{} {} {}", record.target(), record.level(), record.args());
            if let Ok(message) = message.as_str().try_into() {
                unsafe {
                    cb(userdata, &rustls_log_params { message });
                }
            }
        }
    }
    fn flush(&self) {}
}

pub(crate) fn ensure_log_registered() {
    log::set_logger(&Logger {}).ok();
    log::set_max_level(log::LevelFilter::Debug)
}

#[repr(C)]
pub struct rustls_log_params<'a> {
    message: rustls_str<'a>,
}

#[allow(non_camel_case_types)]
pub type rustls_log_callback =
    Option<unsafe extern "C" fn(userdata: *mut c_void, params: *const rustls_log_params)>;
