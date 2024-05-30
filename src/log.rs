use libc::c_void;
use log::Level;

#[cfg(not(feature = "no_log_capture"))]
use crate::log_callback_get;

use crate::rslice::rustls_str;

#[cfg(not(feature = "no_log_capture"))]
struct Logger {}

#[cfg(not(feature = "no_log_capture"))]
impl log::Log for Logger {
    fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, record: &log::Record<'_>) {
        if let Ok((Some(cb), userdata)) = log_callback_get() {
            let message = format!("{} {}", record.target(), record.args());
            if let Ok(message) = message.as_str().try_into() {
                unsafe {
                    cb(
                        userdata,
                        &rustls_log_params {
                            level: record.level() as rustls_log_level,
                            message,
                        },
                    );
                }
            }
        }
    }
    fn flush(&self) {}
}

#[cfg(feature = "no_log_capture")]
pub(crate) fn ensure_log_registered() {}

#[cfg(not(feature = "no_log_capture"))]
pub(crate) fn ensure_log_registered() {
    log::set_logger(&Logger {}).ok();
    log::set_max_level(log::LevelFilter::Debug)
}

pub type rustls_log_level = usize;

/// Return a rustls_str containing the stringified version of a log level.
#[no_mangle]
pub extern "C" fn rustls_log_level_str(level: rustls_log_level) -> rustls_str<'static> {
    let s = match level {
        1 => Level::Error.as_str(),
        2 => Level::Warn.as_str(),
        3 => Level::Info.as_str(),
        4 => Level::Debug.as_str(),
        5 => Level::Trace.as_str(),
        _ => "INVALID",
    };
    rustls_str::from_str_unchecked(s)
}

#[repr(C)]
pub struct rustls_log_params<'a> {
    pub level: rustls_log_level,
    pub message: rustls_str<'a>,
}

#[allow(non_camel_case_types)]
pub type rustls_log_callback =
    Option<unsafe extern "C" fn(userdata: *mut c_void, params: *const rustls_log_params)>;
