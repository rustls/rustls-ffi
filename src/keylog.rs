//! Provides FFI abstractions for the [`rustls::KeyLog`] trait.

use std::ffi::c_int;
use std::fmt;

use crate::rslice::rustls_str;

/// An optional callback for logging key material.
///
/// See the documentation on `rustls_client_config_builder_set_key_log` and
/// `rustls_server_config_builder_set_key_log` for more information about the
/// lifetimes of the parameters.
pub type rustls_keylog_log_callback = Option<
    unsafe extern "C" fn(
        label: rustls_str,
        client_random: *const u8,
        client_random_len: usize,
        secret: *const u8,
        secret_len: usize,
    ),
>;

/// An optional callback for deciding if key material will be logged.
///
/// See the documentation on `rustls_client_config_builder_set_key_log` and
/// `rustls_server_config_builder_set_key_log` for more information about the
/// lifetimes of the parameters.
pub type rustls_keylog_will_log_callback = Option<unsafe extern "C" fn(label: rustls_str) -> c_int>;

/// A type alias for a keylog log callback that has been extracted from an option.
pub(crate) type KeylogLogCallback = unsafe extern "C" fn(
    label: rustls_str,
    client_random: *const u8,
    client_random_len: usize,
    secret: *const u8,
    secret_len: usize,
);

/// An implementation of `rustls::KeyLog` based on C callbacks.
pub(crate) struct CallbackKeyLog {
    // We use the crate-internal rust type here - it is _not_ Option wrapped.
    pub(crate) log_cb: KeylogLogCallback,
    // We use the pub type alias here - it is Option wrapped and may be None.
    pub(crate) will_log_cb: rustls_keylog_will_log_callback,
}

impl rustls::KeyLog for CallbackKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        unsafe {
            (self.log_cb)(
                // Safety: Rustls will never give us a label containing NULL.
                rustls_str::try_from(label).unwrap(),
                client_random.as_ptr(),
                client_random.len(),
                secret.as_ptr(),
                secret.len(),
            );
        }
    }

    fn will_log(&self, label: &str) -> bool {
        match self.will_log_cb {
            Some(cb) => {
                // Safety: Rustls will never give us a label containing NULL.
                let label = rustls_str::try_from(label).unwrap();
                // Log iff the cb returned non-zero.
                !matches!(unsafe { (cb)(label) }, 0)
            }
            // Default to logging everything.
            None => true,
        }
    }
}

impl fmt::Debug for CallbackKeyLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CallbackKeyLog").finish()
    }
}

/// Safety: `CallbackKeyLog` is Send because we don't allocate or deallocate any of its
/// fields.
unsafe impl Send for CallbackKeyLog {}

/// Safety: Verifier is Sync if the C code passes us a callback that
/// obeys the concurrency safety requirements documented in
/// `rustls_client_config_builder_set_key_log` and `rustls_server_config_builder_set_key_log`.
unsafe impl Sync for CallbackKeyLog {}
