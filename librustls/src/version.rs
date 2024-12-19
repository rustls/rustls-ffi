use crate::rslice::rustls_str;

// version.rs gets written at compile time by build.rs
include!(concat!(env!("OUT_DIR"), "/version.rs"));

/// Returns a static string containing the rustls-ffi version as well as the
/// rustls version. The string is alive for the lifetime of the program and does
/// not need to be freed.
#[no_mangle]
pub extern "C" fn rustls_version() -> rustls_str<'static> {
    rustls_str::from_str_unchecked(RUSTLS_FFI_VERSION)
}
