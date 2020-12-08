#![crate_type = "staticlib"]

extern crate libc;
extern crate rustls;
extern crate webpki;

use libc::{c_char, c_int};
use std::ffi::{CStr, CString};
use std::sync::Arc;

use rustls::{ClientSession, ALL_CIPHERSUITES};

static mut RUSTLS_CONFIG: Option<Arc<rustls::ClientConfig>> = None;

#[no_mangle]
pub extern "C" fn init_rustls() {
    unsafe {
        RUSTLS_CONFIG = Some(Arc::new(rustls::ClientConfig::new()));
    }
}

const CRUSTLS_OK: c_int = 0;
const CRUSTLS_ERROR: c_int = 1;

// Create a new rustls::ClientSession, and return it in the output parameter `out`.
// If this returns an error code, `out` remains unchanged.
// If this returns a non-error, `out` is modified to point at a valid ClientSession.
// The caller now owns the ClientSession and must call `drop_client_session` when
// done with it.
#[no_mangle]
pub extern "C" fn new_client_session(
    hostname: *const c_char,
    out: *mut *const ClientSession,
) -> c_int {
    unsafe {
        if RUSTLS_CONFIG.is_none() {
            eprintln!("RUSTLS_CONFIG not initialized");
            return CRUSTLS_ERROR;
        }
    }
    let hostname: &CStr = unsafe { CStr::from_ptr(hostname) };
    let hostname: &str = match hostname.to_str() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("converting hostname to Rust &str: {}", e);
            return CRUSTLS_ERROR;
        }
    };
    let name_ref = match webpki::DNSNameRef::try_from_ascii_str(hostname) {
        Ok(nr) => nr,
        Err(e) => {
            eprintln!(
                "turning hostname '{}' into webpki::DNSNameRef: {}",
                hostname, e
            );
            return CRUSTLS_ERROR;
        }
    };
    let config = unsafe { RUSTLS_CONFIG.clone().unwrap() };
    let client = ClientSession::new(&config, name_ref);

    // We've succeeded. Put the client on the heap, and transfer ownership
    // to the caller. After this point, we must return CRUSTLS_OK so the
    // caller knows it is responsible for this memory.
    let b = Box::new(client);
    unsafe {
        *out = Box::into_raw(b);
    }

    return CRUSTLS_OK;
}

#[no_mangle]
pub extern "C" fn drop_client_session(ptr: *mut ClientSession) {
    // Convert the pointer to a Box and drop it.
    unsafe { Box::from_raw(ptr) };
    ()
}

#[no_mangle]
pub extern "C" fn print_ciphersuites() {
    println!("Supported ciphersuites in rustls:");
    for cs in ALL_CIPHERSUITES.iter() {
        println!("  {:?}", cs.suite);
    }
    ()
}
