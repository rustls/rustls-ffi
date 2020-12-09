#![crate_type = "staticlib"]

extern crate env_logger;
extern crate libc;
extern crate rustls;
extern crate webpki;

use libc::{c_char, c_int, c_void, size_t, ssize_t};
use std::{
    ffi::CStr,
    io::{Cursor, Read},
    slice,
};
use std::{io::Write, sync::Arc};

use rustls::{ClientSession, Session, ALL_CIPHERSUITES};

static mut RUSTLS_CONFIG: Option<Arc<rustls::ClientConfig>> = None;

#[no_mangle]
pub extern "C" fn rustls_init() {
    let mut config = rustls::ClientConfig::new();
    config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    unsafe {
        RUSTLS_CONFIG = Some(Arc::new(config));
    }
    env_logger::init();
}

type CrustlsResult = c_int;

pub const CRUSTLS_OK: c_int = 0;
pub const CRUSTLS_ERROR: c_int = 1;

// Create a new rustls::ClientSession, and return it in the output parameter `out`.
// If this returns an error code, the memory pointed to by `session_out` remains unchanged.
// If this returns a non-error, the memory pointed to by `session_out` is modified to point
// at a valid ClientSession. The caller now owns the ClientSession and must call
// `rustls_client_session_drop` when done with it.
#[no_mangle]
pub extern "C" fn rustls_client_session_new(
    hostname: *const c_char,
    session_out: *mut *const c_void,
) -> CrustlsResult {
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
        *session_out = Box::into_raw(b) as *const c_void;
    }

    return CRUSTLS_OK;
}

#[no_mangle]
pub extern "C" fn rustls_client_session_wants_read(session: *const c_void) -> bool {
    unsafe {
        (session as *const ClientSession)
            .as_ref()
            .map(|cs| cs.wants_read())
            .unwrap_or_default()
    }
}

#[no_mangle]
pub extern "C" fn rustls_client_session_wants_write(session: *const c_void) -> bool {
    unsafe {
        (session as *const ClientSession)
            .as_ref()
            .map(|cs| cs.wants_write())
            .unwrap_or_default()
    }
}

#[no_mangle]
pub extern "C" fn rustls_client_session_process_new_packets(
    session: *const c_void,
) -> CrustlsResult {
    let mut session: Box<ClientSession> = unsafe { Box::from_raw(session as *mut ClientSession) };
    let result: CrustlsResult = match session.process_new_packets() {
        Ok(()) => CRUSTLS_OK,
        Err(e) => {
            eprintln!("ClientSession::process_new_packets: {}", e);
            CRUSTLS_ERROR
        }
    };
    Box::leak(session);
    result
}

#[no_mangle]
pub extern "C" fn rustls_client_session_drop(session: *const c_void) {
    // Convert the pointer to a Box and drop it.
    unsafe { Box::from_raw(session as *mut ClientSession) };
    ()
}

// Write plaintext bytes into the ClientSession. This acts like
// write(2). It returns the number of bytes written, or -1 on error.
#[no_mangle]
pub extern "C" fn rustls_client_session_write(
    session: *const c_void,
    buf: *const u8,
    count: size_t,
) -> ssize_t {
    let mut session: Box<ClientSession> = unsafe { Box::from_raw(session as *mut ClientSession) };
    let write_buf: &[u8] = unsafe {
        assert!(!buf.is_null());
        slice::from_raw_parts(buf, count as usize)
    };
    let n_written: usize = match session.write(write_buf) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("ClientSession::write: {}", e);
            return -1;
        }
    };
    Box::leak(session);
    n_written as ssize_t
}

// Read plaintext bytes from the ClientSession. This acts like
// read(2). It returns the number of bytes read, or -1 on error.
#[no_mangle]
pub extern "C" fn rustls_client_session_read(
    session: *const c_void,
    buf: *mut u8,
    count: size_t,
) -> ssize_t {
    let mut session: Box<ClientSession> = unsafe { Box::from_raw(session as *mut ClientSession) };
    let read_buf: &mut [u8] = unsafe {
        assert!(!buf.is_null());
        slice::from_raw_parts_mut(buf, count as usize)
    };
    let n_read: usize = match session.read(read_buf) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("ClientSession::read: {}", e);
            return -1;
        }
    };
    Box::leak(session);
    n_read as ssize_t
}

// Read TLS bytes taken from a socket into the ClientSession. This acts like
// read(2). It returns the number of bytes read, or -1 on error.
#[no_mangle]
pub extern "C" fn rustls_client_session_read_tls(
    session: *const c_void,
    buf: *const u8,
    count: size_t,
) -> ssize_t {
    let mut session: Box<ClientSession> = unsafe { Box::from_raw(session as *mut ClientSession) };
    let input_buf: &[u8] = unsafe {
        assert!(!buf.is_null());
        slice::from_raw_parts(buf, count as usize)
    };
    let mut cursor = Cursor::new(input_buf);
    let n_read: usize = match session.read_tls(&mut cursor) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("ClientSession::read_tls: {}", e);
            return -1;
        }
    };
    Box::leak(session);
    n_read as ssize_t
}

// Write TLS bytes from the ClientSession into a buffer. Those bytes should then be written to
// a socket. This acts like write(2). It returns the number of bytes read, or -1 on error.
#[no_mangle]
pub extern "C" fn rustls_client_session_write_tls(
    session: *const c_void,
    buf: *mut u8,
    count: size_t,
) -> ssize_t {
    let mut session: Box<ClientSession> = unsafe { Box::from_raw(session as *mut ClientSession) };
    let mut output_buf: &mut [u8] = unsafe {
        assert!(!buf.is_null());
        slice::from_raw_parts_mut(buf, count as usize)
    };
    let n_written: usize = match session.write_tls(&mut output_buf) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("ClientSession::write_tls: {}", e);
            return -1;
        }
    };
    Box::leak(session);
    n_written as ssize_t
}

#[no_mangle]
pub extern "C" fn print_ciphersuites() {
    println!("Supported ciphersuites in rustls:");
    for cs in ALL_CIPHERSUITES.iter() {
        println!("  {:?}", cs.suite);
    }
    ()
}
