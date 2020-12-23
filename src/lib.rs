#![crate_type = "staticlib"]
use libc::{c_char, size_t, ssize_t};
use std::{
    cmp::min,
    io::{BufReader, Cursor, Read, Write},
};
use std::{ffi::CStr, sync::Arc};
use std::{ffi::OsStr, fs::File, slice};
use std::{io::ErrorKind::ConnectionAborted, mem};

use rustls::{ClientConfig, ClientSession, Session};

#[allow(non_camel_case_types)]
#[repr(C)]
pub enum rustls_result {
    OK = 0,
    ERROR = 1,
}

// We use the opaque struct pattern to tell C about our types without
// telling them what's inside.
// https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs
#[allow(non_camel_case_types)]
pub struct rustls_client_config {
    _private: [u8; 0],
}
#[allow(non_camel_case_types)]
pub struct rustls_client_session {
    _private: [u8; 0],
}

// Keep in sync with Cargo.toml.
const RUSTLS_CRATE_VERSION: &str = "0.19.0";

/// Write the version of the crustls C bindings and rustls itself into the
/// provided buffer, up to a max of `len` bytes. Output is UTF-8 encoded
/// and NUL terminated. Returns the number of bytes written before the NUL.
#[no_mangle]
pub extern "C" fn rustls_version(buf: *mut c_char, len: size_t) -> size_t {
    let write_buf: &mut [u8] = unsafe {
        if buf.is_null() {
            eprintln!("rustls_version: buf was NULL!");
            return 0;
        }
        slice::from_raw_parts_mut(buf as *mut u8, len as usize)
    };
    let version: String = format!(
        "crustls/{}/rustls/{}",
        env!("CARGO_PKG_VERSION"),
        RUSTLS_CRATE_VERSION,
    );
    let version: &[u8] = version.as_bytes();
    let len: usize = min(write_buf.len() - 1, version.len());
    write_buf[..len].copy_from_slice(&version[..len]);
    write_buf[len] = 0;
    len
}

/// Create a rustls_client_config. Caller owns the memory and must free it with
/// rustls_client_config_free. This starts out with no trusted roots.
/// This config may be modified using methods whose names start with
/// rustls_client_config_, but only so long as it is not shared. The config
/// becomes shared as soon as you create a session that relies on it with
/// rustls_client_session_new. The config also becomes shared if you have
/// multiple pointers to the same config.
#[no_mangle]
pub extern "C" fn rustls_client_config_new() -> *mut rustls_client_config {
    let config = rustls::ClientConfig::new();
    env_logger::init();
    Arc::into_raw(Arc::new(config)) as *mut _
}

/// Given a &mut T that originally came from Arc::into_raw, check that the
/// Arc is unshared.
/// This is a best-effort check to prevent mutating a shared Arc. We cannot
/// prevent sharing of the pointer on the C side, and there may be multiple
/// inflight calls racing to modify the contents of the arc.
/// Arc::get_mut doesn't help us, because it relies on `&mut Arc` to ensure
/// it has exclusive access, but we don't get that guarantee so long as C
/// has a copy.
unsafe fn arc_is_unique<T>(input: &mut T) -> bool {
    let arc = arc_with_incref_from_raw(input);
    Arc::strong_count(&arc) == 2 && Arc::weak_count(&arc) == 0
}

/// Add certificates from platform's native root store, using
/// https://github.com/ctz/rustls-native-certs#readme.
/// May only be called when the config is not shared.
#[no_mangle]
pub extern "C" fn rustls_client_config_load_native_roots(
    config: *mut rustls_client_config,
) -> rustls_result {
    let mut config: &mut ClientConfig = unsafe {
        match (config as *mut ClientConfig).as_mut() {
            Some(c) => c,
            None => {
                eprintln!("rustls_client_config_load_native_roots: config was NULL");
                return rustls_result::ERROR;
            }
        }
    };
    unsafe {
        if !arc_is_unique(config) {
            eprintln!("rustls_client_config_load_native_roots: config was shared");
            return rustls_result::ERROR;
        }
    }
    let store = match rustls_native_certs::load_native_certs() {
        Ok(store) => store,
        Err((_, e)) => {
            eprintln!("rustls_client_config_load_native_roots: {}", e);
            return rustls_result::ERROR;
        }
    };
    config.root_store = store;
    rustls_result::OK
}

/// Add trusted root certificates from the named file, which should contain
/// PEM-formatted certificates.
/// May only be called when the config is not shared.
#[no_mangle]
pub extern "C" fn rustls_client_config_load_roots_from_file(
    config: *mut rustls_client_config,
    filename: *const c_char,
) -> rustls_result {
    let filename: &CStr = unsafe {
        if filename.is_null() {
            eprintln!("rustls_client_config_load_roots_from_file: hostname was NULL");
            return rustls_result::ERROR;
        }
        CStr::from_ptr(filename)
    };
    let config: &mut ClientConfig = unsafe {
        match (config as *mut ClientConfig).as_mut() {
            Some(c) => c,
            None => {
                eprintln!("rustls_client_config_load_native_roots: config was NULL");
                return rustls_result::ERROR;
            }
        }
    };
    unsafe {
        if !arc_is_unique(config) {
            eprintln!("rustls_client_config_load_native_roots: config was shared");
            return rustls_result::ERROR;
        }
    }
    let filename: &[u8] = filename.to_bytes();
    let filename: &str = match std::str::from_utf8(filename) {
        Ok(s) => s,
        Err(_) => return rustls_result::ERROR,
    };
    let filename: &OsStr = OsStr::new(filename);
    let mut cafile = match File::open(filename) {
        Ok(f) => f,
        Err(_) => return rustls_result::ERROR,
    };
    let mut bufreader = BufReader::new(&mut cafile);
    match config.root_store.add_pem_file(&mut bufreader) {
        Ok(_) => {}
        Err(_) => {
            eprintln!("rustls_client_config_load_roots_from_file: error reading roots");
            return rustls_result::ERROR;
        }
    };
    rustls_result::OK
}

/// "Free" a client_config previously returned from rustls_client_config_new.
/// Since client_config is actually an atomically reference-counted pointer,
/// extant client_sessions may still hold an internal reference to the
/// Rust object. However, C code must consider this pointer unusable after
/// "free"ing it.
/// Calling with NULL is fine. Must not be called twice with the same value.
#[no_mangle]
pub extern "C" fn rustls_client_config_free(config: *const rustls_client_config) {
    unsafe {
        if let Some(c) = (config as *const ClientConfig).as_ref() {
            // To free the client_config, we reconstruct the Arc. It should have a refcount of 1,
            // representing the C code's copy. When it drops, that refcount will go down to 0
            // and the inner ClientConfig will be dropped.
            let arc: Arc<ClientConfig> = Arc::from_raw(c);
            let strong_count = Arc::strong_count(&arc);
            if strong_count < 1 {
                eprintln!(
                    "rustls_client_config_free: invariant failed: arc.strong_count was < 1: {}. \
                    You must not free the same client_config multiple times.",
                    strong_count
                );
            }
        } else {
            eprintln!("rustls_client_config_free: config was NULL");
        }
    };
}

/// In rustls_client_config_new, we create an Arc, then call `into_raw` and return the resulting raw
/// pointer to C. C can then call rustls_client_session_new multiple times using that same raw
/// pointer. On each call, we need to reconstruct the Arc. But once we reconstruct the Arc, its
/// reference count will be decremented on drop. We need to reference count to stay at 1, because
/// the C code is holding a copy. This function turns the raw pointer back into an Arc, clones it
/// to increment the reference count (which will make it 2 in this particular case), and
/// mem::forgets the clone. The mem::forget prevents the reference count from being decremented when
/// we exit this function, so it will stay at 2 as long as we are in Rust code. Once the caller
/// drops its Arc, the reference count will go back down to 1, indicating the C code's copy.
///
/// Unsafety:
///
/// v must be a non-null pointer that resulted from previously calling `Arc::into_raw`.
unsafe fn arc_with_incref_from_raw<T>(v: *const T) -> Arc<T> {
    let r = Arc::from_raw(v);
    let val = Arc::clone(&r);
    mem::forget(r);
    val
}

/// Create a new rustls::ClientSession, and return it in the output parameter `out`.
/// If this returns an error code, the memory pointed to by `session_out` remains unchanged.
/// If this returns a non-error, the memory pointed to by `session_out` is modified to point
/// at a valid ClientSession. The caller now owns the ClientSession and must call
/// `rustls_client_session_free` when done with it.
#[no_mangle]
pub extern "C" fn rustls_client_session_new(
    config: *const rustls_client_config,
    hostname: *const c_char,
    session_out: *mut *mut rustls_client_session,
) -> rustls_result {
    let hostname: &CStr = unsafe {
        if hostname.is_null() {
            eprintln!("rustls_client_session_new: hostname was NULL");
            return rustls_result::ERROR;
        }
        CStr::from_ptr(hostname)
    };
    let config: Arc<ClientConfig> = unsafe {
        match (config as *const ClientConfig).as_ref() {
            Some(c) => arc_with_incref_from_raw(c),
            None => {
                eprintln!("rustls_client_session_new: config was NULL");
                return rustls_result::ERROR;
            }
        }
    };
    let hostname: &str = match hostname.to_str() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("converting hostname to Rust &str: {}", e);
            return rustls_result::ERROR;
        }
    };
    let name_ref = match webpki::DNSNameRef::try_from_ascii_str(hostname) {
        Ok(nr) => nr,
        Err(e) => {
            eprintln!(
                "turning hostname '{}' into webpki::DNSNameRef: {}",
                hostname, e
            );
            return rustls_result::ERROR;
        }
    };
    let client = ClientSession::new(&config, name_ref);

    // We've succeeded. Put the client on the heap, and transfer ownership
    // to the caller. After this point, we must return CRUSTLS_OK so the
    // caller knows it is responsible for this memory.
    let b = Box::new(client);
    unsafe {
        *session_out = Box::into_raw(b) as *mut _;
    }

    return rustls_result::OK;
}

#[no_mangle]
pub extern "C" fn rustls_client_session_wants_read(session: *const rustls_client_session) -> bool {
    unsafe {
        match (session as *const ClientSession).as_ref() {
            Some(cs) => cs.wants_read(),
            None => false,
        }
    }
}

#[no_mangle]
pub extern "C" fn rustls_client_session_wants_write(session: *const rustls_client_session) -> bool {
    unsafe {
        match (session as *const ClientSession).as_ref() {
            Some(cs) => cs.wants_write(),
            None => false,
        }
    }
}

#[no_mangle]
pub extern "C" fn rustls_client_session_is_handshaking(
    session: *const rustls_client_session,
) -> bool {
    unsafe {
        match (session as *const ClientSession).as_ref() {
            Some(cs) => cs.is_handshaking(),
            None => false,
        }
    }
}

#[no_mangle]
pub extern "C" fn rustls_client_session_process_new_packets(
    session: *mut rustls_client_session,
) -> rustls_result {
    let session: &mut ClientSession = unsafe {
        match (session as *mut ClientSession).as_mut() {
            Some(cs) => cs,
            None => {
                eprintln!("ClientSession::process_new_packets: session was NULL");
                return rustls_result::ERROR;
            }
        }
    };
    match session.process_new_packets() {
        Ok(()) => rustls_result::OK,
        Err(e) => {
            eprintln!("ClientSession::process_new_packets: {}", e);
            return rustls_result::ERROR;
        }
    }
}

/// Free a client_session previously returned from rustls_client_session_new.
/// Calling with NULL is fine. Must not be called twice with the same value.
#[no_mangle]
pub extern "C" fn rustls_client_session_free(session: *mut rustls_client_session) {
    unsafe {
        if let Some(c) = (session as *mut ClientSession).as_mut() {
            // Convert the pointer to a Box and drop it.
            Box::from_raw(c);
        } else {
            eprintln!("warning: rustls_client_config_free: config was NULL");
        }
    }
}

/// Write plaintext bytes into the ClientSession. This acts like
/// write(2). It returns the number of bytes written, or -1 on error.
#[no_mangle]
pub extern "C" fn rustls_client_session_write(
    session: *const rustls_client_session,
    buf: *const u8,
    count: size_t,
) -> ssize_t {
    let session: &mut ClientSession = unsafe {
        match (session as *mut ClientSession).as_mut() {
            Some(cs) => cs,
            None => {
                eprintln!("ClientSession::write: session was NULL");
                return -1;
            }
        }
    };
    let write_buf: &[u8] = unsafe {
        if buf.is_null() {
            eprintln!("ClientSession::write: buf was NULL");
            return -1;
        }
        slice::from_raw_parts(buf, count as usize)
    };
    let n_written: usize = match session.write(write_buf) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("ClientSession::write: {}", e);
            return -1;
        }
    };
    n_written as ssize_t
}

/// Read plaintext bytes from the ClientSession. This acts like
/// read(2), writing the plaintext bytes into `buf`. It returns
/// the number of bytes read, or -1 on error.
#[no_mangle]
pub extern "C" fn rustls_client_session_read(
    session: *const rustls_client_session,
    buf: *mut u8,
    count: size_t,
) -> ssize_t {
    let session: &mut ClientSession = unsafe {
        match (session as *mut ClientSession).as_mut() {
            Some(cs) => cs,
            None => {
                eprintln!("ClientSession::read: session was NULL");
                return -1;
            }
        }
    };
    let read_buf: &mut [u8] = unsafe {
        if buf.is_null() {
            eprintln!("ClientSession::read: buf was NULL");
            return -1;
        }
        slice::from_raw_parts_mut(buf, count as usize)
    };
    // Since it's *possible* for a Read impl to consume the possibly-uninitialized memory from buf,
    // zero it out just in case. TODO: use Initializer once it's stabilized.
    // https://doc.rust-lang.org/nightly/std/io/trait.Read.html#method.initializer
    for c in read_buf.iter_mut() {
        *c = 0;
    }
    let n_read: usize = match session.read(read_buf) {
        Ok(n) => n,
        // The CloseNotify TLS alert is benign, but rustls returns it as an Error. See comment on
        // https://docs.rs/rustls/0.19.0/rustls/struct.ClientSession.html#impl-Read.
        // Log it and return EOF.
        Err(e) if e.kind() == ConnectionAborted && e.to_string().contains("CloseNotify") => {
            eprintln!("ClientSession::read: CloseNotify (this is expected): {}", e);
            return 0;
        }
        Err(e) => {
            eprintln!("ClientSession::read: {}", e);
            return -1;
        }
    };
    n_read as ssize_t
}

/// Read TLS bytes taken from a socket into the ClientSession. This acts like
/// read(2). It returns the number of bytes read, or -1 on error.
#[no_mangle]
pub extern "C" fn rustls_client_session_read_tls(
    session: *const rustls_client_session,
    buf: *const u8,
    count: size_t,
) -> ssize_t {
    let session: &mut ClientSession = unsafe {
        match (session as *mut ClientSession).as_mut() {
            Some(cs) => cs,
            None => {
                eprintln!("ClientSession::read_tls: session was NULL");
                return -1;
            }
        }
    };
    let input_buf: &[u8] = unsafe {
        if buf.is_null() {
            eprintln!("ClientSession::read_tls: buf was NULL");
            return -1;
        }
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
    n_read as ssize_t
}

/// Write TLS bytes from the ClientSession into a buffer. Those bytes should then be written to
/// a socket. This acts like write(2). It returns the number of bytes read, or -1 on error.
#[no_mangle]
pub extern "C" fn rustls_client_session_write_tls(
    session: *const rustls_client_session,
    buf: *mut u8,
    count: size_t,
) -> ssize_t {
    let session: &mut ClientSession = unsafe {
        match (session as *mut ClientSession).as_mut() {
            Some(cs) => cs,
            None => {
                eprintln!("ClientSession::write_tls: session was NULL");
                return -1;
            }
        }
    };
    let mut output_buf: &mut [u8] = unsafe {
        if buf.is_null() {
            eprintln!("ClientSession::write_tls: buf was NULL");
            return -1;
        }
        slice::from_raw_parts_mut(buf, count as usize)
    };
    let n_written: usize = match session.write_tls(&mut output_buf) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("ClientSession::write_tls: {}", e);
            return -1;
        }
    };
    n_written as ssize_t
}
