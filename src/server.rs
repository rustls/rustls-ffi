use libc::size_t;
use std::io::ErrorKind::ConnectionAborted;
use std::io::{Cursor, Read, Write};
use std::ptr::null;
use std::slice;
use std::sync::Arc;

use rustls::{Certificate, NoClientAuth, PrivateKey, ServerConfig, ServerSession, Session};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};

use crate::arc_with_incref_from_raw;
use crate::error::{map_error, rustls_result};
use crate::{
    ffi_panic_boundary, ffi_panic_boundary_bool, ffi_panic_boundary_generic,
    ffi_panic_boundary_ptr, ffi_panic_boundary_unit, try_ref_from_ptr,
};
use rustls_result::NullParameter;

/// A server config being constructed. A builder can be modified by,
/// e.g. rustls_server_config_builder_load_native_roots. Once you're
/// done configuring settings, call rustls_server_config_builder_build
/// to turn it into a *rustls_server_config. This object is not safe
/// for concurrent mutation. Under the hood, it corresponds to a
/// Box<ServerConfig>.
/// https://docs.rs/rustls/0.19.0/rustls/struct.ServerConfig.html
#[allow(non_camel_case_types)]
pub struct rustls_server_config_builder {
    // We use the opaque struct pattern to tell C about our types without
    // telling them what's inside.
    // https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs
    _private: [u8; 0],
}

/// A server config that is done being constructed and is now read-only.
/// Under the hood, this object corresponds to an Arc<ServerConfig>.
/// https://docs.rs/rustls/0.19.0/rustls/struct.ServerConfig.html
#[allow(non_camel_case_types)]
pub struct rustls_server_config {
    // We use the opaque struct pattern to tell C about our types without
    // telling them what's inside.
    // https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs
    _private: [u8; 0],
}

#[allow(non_camel_case_types)]
pub struct rustls_server_session {
    _private: [u8; 0],
}

/// Create a rustls_server_config_builder. Caller owns the memory and must
/// eventually call rustls_server_config_builder_build, then free the
/// resulting rustls_server_config. This starts out with no trusted roots.
/// Caller must add roots with rustls_server_config_builder_load_native_roots
/// or rustls_server_config_builder_load_roots_from_file.
/// https://docs.rs/rustls/0.19.0/rustls/struct.ServerConfig.html#method.new
#[no_mangle]
pub extern "C" fn rustls_server_config_builder_new() -> *mut rustls_server_config_builder {
    ffi_panic_boundary_ptr! {
        let config = rustls::ServerConfig::new(Arc::new(NoClientAuth));
        let b = Box::new(config);
        Box::into_raw(b) as *mut _
    }
}

/// With `ignore` != 0, the server will ignore the client ordering of cipher
/// suites, aka preference, during handshake and respect its own ordering
/// as configured.
/// https://docs.rs/rustls/0.19.0/rustls/struct.ServerConfig.html#fields
#[no_mangle]
pub extern "C" fn rustls_server_config_builder_set_ignore_client_order(
    builder: *mut rustls_server_config_builder,
    ignore: bool,
) -> rustls_result {
    ffi_panic_boundary! {
        let config: &mut ServerConfig = try_ref_from_ptr!(builder, &mut ServerConfig);
        config.ignore_client_order = ignore;
        rustls_result::Ok
    }
}

/// Sets a single certificate chain and matching private key.
/// This certificate and key is used for all subsequent connections,
/// irrespective of things like SNI hostname.
/// cert_chain must point to a byte array of length cert_chain_len containing
/// a series of PEM-encoded certificates, with the end-entity certificate
/// first.
/// private_key must point to a byte array of length private_key_len containing
/// a private key in PEM-encoded PKCS#8 or PKCS#1 format.
#[no_mangle]
pub extern "C" fn rustls_server_config_builder_set_single_cert_pem(
    builder: *mut rustls_server_config_builder,
    cert_chain: *const u8,
    cert_chain_len: size_t,
    private_key: *const u8,
    private_key_len: size_t,
) -> rustls_result {
    ffi_panic_boundary! {
        let config: &mut ServerConfig = try_ref_from_ptr!(builder, &mut ServerConfig);
        let mut cert_chain: &[u8] = unsafe {
            if cert_chain.is_null() {
                return NullParameter;
            }
            slice::from_raw_parts(cert_chain, cert_chain_len as usize)
        };
        let private_key: &[u8] = unsafe {
            if private_key.is_null() {
                return NullParameter;
            }
            slice::from_raw_parts(private_key, private_key_len as usize)
        };
        let mut private_keys: Vec<Vec<u8>> = match pkcs8_private_keys(&mut Cursor::new(private_key)) {
            Ok(v) => v,
            _ => match rsa_private_keys(&mut Cursor::new(private_key)) {
                Ok(v) => v,
                Err(_) => return rustls_result::PrivateKeyParseError,
            }
        };
        let private_key: PrivateKey = match private_keys.pop() {
            Some(p) => PrivateKey(p),
            None => return rustls_result::PrivateKeyParseError,
        };
        let parsed_chain: Vec<Certificate> = match certs(&mut cert_chain) {
            Ok(v) => v.into_iter().map(Certificate).collect(),
            Err(_) => return rustls_result::CertificateParseError,
        };
        match config.set_single_cert(parsed_chain, private_key) {
            Ok(()) => rustls_result::Ok,
            Err(e) => map_error(e),
        }
    }
}

/// Turn a *rustls_server_config_builder (mutable) into a *rustls_server_config
/// (read-only).
#[no_mangle]
pub extern "C" fn rustls_server_config_builder_build(
    builder: *mut rustls_server_config_builder,
) -> *const rustls_server_config {
    ffi_panic_boundary_ptr! {
        let config: &mut ServerConfig = try_ref_from_ptr!(builder, &mut ServerConfig,
             null::<rustls_server_config>());
        let b = unsafe { Box::from_raw(config) };
        Arc::into_raw(Arc::new(*b)) as *const _
    }
}

/// "Free" a server_config previously returned from
/// rustls_server_config_builder_build. Since server_config is actually an
/// atomically reference-counted pointer, extant server_sessions may still
/// hold an internal reference to the Rust object. However, C code must
/// consider this pointer unusable after "free"ing it.
/// Calling with NULL is fine. Must not be called twice with the same value.
#[no_mangle]
pub extern "C" fn rustls_server_config_free(config: *const rustls_server_config) {
    ffi_panic_boundary_unit! {
        let config: &ServerConfig = try_ref_from_ptr!(config, &mut ServerConfig, ());
        // To free the server_config, we reconstruct the Arc. It should have a refcount of 1,
        // representing the C code's copy. When it drops, that refcount will go down to 0
        // and the inner ServerConfig will be dropped.
        let arc: Arc<ServerConfig> = unsafe { Arc::from_raw(config) };
        let strong_count = Arc::strong_count(&arc);
        if strong_count < 1 {
            eprintln!(
                "rustls_server_config_free: invariant failed: arc.strong_count was < 1: {}. \
                You must not free the same server_config multiple times.",
                strong_count
            );
        }
    }
}

/// Create a new rustls::ServerSession, and return it in the output parameter `out`.
/// If this returns an error code, the memory pointed to by `session_out` remains unchanged.
/// If this returns a non-error, the memory pointed to by `session_out` is modified to point
/// at a valid ServerSession. The caller now owns the ServerSession and must call
/// `rustls_server_session_free` when done with it.
#[no_mangle]
pub extern "C" fn rustls_server_session_new(
    config: *const rustls_server_config,
    session_out: *mut *mut rustls_server_session,
) -> rustls_result {
    ffi_panic_boundary! {
        let config: Arc<ServerConfig> = unsafe {
            match (config as *const ServerConfig).as_ref() {
                Some(c) => arc_with_incref_from_raw(c),
                None => return NullParameter,
            }
        };
        let server = ServerSession::new(&config);

        // We've succeeded. Put the server on the heap, and transfer ownership
        // to the caller. After this point, we must return CRUSTLS_OK so the
        // caller knows it is responsible for this memory.
        let b = Box::new(server);
        unsafe {
            *session_out = Box::into_raw(b) as *mut _;
        }

        return rustls_result::Ok;
    }
}

#[no_mangle]
pub extern "C" fn rustls_server_session_wants_read(session: *const rustls_server_session) -> bool {
    ffi_panic_boundary_bool! {
        let session: &ServerSession = try_ref_from_ptr!(session, &ServerSession, false);
        session.wants_read()
    }
}

#[no_mangle]
pub extern "C" fn rustls_server_session_wants_write(session: *const rustls_server_session) -> bool {
    ffi_panic_boundary_bool! {
        let session: &ServerSession = try_ref_from_ptr!(session, &ServerSession, false);
        session.wants_write()
    }
}

#[no_mangle]
pub extern "C" fn rustls_server_session_is_handshaking(
    session: *const rustls_server_session,
) -> bool {
    ffi_panic_boundary_bool! {
        let session: &ServerSession = try_ref_from_ptr!(session, &ServerSession, false);
        session.is_handshaking()
    }
}

#[no_mangle]
pub extern "C" fn rustls_server_session_process_new_packets(
    session: *mut rustls_server_session,
) -> rustls_result {
    ffi_panic_boundary! {
        let session: &mut ServerSession = try_ref_from_ptr!(session, &mut ServerSession);
        match session.process_new_packets() {
            Ok(()) => rustls_result::Ok,
            Err(e) => return map_error(e),
        }
    }
}

/// Queues a close_notify fatal alert to be sent in the next write_tls call.
/// https://docs.rs/rustls/0.19.0/rustls/trait.Session.html#tymethod.send_close_notify
#[no_mangle]
pub extern "C" fn rustls_server_session_send_close_notify(session: *mut rustls_server_session) {
    ffi_panic_boundary_unit! {
        let session: &mut ServerSession = try_ref_from_ptr!(session, &mut ServerSession, ());
        session.send_close_notify()
    }
}

/// Free a server_session previously returned from rustls_server_session_new.
/// Calling with NULL is fine. Must not be called twice with the same value.
#[no_mangle]
pub extern "C" fn rustls_server_session_free(session: *mut rustls_server_session) {
    ffi_panic_boundary_unit! {
        let session: &mut ServerSession = try_ref_from_ptr!(session, &mut ServerSession, ());
        // Convert the pointer to a Box and drop it.
        unsafe { Box::from_raw(session); }
    }
}

/// Write up to `count` plaintext bytes from `buf` into the ServerSession.
/// This will increase the number of output bytes available to
/// `rustls_server_session_write_tls`.
/// On success, store the number of bytes actually written in *out_n
/// (this may be less than `count`).
/// https://docs.rs/rustls/0.19.0/rustls/struct.ServerSession.html#method.write
#[no_mangle]
pub extern "C" fn rustls_server_session_write(
    session: *mut rustls_server_session,
    buf: *const u8,
    count: size_t,
    out_n: *mut size_t,
) -> rustls_result {
    ffi_panic_boundary! {
        let session: &mut ServerSession = try_ref_from_ptr!(session, &mut ServerSession);
        let write_buf: &[u8] = unsafe {
            if buf.is_null() {
                return NullParameter;
            }
            slice::from_raw_parts(buf, count as usize)
        };
        let out_n: &mut size_t = unsafe {
            match out_n.as_mut() {
                Some(out_n) => out_n,
                None => return NullParameter,
            }
        };
        let n_written: usize = match session.write(write_buf) {
            Ok(n) => n,
            Err(_) => return rustls_result::Io,
        };
        *out_n = n_written;
        rustls_result::Ok
    }
}

/// Read up to `count` plaintext bytes from the ServerSession into `buf`.
/// On success, store the number of bytes read in *out_n (this may be less
/// than `count`). A success with *out_n set to 0 means "all bytes currently
/// available have been read, but more bytes may become available after
/// subsequent calls to rustls_server_session_read_tls and
/// rustls_server_session_process_new_packets."
/// https://docs.rs/rustls/0.19.0/rustls/struct.ServerSession.html#method.read
#[no_mangle]
pub extern "C" fn rustls_server_session_read(
    session: *mut rustls_server_session,
    buf: *mut u8,
    count: size_t,
    out_n: *mut size_t,
) -> rustls_result {
    ffi_panic_boundary! {
        let session: &mut ServerSession = try_ref_from_ptr!(session, &mut ServerSession);
        let read_buf: &mut [u8] = unsafe {
            if buf.is_null() {
                return NullParameter;
            }
            slice::from_raw_parts_mut(buf, count as usize)
        };
        let out_n = unsafe {
            match out_n.as_mut() {
                Some(out_n) => out_n,
                None => return NullParameter,
            }
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
            // https://docs.rs/rustls/0.19.0/rustls/struct.ServerSession.html#impl-Read.
            // Log it and return EOF.
            Err(e) if e.kind() == ConnectionAborted && e.to_string().contains("CloseNotify") => {
                *out_n = 0;
                return rustls_result::Ok;
            }
            Err(_) => return rustls_result::Io,
        };
        *out_n = n_read;
        rustls_result::Ok
    }
}

/// Read up to `count` TLS bytes from `buf` (usually read from a socket) into
/// the ServerSession. This may make packets available to
/// `rustls_server_session_process_new_packets`, which in turn may make more
/// bytes available to `rustls_server_session_read`.
/// On success, store the number of bytes actually read in *out_n (this may
/// be less than `count`). This function returns success and stores 0 in
/// *out_n when the input count is 0.
/// https://docs.rs/rustls/0.19.0/rustls/trait.Session.html#tymethod.read_tls
#[no_mangle]
pub extern "C" fn rustls_server_session_read_tls(
    session: *mut rustls_server_session,
    buf: *const u8,
    count: size_t,
    out_n: *mut size_t,
) -> rustls_result {
    ffi_panic_boundary! {
        let session: &mut ServerSession = try_ref_from_ptr!(session, &mut ServerSession);
        let input_buf: &[u8] = unsafe {
            if buf.is_null() {
                return NullParameter;
            }
            slice::from_raw_parts(buf, count as usize)
        };
        let out_n = unsafe {
            match out_n.as_mut() {
                Some(out_n) => out_n,
                None => return NullParameter,
            }
        };
        let mut cursor = Cursor::new(input_buf);
        let n_read: usize = match session.read_tls(&mut cursor) {
            Ok(n) => n,
            Err(_) => return rustls_result::Io,
        };
        *out_n = n_read;
        rustls_result::Ok
    }
}

/// Write up to `count` TLS bytes from the ServerSession into `buf`. Those
/// bytes should then be written to a socket. On success, store the number of
/// bytes actually written in *out_n (this maybe less than `count`).
/// https://docs.rs/rustls/0.19.0/rustls/trait.Session.html#tymethod.write_tls
#[no_mangle]
pub extern "C" fn rustls_server_session_write_tls(
    session: *mut rustls_server_session,
    buf: *mut u8,
    count: size_t,
    out_n: *mut size_t,
) -> rustls_result {
    ffi_panic_boundary! {
        let session: &mut ServerSession = try_ref_from_ptr!(session, &mut ServerSession);
        let mut output_buf: &mut [u8] = unsafe {
            if buf.is_null() {
                return NullParameter;
            }
            slice::from_raw_parts_mut(buf, count as usize)
        };
        let out_n = unsafe {
            match out_n.as_mut() {
                Some(out_n) => out_n,
                None => return NullParameter,
            }
        };
        let n_written: usize = match session.write_tls(&mut output_buf) {
            Ok(n) => n,
            Err(_) => return rustls_result::Io,
        };
        *out_n = n_written;
        rustls_result::Ok
    }
}

/// Copy the SNI hostname to `buf` which can hold up  to `count` bytes,
/// and the length of that hostname in `out_n`. The string is stored in UTF-8
/// with no terminating NUL byte.
/// Returns RUSTLS_RESULT_INSUFFICIENT_SIZE if the SNI hostname is longer than `count`.
/// Returns Ok with *out_n == 0 if there is no SNI hostname available on this session
/// because it hasn't been processed yet, or because the client did not send SNI.
/// https://docs.rs/rustls/0.19.0/rustls/struct.ServerSession.html#method.get_sni_hostname
#[no_mangle]
pub extern "C" fn rustls_server_session_get_sni_hostname(
    session: *const rustls_server_session,
    buf: *mut u8,
    count: size_t,
    out_n: *mut size_t,
) -> rustls_result {
    ffi_panic_boundary! {
        let session: &ServerSession = try_ref_from_ptr!(session, &ServerSession, NullParameter);
        let write_buf: &mut [u8] = unsafe {
            let out_n: &mut size_t = match out_n.as_mut() {
                Some(out_n) => out_n,
                None => return NullParameter,
            };
            *out_n = 0;
            if buf.is_null() {
                return NullParameter;
            }
            slice::from_raw_parts_mut(buf as *mut u8, count as usize)
        };
        let sni_hostname = match session.get_sni_hostname() {
            Some(sni_hostname) => sni_hostname,
            None => {
                return rustls_result::Ok
            },
        };
        let len: usize = sni_hostname.len();
        if len > write_buf.len() {
            return rustls_result::InsufficientSize;
        }
        write_buf[..len].copy_from_slice(&sni_hostname.as_bytes());
        unsafe {
            *out_n = len;
        }
        rustls_result::Ok
    }
}