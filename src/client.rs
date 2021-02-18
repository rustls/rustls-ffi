use libc::{c_char, size_t};
use std::io::ErrorKind::ConnectionAborted;
use std::io::{BufReader, Cursor, Read, Write};
use std::ptr::null;
use std::slice;
use std::{ffi::CStr, sync::Arc};
use std::{ffi::OsStr, fs::File};
use webpki::DNSNameRef;

use rustls::{
    Certificate, ClientConfig, ClientSession, RootCertStore, ServerCertVerified, Session, TLSError,
};

use crate::{
    arc_with_incref_from_raw,
    error::{self, map_error, rustls_result},
};
use crate::{
    ffi_panic_boundary, ffi_panic_boundary_bool, ffi_panic_boundary_generic,
    ffi_panic_boundary_ptr, ffi_panic_boundary_unit, try_ref_from_ptr,
};
use rustls_result::NullParameter;

/// A client config being constructed. A builder can be modified by,
/// e.g. rustls_client_config_builder_load_native_roots. Once you're
/// done configuring settings, call rustls_client_config_builder_build
/// to turn it into a *rustls_client_config. This object is not safe
/// for concurrent mutation. Under the hood, it corresponds to a
/// Box<ClientConfig>.
/// https://docs.rs/rustls/0.19.0/rustls/struct.ClientConfig.html
#[allow(non_camel_case_types)]
pub struct rustls_client_config_builder {
    // We use the opaque struct pattern to tell C about our types without
    // telling them what's inside.
    // https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs
    _private: [u8; 0],
}

/// A client config that is done being constructed and is now read-only.
/// Under the hood, this object corresponds to an Arc<ClientConfig>.
/// https://docs.rs/rustls/0.19.0/rustls/struct.ClientConfig.html
#[allow(non_camel_case_types)]
pub struct rustls_client_config {
    // We use the opaque struct pattern to tell C about our types without
    // telling them what's inside.
    // https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs
    _private: [u8; 0],
}

#[allow(non_camel_case_types)]
pub struct rustls_client_session {
    _private: [u8; 0],
}

/// Create a rustls_client_config_builder. Caller owns the memory and must
/// eventually call rustls_client_config_builder_build, then free the
/// resulting rustls_client_config. This starts out with no trusted roots.
/// Caller must add roots with rustls_client_config_builder_load_native_roots
/// or rustls_client_config_builder_load_roots_from_file.
#[no_mangle]
pub extern "C" fn rustls_client_config_builder_new() -> *mut rustls_client_config_builder {
    ffi_panic_boundary_ptr! {
        let config = rustls::ClientConfig::new();
        let b = Box::new(config);
        Box::into_raw(b) as *mut _
    }
}

/// Turn a *rustls_client_config_builder (mutable) into a *rustls_client_config
/// (read-only).
#[no_mangle]
pub extern "C" fn rustls_client_config_builder_build(
    builder: *mut rustls_client_config_builder,
) -> *const rustls_client_config {
    ffi_panic_boundary_ptr! {
        let config: &mut ClientConfig = try_ref_from_ptr!(builder, &mut ClientConfig,
             null::<rustls_client_config>());
        let b = unsafe { Box::from_raw(config) };
        Arc::into_raw(Arc::new(*b)) as *const _
    }
}

#[allow(non_camel_case_types)]
pub struct rustls_root_cert_store {
    _private: [u8; 0],
}

#[allow(non_camel_case_types)]
#[allow(dead_code)]
#[repr(C)]
pub struct rustls_certificate {
    bytes: *const u8,
    len: usize,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct rustls_verify_server_cert_params {
    roots: *const rustls_root_cert_store,
    end_entity: rustls_certificate,
    intermediates: *const rustls_certificate,
    intermediates_len: usize,
    dns_name: *const c_char,
    dns_name_len: usize,
    ocsp_response: *const u8,
    ocsp_response_len: usize,
}

#[allow(non_camel_case_types)]
type rustls_verify_server_cert_user_data = *mut libc::c_void;

// According to the nomicon https://doc.rust-lang.org/nomicon/ffi.html#the-nullable-pointer-optimization):
// > Option<extern "C" fn(c_int) -> c_int> is a correct way to represent a
// > nullable function pointer using the C ABI (corresponding to the C type int (*)(int)).
// So we use Option<...> here. This is the type that is passed from C code.
#[allow(non_camel_case_types)]
type rustls_verify_server_cert_callback = Option<unsafe extern "C" fn(
    userdata: rustls_verify_server_cert_user_data,
    params: *const rustls_verify_server_cert_params,
) -> rustls_result>;

// This is the same as a rustls_verify_server_cert_callback after unwrapping
// the Option (which is equivalent to checking for null).
type NonNullVerifyCallback = unsafe extern "C" fn(
    userdata: rustls_verify_server_cert_user_data,
    params: *const rustls_verify_server_cert_params,
) -> rustls_result;

// An implementation of rustls::ServerCertVerifier based on a C callback.
struct Verifier {
    callback: NonNullVerifyCallback,
    userdata: rustls_verify_server_cert_user_data,
}

unsafe impl Send for Verifier {}
unsafe impl Sync for Verifier {}

impl rustls::ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        roots: &RootCertStore,
        presented_certs: &[Certificate],
        dns_name: DNSNameRef<'_>,
        ocsp_response: &[u8],
    ) -> Result<ServerCertVerified, TLSError> {
        let cb = self.callback;
        let dns_name: &str = dns_name.into();
        let mut certificates: Vec<rustls_certificate> = presented_certs
            .iter()
            .map(|cert: &Certificate| {
                let cert: &[u8] = cert.as_ref();
                rustls_certificate {
                    bytes: cert.as_ptr(),
                    len: cert.len(),
                }
            })
            .collect();
        // In https://github.com/ctz/rustls/pull/462 (unreleased as of 0.19.0),
        // rustls changed the verifier API to separate the end entity and intermediates.
        // We anticipate that API by doing it ourselves.
        let end_entity = match certificates.pop() {
            Some(c) => c,
            None => return Err(TLSError::General("missing end-entity certificate".to_string())),
        };
        let params = rustls_verify_server_cert_params {
            roots: (roots as *const RootCertStore) as *const rustls_root_cert_store,
            end_entity,
            intermediates: certificates.as_ptr(),
            intermediates_len: certificates.len(),
            dns_name: dns_name.as_ptr() as *const c_char,
            dns_name_len: dns_name.len(),
            ocsp_response: ocsp_response.as_ptr(),
            ocsp_response_len: ocsp_response.len(),
        };
        let result: rustls_result = unsafe { cb(self.userdata, &params) };
        match result {
            rustls_result::Ok => Ok(ServerCertVerified::assertion()),
            r => match error::result_to_tlserror(&r) {
                error::Either::TLSError(te) => Err(te),
                error::Either::String(se) => Err(TLSError::General(se)),
            },
        }
    }
}

/// Set a custom server certificate verifier.
///
/// The userdata pointer must stay valid until (a) all sessions created with this
/// config have been freed, and (b) the config itself has been freed.
/// The callback must not capture any of the pointers in its
/// rustls_verify_server_cert_params.
///
/// The callback must be safe to call on any thread at any time, including
/// multiple concurrent calls. So, for instance, if the callback mutates
/// userdata (or other shared state), it must use synchronization primitives
/// to make such mutatation safe.
///
/// The callback receives certificate chain information as raw bytes.
/// Currently this library offers no functions for C code to parse the
/// certificates, so it's only possible to implement verifiers that either
/// (a) always succeed (or fail), or (b) compare the certificates against
/// static bytes. We plan to export parsing code in the future to make it
/// possible to implement other strategies.
///
/// If the custom verifier accepts the certificate, it should return
/// RUSTLS_RESULT_OK. Otherwise, it may return any other rustls_result error.
/// Feel free to use an appropriate error from the RUSTLS_RESULT_CERT_*
/// section.
#[no_mangle]
pub extern "C" fn rustls_client_config_builder_dangerous_set_certificate_verifier(
    config: *mut rustls_client_config_builder,
    callback: rustls_verify_server_cert_callback,
    userdata: rustls_verify_server_cert_user_data,
) -> rustls_result {
    ffi_panic_boundary! {
        let callback: NonNullVerifyCallback = match callback {
            Some(cb) => cb,
            None => return rustls_result::NullParameter,
        };
        let config: &mut ClientConfig = try_ref_from_ptr!(config, &mut ClientConfig);
        let verifier: Verifier = Verifier{callback: callback, userdata};
        config.dangerous().set_certificate_verifier(Arc::new(verifier));
        rustls_result::Ok
    }
}

/// Add certificates from platform's native root store, using
/// https://github.com/ctz/rustls-native-certs#readme.
#[no_mangle]
pub extern "C" fn rustls_client_config_builder_load_native_roots(
    config: *mut rustls_client_config_builder,
) -> rustls_result {
    ffi_panic_boundary! {
        let mut config: &mut ClientConfig = try_ref_from_ptr!(config, &mut ClientConfig);
        let store = match rustls_native_certs::load_native_certs() {
            Ok(store) => store,
            Err(_) => return rustls_result::Io,
        };
        config.root_store = store;
        rustls_result::Ok
    }
}

/// Add trusted root certificates from the named file, which should contain
/// PEM-formatted certificates.
#[no_mangle]
pub extern "C" fn rustls_client_config_builder_load_roots_from_file(
    config: *mut rustls_client_config_builder,
    filename: *const c_char,
) -> rustls_result {
    ffi_panic_boundary! {
        let filename: &CStr = unsafe {
            if filename.is_null() {
                return rustls_result::NullParameter;
            }
            CStr::from_ptr(filename)
        };
        let config: &mut ClientConfig = try_ref_from_ptr!(config, &mut ClientConfig);
        let filename: &[u8] = filename.to_bytes();
        let filename: &str = match std::str::from_utf8(filename) {
            Ok(s) => s,
            Err(_) => return rustls_result::Io,
        };
        let filename: &OsStr = OsStr::new(filename);
        let mut cafile = match File::open(filename) {
            Ok(f) => f,
            Err(_) => return rustls_result::Io,
        };
        let mut bufreader = BufReader::new(&mut cafile);
        match config.root_store.add_pem_file(&mut bufreader) {
            Ok(_) => {}
            Err(_) => return rustls_result::Io,
        };
        rustls_result::Ok
    }
}

/// "Free" a client_config previously returned from
/// rustls_client_config_builder_build. Since client_config is actually an
/// atomically reference-counted pointer, extant client_sessions may still
/// hold an internal reference to the Rust object. However, C code must
/// consider this pointer unusable after "free"ing it.
/// Calling with NULL is fine. Must not be called twice with the same value.
#[no_mangle]
pub extern "C" fn rustls_client_config_free(config: *const rustls_client_config) {
    ffi_panic_boundary_unit! {
        let config: &ClientConfig = try_ref_from_ptr!(config, &mut ClientConfig, ());
        // To free the client_config, we reconstruct the Arc and then drop it. It should
        // have a refcount of 1, representing the C code's copy. When it drops, that
        // refcount will go down to 0 and the inner ClientConfig will be dropped.
        unsafe { drop(Arc::from_raw(config)) };
    }
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
    ffi_panic_boundary! {
        let hostname: &CStr = unsafe {
            if hostname.is_null() {
                return NullParameter;
            }
            CStr::from_ptr(hostname)
        };
        let config: Arc<ClientConfig> = unsafe {
            match (config as *const ClientConfig).as_ref() {
                Some(c) => arc_with_incref_from_raw(c),
                None => return NullParameter,
            }
        };
        let hostname: &str = match hostname.to_str() {
            Ok(s) => s,
            Err(std::str::Utf8Error { .. }) => return rustls_result::InvalidDnsNameError,
        };
        let name_ref = match webpki::DNSNameRef::try_from_ascii_str(hostname) {
            Ok(nr) => nr,
            Err(webpki::InvalidDNSNameError { .. }) => return rustls_result::InvalidDnsNameError,
        };
        let client = ClientSession::new(&config, name_ref);

        // We've succeeded. Put the client on the heap, and transfer ownership
        // to the caller. After this point, we must return CRUSTLS_OK so the
        // caller knows it is responsible for this memory.
        let b = Box::new(client);
        unsafe {
            *session_out = Box::into_raw(b) as *mut _;
        }

        return rustls_result::Ok;
    }
}

#[no_mangle]
pub extern "C" fn rustls_client_session_wants_read(session: *const rustls_client_session) -> bool {
    ffi_panic_boundary_bool! {
        let session: &ClientSession = try_ref_from_ptr!(session, &ClientSession, false);
        session.wants_read()
    }
}

#[no_mangle]
pub extern "C" fn rustls_client_session_wants_write(session: *const rustls_client_session) -> bool {
    ffi_panic_boundary_bool! {
        let session: &ClientSession = try_ref_from_ptr!(session, &ClientSession, false);
        session.wants_write()
    }
}

#[no_mangle]
pub extern "C" fn rustls_client_session_is_handshaking(
    session: *const rustls_client_session,
) -> bool {
    ffi_panic_boundary_bool! {
        let session: &ClientSession = try_ref_from_ptr!(session, &ClientSession, false);
        session.is_handshaking()
    }
}

#[no_mangle]
pub extern "C" fn rustls_client_session_process_new_packets(
    session: *mut rustls_client_session,
) -> rustls_result {
    ffi_panic_boundary! {
        let session: &mut ClientSession = try_ref_from_ptr!(session, &mut ClientSession);
        match session.process_new_packets() {
            Ok(()) => rustls_result::Ok,
            Err(e) => return map_error(e),
        }
    }
}

/// Queues a close_notify fatal alert to be sent in the next write_tls call.
/// https://docs.rs/rustls/0.19.0/rustls/trait.Session.html#tymethod.send_close_notify
#[no_mangle]
pub extern "C" fn rustls_client_session_send_close_notify(session: *mut rustls_client_session) {
    ffi_panic_boundary_unit! {
        let session: &mut ClientSession = try_ref_from_ptr!(session, &mut ClientSession, ());
        session.send_close_notify()
    }
}

/// Free a client_session previously returned from rustls_client_session_new.
/// Calling with NULL is fine. Must not be called twice with the same value.
#[no_mangle]
pub extern "C" fn rustls_client_session_free(session: *mut rustls_client_session) {
    ffi_panic_boundary_unit! {
        let session: &mut ClientSession = try_ref_from_ptr!(session, &mut ClientSession, ());
        // Convert the pointer to a Box and drop it.
        unsafe { Box::from_raw(session); }
    }
}

/// Write up to `count` plaintext bytes from `buf` into the ClientSession.
/// This will increase the number of output bytes available to
/// `rustls_client_session_write_tls`.
/// On success, store the number of bytes actually written in *out_n
/// (this may be less than `count`).
/// https://docs.rs/rustls/0.19.0/rustls/struct.ClientSession.html#method.write
#[no_mangle]
pub extern "C" fn rustls_client_session_write(
    session: *mut rustls_client_session,
    buf: *const u8,
    count: size_t,
    out_n: *mut size_t,
) -> rustls_result {
    ffi_panic_boundary! {
        let session: &mut ClientSession = try_ref_from_ptr!(session, &mut ClientSession);
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

/// Read up to `count` plaintext bytes from the ClientSession into `buf`.
/// On success, store the number of bytes read in *out_n (this may be less
/// than `count`). A success with *out_n set to 0 means "all bytes currently
/// available have been read, but more bytes may become available after
/// subsequent calls to rustls_client_session_read_tls and
/// rustls_client_session_process_new_packets."
/// https://docs.rs/rustls/0.19.0/rustls/struct.ClientSession.html#method.read
#[no_mangle]
pub extern "C" fn rustls_client_session_read(
    session: *mut rustls_client_session,
    buf: *mut u8,
    count: size_t,
    out_n: *mut size_t,
) -> rustls_result {
    ffi_panic_boundary! {
        let session: &mut ClientSession = try_ref_from_ptr!(session, &mut ClientSession);
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
            // https://docs.rs/rustls/0.19.0/rustls/struct.ClientSession.html#impl-Read.
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
/// the ClientSession. This may make packets available to
/// `rustls_client_session_process_new_packets`, which in turn may make more
/// bytes available to `rustls_client_session_read`.
/// On success, store the number of bytes actually read in *out_n (this may
/// be less than `count`). This function returns success and stores 0 in
/// *out_n when the input count is 0.
/// https://docs.rs/rustls/0.19.0/rustls/trait.Session.html#tymethod.read_tls
#[no_mangle]
pub extern "C" fn rustls_client_session_read_tls(
    session: *mut rustls_client_session,
    buf: *const u8,
    count: size_t,
    out_n: *mut size_t,
) -> rustls_result {
    ffi_panic_boundary! {
        let session: &mut ClientSession = try_ref_from_ptr!(session, &mut ClientSession);
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

/// Write up to `count` TLS bytes from the ClientSession into `buf`. Those
/// bytes should then be written to a socket. On success, store the number of
/// bytes actually written in *out_n (this maybe less than `count`).
/// https://docs.rs/rustls/0.19.0/rustls/trait.Session.html#tymethod.write_tls
#[no_mangle]
pub extern "C" fn rustls_client_session_write_tls(
    session: *mut rustls_client_session,
    buf: *mut u8,
    count: size_t,
    out_n: *mut size_t,
) -> rustls_result {
    ffi_panic_boundary! {
        let session: &mut ClientSession = try_ref_from_ptr!(session, &mut ClientSession);
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
