use libc::size_t;
use std::ffi::c_void;
use std::io::{Cursor, Read, Write};
use std::ptr::null;
use std::ptr::null_mut;
use std::slice;
use std::sync::Arc;
use std::{convert::TryInto, io::ErrorKind::ConnectionAborted};

use rustls::{sign::CertifiedKey, ResolvesServerCert};
use rustls::{ClientHello, NoClientAuth, ServerConfig, ServerSession, Session};
use rustls_result::NullParameter;

use crate::error::{map_error, rustls_result};
use crate::rslice::{rustls_slice_bytes, rustls_slice_slice_bytes, rustls_slice_u16, rustls_str};
use crate::{arc_with_incref_from_raw, cipher::rustls_certified_key};
use crate::{
    ffi_panic_boundary, ffi_panic_boundary_bool, ffi_panic_boundary_generic,
    ffi_panic_boundary_ptr, ffi_panic_boundary_unit, try_ref_from_ptr,
};

/// A server config being constructed. A builder can be modified by,
/// e.g. rustls_server_config_builder_load_native_roots. Once you're
/// done configuring settings, call rustls_server_config_builder_build
/// to turn it into a *rustls_server_config. This object is not safe
/// for concurrent mutation. Under the hood, it corresponds to a
/// Box<ServerConfig>.
/// https://docs.rs/rustls/0.19.0/rustls/struct.ServerConfig.html
pub struct rustls_server_config_builder {
    // We use the opaque struct pattern to tell C about our types without
    // telling them what's inside.
    // https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs
    _private: [u8; 0],
}

/// A server config that is done being constructed and is now read-only.
/// Under the hood, this object corresponds to an Arc<ServerConfig>.
/// https://docs.rs/rustls/0.19.0/rustls/struct.ServerConfig.html
pub struct rustls_server_config {
    // We use the opaque struct pattern to tell C about our types without
    // telling them what's inside.
    // https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs
    _private: [u8; 0],
}

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

/// "Free" a server_config_builder before transmogrifying it into a server_config.
/// Normally builders are consumed to server_configs via `rustls_server_config_builder_build`
/// and may not be free'd or otherwise used afterwards.
/// Use free only when the building of a config has to be aborted before a config
/// was created.
#[no_mangle]
pub extern "C" fn rustls_server_config_builder_free(config: *mut rustls_server_config_builder) {
    ffi_panic_boundary_unit! {
        let config: &mut ServerConfig = try_ref_from_ptr!(config, &mut ServerConfig, ());
        // Convert the pointer to a Box and drop it.
        unsafe { Box::from_raw(config); }
    }
}

/// Create a rustls_server_config_builder from an existing rustls_server_config. The
/// builder will be used to create a new, separate config that starts with the settings
/// from the supplied configuration.
#[no_mangle]
pub extern "C" fn rustls_server_config_builder_from_config(
    config: *const rustls_server_config,
) -> *mut rustls_server_config_builder {
    ffi_panic_boundary_ptr! {
        let config: &ServerConfig = try_ref_from_ptr!(config, & ServerConfig, null_mut());
        Box::into_raw(Box::new(config.clone())) as *mut _
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

#[no_mangle]
pub extern "C" fn rustls_server_config_builder_set_protocols(
    builder: *mut rustls_server_config_builder,
    protocols: *const rustls_slice_bytes,
    len: size_t,
) -> rustls_result {
    ffi_panic_boundary! {
        let config: &mut ServerConfig = try_ref_from_ptr!(builder, &mut ServerConfig);
        let protocols: &[rustls_slice_bytes] = unsafe {
            if protocols.is_null() {
                return NullParameter;
            }
                slice::from_raw_parts(protocols, len)
        };

        let mut vv: Vec<Vec<u8>> = Vec::new();
        for p in protocols {
            let v: &[u8] = unsafe {
                if p.data.is_null() {
                    return NullParameter;
                }
                slice::from_raw_parts(p.data, p.len)
            };
            vv.push(v.to_vec());
        }
        config.set_protocols(&vv);
        rustls_result::Ok
    }
}

/// Provide the configuration a list of certificates where the session
/// will select the first one that is compatible with the client's signature
/// verification capabilities. Servers that want to support ECDSA and RSA certificates
/// will want the ECSDA to go first in the list.
///
/// The built configuration will keep a reference to all certified keys
/// provided. The client may `rustls_certified_key_free()` afterwards
/// without the configuration losing them. The same certified key may also
/// be used in multiple configs.
///
/// EXPERIMENTAL: installing a client_hello callback will replace any
/// configured certified keys and vice versa. Same holds true for the
/// set_single_cert variant.
#[no_mangle]
pub extern "C" fn rustls_server_config_builder_set_certified_keys(
    builder: *mut rustls_server_config_builder,
    certified_keys: *const *const rustls_certified_key,
    certified_keys_len: size_t,
) -> rustls_result {
    ffi_panic_boundary! {
        let config: &mut ServerConfig = try_ref_from_ptr!(builder, &mut ServerConfig);
        let keys_ptrs: &[*const rustls_certified_key] = unsafe {
            if certified_keys.is_null() {
                return NullParameter;
            }
            slice::from_raw_parts(certified_keys, certified_keys_len)
        };
        let mut keys: Vec<Arc<CertifiedKey>> = Vec::new();
        for &key_ptr in keys_ptrs {
            let certified_key: Arc<CertifiedKey> = unsafe {
                match (key_ptr as *const CertifiedKey).as_ref() {
                    Some(c) => arc_with_incref_from_raw(c),
                    None => return NullParameter,
                }
            };
            keys.push(certified_key);
        }
        config.cert_resolver = Arc::new(ResolvesServerCertFromChoices::new(&keys));
        rustls_result::Ok
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

/// Choose the server certificate to be used for a session.
/// Will pick the first CertfiedKey available that is suitable for
/// the SignatureSchemes supported by the client.
struct ResolvesServerCertFromChoices {
    choices: Vec<Arc<CertifiedKey>>,
}

impl ResolvesServerCertFromChoices {
    pub fn new(choices: &[Arc<CertifiedKey>]) -> Self {
        ResolvesServerCertFromChoices {
            choices: Vec::from(choices),
        }
    }
}

impl ResolvesServerCert for ResolvesServerCertFromChoices {
    fn resolve(&self, client_hello: ClientHello) -> Option<CertifiedKey> {
        for key in self.choices.iter() {
            if key.key.choose_scheme(client_hello.sigschemes()).is_some() {
                return Some(key.as_ref().clone());
            }
        }
        None
    }
}

/// The TLS Client Hello information provided to a ClientHelloCallback function.
/// `sni_name` is the SNI servername provided by the client. If the client
/// did not provide an SNI, the length of this `rustls_string` will be 0.
/// The signature_schemes carries the values supplied by the client or, should
/// the client not use this TLS extension, the default schemes in the rustls
/// library. See:
/// https://docs.rs/rustls/0.19.0/rustls/internal/msgs/enums/enum.SignatureScheme.html
/// `alpn` carries the list of ALPN protocol names that the client proposed to
/// the server. Again, the length of this list will be 0 if none were supplied.
///
/// All this data, when passed to a callback function, is only accessible during
/// the call and may not be modified. Users of this API must copy any values that
/// they want to access when the callback returned.
///
/// EXPERIMENTAL: this feature of crustls is likely to change in the future, as
/// the rustls library is re-evaluating their current approach to client hello handling.
#[repr(C)]
pub struct rustls_client_hello<'a> {
    sni_name: rustls_str<'a>,
    signature_schemes: rustls_slice_u16<'a>,
    alpn: *const rustls_slice_slice_bytes<'a>,
}

/// Any context information the callback will receive when invoked.
pub type rustls_client_hello_userdata = *mut c_void;

/// Prototype of a callback that can be installed by the application at the
/// `rustls_server_config`. This callback will be invoked by a `rustls_server_session`
/// once the TLS client hello message has been received.
/// `userdata` will be supplied as provided when registering the callback.
/// `hello` gives the value of the available client announcements, as interpreted
/// by rustls. See the definition of `rustls_client_hello` for details.
///
/// NOTE: the passed in `hello` and all its values are only availabe during the
/// callback invocations.
///
/// EXPERIMENTAL: this feature of crustls is likely to change in the future, as
/// the rustls library is re-evaluating their current approach to client hello handling.
pub type rustls_client_hello_callback = Option<
    unsafe extern "C" fn(
        userdata: rustls_client_hello_userdata,
        hello: *const rustls_client_hello,
    ) -> *const rustls_certified_key,
>;

// This is the same as a rustls_verify_server_cert_callback after unwrapping
// the Option (which is equivalent to checking for null).
type ClientHelloCallback = unsafe extern "C" fn(
    userdata: rustls_client_hello_userdata,
    hello: *const rustls_client_hello,
) -> *const rustls_certified_key;

struct ClientHelloResolver {
    /// Implementation of rustls::ResolvesServerCert that passes values
    /// from the supplied ClientHello to the callback function.
    pub callback: ClientHelloCallback,
    pub userdata: rustls_client_hello_userdata,
}

impl ClientHelloResolver {
    pub fn new(
        callback: ClientHelloCallback,
        userdata: rustls_client_hello_userdata,
    ) -> ClientHelloResolver {
        ClientHelloResolver { callback, userdata }
    }
}

impl ResolvesServerCert for ClientHelloResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<CertifiedKey> {
        let sni_name: &str = {
            match client_hello.server_name() {
                Some(c) => c.into(),
                None => "",
            }
        };
        let sni_name: rustls_str = match sni_name.try_into() {
            Ok(r) => r,
            Err(_) => return None,
        };
        let mapped_sigs: Vec<u16> = client_hello
            .sigschemes()
            .iter()
            .map(|s| s.get_u16())
            .collect();
        // Unwrap the Option. None becomes an empty slice.
        let alpn: &[&[u8]] = client_hello.alpn().unwrap_or(&[]);
        let alpn: rustls_slice_slice_bytes = rustls_slice_slice_bytes { inner: alpn };
        let signature_schemes: rustls_slice_u16 = (&*mapped_sigs).into();
        let hello = rustls_client_hello {
            sni_name,
            signature_schemes,
            alpn: &alpn,
        };
        let cb = self.callback;
        let key_ptr = unsafe { cb(self.userdata, &hello) };
        let certified_key: &CertifiedKey = try_ref_from_ptr!(key_ptr, &CertifiedKey, None);
        Some(certified_key.clone())
    }
}

unsafe impl Sync for ClientHelloResolver {}
unsafe impl Send for ClientHelloResolver {}

/// Register a callback to be invoked when a session created from this config
/// is seeing a TLS ClientHello message. The given `userdata` will be passed
/// to the callback when invoked.
///
/// Any existing `ResolvesServerCert` implementation currently installed in the
/// `rustls_server_config` will be replaced. This also means registering twice
/// will overwrite the first registration. It is not permitted to pass a NULL
/// value for `callback`, but it is possible to have `userdata` as NULL.
///
/// EXPERIMENTAL: this feature of crustls is likely to change in the future, as
/// the rustls library is re-evaluating their current approach to client hello handling.
/// Installing a client_hello callback will replace any configured certified keys
/// and vice versa. Same holds true for the set_single_cert variant.
#[no_mangle]
pub extern "C" fn rustls_server_config_builder_set_hello_callback(
    builder: *mut rustls_server_config_builder,
    callback: rustls_client_hello_callback,
    userdata: rustls_client_hello_userdata,
) -> rustls_result {
    ffi_panic_boundary! {
        let callback: ClientHelloCallback = match callback {
            Some(cb) => cb,
            None => return rustls_result::NullParameter,
        };
        let config: &mut ServerConfig = try_ref_from_ptr!(builder, &mut ServerConfig);
        config.cert_resolver = Arc::new(ClientHelloResolver::new(
            callback, userdata
        ));
        rustls_result::Ok
    }
}
