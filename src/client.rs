use std::ffi::OsStr;
use std::fs::File;
use std::io::BufReader;
use std::slice;
use std::sync::Arc;
use std::{convert::TryInto, ffi::CStr};

use libc::{c_char, size_t};
use rustls::{
    Certificate, ClientConfig, ClientSession, RootCertStore, ServerCertVerified, TLSError,
};
use webpki::DNSNameRef;

use crate::connection::{rustls_connection, Connection};
use crate::error::{self, result_to_tlserror, rustls_result};
use crate::rslice::NulByte;
use crate::rslice::{rustls_slice_bytes, rustls_slice_slice_bytes, rustls_str};
use crate::session::{
    rustls_session_store_get_callback, rustls_session_store_put_callback, SessionStoreBroker,
    SessionStoreGetCallback, SessionStorePutCallback,
};
use crate::{
    arc_with_incref_from_raw, ffi_panic_boundary, try_mut_from_ptr, try_ref_from_ptr, try_slice,
    userdata_get, CastPtr,
};
use rustls_result::NullParameter;

/// A client config being constructed. A builder can be modified by,
/// e.g. rustls_client_config_builder_load_native_roots. Once you're
/// done configuring settings, call rustls_client_config_builder_build
/// to turn it into a *rustls_client_config. This object is not safe
/// for concurrent mutation. Under the hood, it corresponds to a
/// Box<ClientConfig>.
/// https://docs.rs/rustls/0.19.0/rustls/struct.ClientConfig.html
pub struct rustls_client_config_builder {
    // We use the opaque struct pattern to tell C about our types without
    // telling them what's inside.
    // https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs
    _private: [u8; 0],
}

impl CastPtr for rustls_client_config_builder {
    type RustType = ClientConfig;
}

/// A client config that is done being constructed and is now read-only.
/// Under the hood, this object corresponds to an Arc<ClientConfig>.
/// https://docs.rs/rustls/0.19.0/rustls/struct.ClientConfig.html
pub struct rustls_client_config {
    // We use the opaque struct pattern to tell C about our types without
    // telling them what's inside.
    // https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs
    _private: [u8; 0],
}

impl CastPtr for rustls_client_config {
    type RustType = ClientConfig;
}

/// Create a rustls_client_config_builder. Caller owns the memory and must
/// eventually call rustls_client_config_builder_build, then free the
/// resulting rustls_client_config. This starts out with no trusted roots.
/// Caller must add roots with rustls_client_config_builder_load_native_roots
/// or rustls_client_config_builder_load_roots_from_file.
#[no_mangle]
pub extern "C" fn rustls_client_config_builder_new() -> *mut rustls_client_config_builder {
    ffi_panic_boundary! {
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
    ffi_panic_boundary! {
        let config: &mut ClientConfig = try_mut_from_ptr!(builder);
        let b = unsafe { Box::from_raw(config) };
        Arc::into_raw(Arc::new(*b)) as *const _
    }
}

/// Currently just a placeholder with no accessors yet.
/// https://docs.rs/rustls/0.19.0/rustls/struct.RootCertStore.html
#[allow(non_camel_case_types)]
pub struct rustls_root_cert_store {
    _private: [u8; 0],
}

/// Input to a custom certificate verifier callback. See
/// rustls_client_config_builder_dangerous_set_certificate_verifier().
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct rustls_verify_server_cert_params<'a> {
    pub end_entity_cert_der: rustls_slice_bytes<'a>,
    pub intermediate_certs_der: &'a rustls_slice_slice_bytes<'a>,
    pub roots: *const rustls_root_cert_store,
    pub dns_name: rustls_str<'a>,
    pub ocsp_response: rustls_slice_bytes<'a>,
}

/// User-provided input to a custom certificate verifier callback. See
/// rustls_client_config_builder_dangerous_set_certificate_verifier().
#[allow(non_camel_case_types)]
type rustls_verify_server_cert_user_data = *mut libc::c_void;

// According to the nomicon https://doc.rust-lang.org/nomicon/ffi.html#the-nullable-pointer-optimization):
// > Option<extern "C" fn(c_int) -> c_int> is a correct way to represent a
// > nullable function pointer using the C ABI (corresponding to the C type int (*)(int)).
// So we use Option<...> here. This is the type that is passed from C code.
#[allow(non_camel_case_types)]
type rustls_verify_server_cert_callback = Option<
    unsafe extern "C" fn(
        userdata: rustls_verify_server_cert_user_data,
        params: *const rustls_verify_server_cert_params,
    ) -> rustls_result,
>;

// This is the same as a rustls_verify_server_cert_callback after unwrapping
// the Option (which is equivalent to checking for null).
type VerifyCallback = unsafe extern "C" fn(
    userdata: rustls_verify_server_cert_user_data,
    params: *const rustls_verify_server_cert_params,
) -> rustls_result;

// An implementation of rustls::ServerCertVerifier based on a C callback.
struct Verifier {
    callback: VerifyCallback,
}

/// Safety: Verifier is Send because we don't allocate or deallocate any of its
/// fields.
unsafe impl Send for Verifier {}
/// Safety: Verifier is Sync if the C code that passes us a callback that
/// obeys the concurrency safety requirements documented in
/// rustls_client_config_builder_dangerous_set_certificate_verifier.
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
        let dns_name: rustls_str = match dns_name.try_into() {
            Ok(r) => r,
            Err(NulByte {}) => return Err(TLSError::General("NUL byte in SNI".to_string())),
        };
        let mut certificates: Vec<&[u8]> = presented_certs
            .iter()
            .map(|cert: &Certificate| cert.as_ref())
            .collect();
        // In https://github.com/ctz/rustls/pull/462 (unreleased as of 0.19.0),
        // rustls changed the verifier API to separate the end entity and intermediates.
        // We anticipate that API by doing it ourselves.
        let end_entity = match certificates.pop() {
            Some(c) => c,
            None => {
                return Err(TLSError::General(
                    "missing end-entity certificate".to_string(),
                ))
            }
        };
        let intermediates = rustls_slice_slice_bytes {
            inner: &*certificates,
        };

        let params = rustls_verify_server_cert_params {
            roots: (roots as *const RootCertStore) as *const rustls_root_cert_store,
            end_entity_cert_der: end_entity.into(),
            intermediate_certs_der: &intermediates,
            dns_name: dns_name.into(),
            ocsp_response: ocsp_response.into(),
        };
        let userdata = userdata_get().map_err(|_| {
            TLSError::General("internal error with thread-local storage".to_string())
        })?;
        let result: rustls_result = unsafe { cb(userdata, &params) };
        match result {
            rustls_result::Ok => Ok(ServerCertVerified::assertion()),
            r => match result_to_tlserror(&r) {
                error::Either::TLSError(te) => Err(te),
                error::Either::String(se) => Err(TLSError::General(se)),
            },
        }
    }
}

/// Set a custom server certificate verifier.
///
/// The callback must not capture any of the pointers in its
/// rustls_verify_server_cert_params.
/// If `userdata` has been set with rustls_connection_set_userdata, it
/// will be passed to the callback. Otherwise the userdata param passed to
/// the callback will be NULL.
///
/// The callback must be safe to call on any thread at any time, including
/// multiple concurrent calls. So, for instance, if the callback mutates
/// userdata (or other shared state), it must use synchronization primitives
/// to make such mutation safe.
///
/// The callback receives certificate chain information as raw bytes.
/// Currently this library offers no functions for C code to parse the
/// certificates, so you'll need to bring your own certificate parsing library
/// if you need to parse them.
///
/// If you intend to write a verifier that accepts all certificates, be aware
/// that special measures are required for IP addresses. Rustls currently
/// (0.19.0) doesn't support building a ClientSession with an IP address
/// (because it's not a valid DNSNameRef). One workaround is to detect IP
/// addresses and rewrite them to `example.invalid`, and _also_ to disable
/// SNI via rustls_client_config_builder_set_enable_sni (IP addresses don't
/// need SNI).
///
/// If the custom verifier accepts the certificate, it should return
/// RUSTLS_RESULT_OK. Otherwise, it may return any other rustls_result error.
/// Feel free to use an appropriate error from the RUSTLS_RESULT_CERT_*
/// section.
///
/// https://docs.rs/rustls/0.19.0/rustls/struct.DangerousClientConfig.html#method.set_certificate_verifier
#[no_mangle]
pub extern "C" fn rustls_client_config_builder_dangerous_set_certificate_verifier(
    config: *mut rustls_client_config_builder,
    callback: rustls_verify_server_cert_callback,
) {
    ffi_panic_boundary! {
        let callback: VerifyCallback = match callback {
            Some(cb) => cb,
            None => return,
        };
        let config: &mut ClientConfig = try_mut_from_ptr!(config);
        let verifier: Verifier = Verifier{callback: callback};
        config.dangerous().set_certificate_verifier(Arc::new(verifier));
    }
}

/// Add certificates from platform's native root store, using
/// https://github.com/ctz/rustls-native-certs#readme.
#[no_mangle]
pub extern "C" fn rustls_client_config_builder_load_native_roots(
    config: *mut rustls_client_config_builder,
) -> rustls_result {
    ffi_panic_boundary! {
        let mut config: &mut ClientConfig = try_mut_from_ptr!(config);
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
        let config: &mut ClientConfig = try_mut_from_ptr!(config);
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

/// Set the ALPN protocol list to the given protocols. `protocols` must point
/// to a buffer of `rustls_slice_bytes` (built by the caller) with `len`
/// elements. Each element of the buffer must be a rustls_slice_bytes whose
/// data field points to a single ALPN protocol ID. Standard ALPN protocol
/// IDs are defined at
/// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids.
///
/// This function makes a copy of the data in `protocols` and does not retain
/// any pointers, so the caller can free the pointed-to memory after calling.
///
/// https://docs.rs/rustls/0.19.0/rustls/struct.ClientConfig.html#method.set_protocols
#[no_mangle]
pub extern "C" fn rustls_client_config_builder_set_protocols(
    builder: *mut rustls_client_config_builder,
    protocols: *const rustls_slice_bytes,
    len: size_t,
) -> rustls_result {
    ffi_panic_boundary! {
        let config: &mut ClientConfig = try_mut_from_ptr!(builder);
        let protocols: &[rustls_slice_bytes] = try_slice!(protocols, len);

        let mut vv: Vec<Vec<u8>> = Vec::with_capacity(protocols.len());
        for p in protocols {
            let v: &[u8] = try_slice!(p.data, p.len);
            vv.push(v.to_vec());
        }
        config.set_protocols(&vv);
        rustls_result::Ok
    }
}

/// Enable or disable SNI.
/// https://docs.rs/rustls/0.19.0/rustls/struct.ClientConfig.html#structfield.enable_sni
#[no_mangle]
pub extern "C" fn rustls_client_config_builder_set_enable_sni(
    config: *mut rustls_client_config_builder,
    enable: bool,
) {
    ffi_panic_boundary! {
        let config: &mut ClientConfig = try_mut_from_ptr!(config);
        config.enable_sni = enable;
    }
}

/// "Free" a client_config previously returned from
/// rustls_client_config_builder_build. Since client_config is actually an
/// atomically reference-counted pointer, extant client connections may still
/// hold an internal reference to the Rust object. However, C code must
/// consider this pointer unusable after "free"ing it.
/// Calling with NULL is fine. Must not be called twice with the same value.
#[no_mangle]
pub extern "C" fn rustls_client_config_free(config: *const rustls_client_config) {
    ffi_panic_boundary! {
        let config: &ClientConfig = try_ref_from_ptr!(config);
        // To free the client_config, we reconstruct the Arc and then drop it. It should
        // have a refcount of 1, representing the C code's copy. When it drops, that
        // refcount will go down to 0 and the inner ClientConfig will be dropped.
        unsafe { drop(Arc::from_raw(config)) };
    }
}

/// Create a new rustls_connection containing a client connection and return it
/// in the output parameter `out`. If this returns an error code, the memory
/// pointed to by `session_out` remains unchanged.
/// If this returns a non-error, the memory pointed to by `conn_out` is modified to point
/// at a valid rustls_connection. The caller now owns the rustls_connection and must call
/// `rustls_client_connection_free` when done with it.
#[no_mangle]
pub extern "C" fn rustls_client_connection_new(
    config: *const rustls_client_config,
    hostname: *const c_char,
    conn_out: *mut *mut rustls_connection,
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

        // We've succeeded. Put the client on the heap, and transfer ownership
        // to the caller. After this point, we must return CRUSTLS_OK so the
        // caller knows it is responsible for this memory.
        let c = Connection::from_client( ClientSession::new(&config, name_ref));
        unsafe {
            *conn_out = Box::into_raw(Box::new(c)) as *mut _;
        }

        return rustls_result::Ok;
    }
}

/// Register callbacks for persistence of TLS session data. This means either
/// session IDs (TLSv1.2) or . Both
/// keys and values are highly sensitive data, containing enough information
/// to break the security of the sessions involved.
///
/// If `userdata` has been set with rustls_connection_set_userdata, it
/// will be passed to the callbacks. Otherwise the userdata param passed to
/// the callbacks will be NULL.
#[no_mangle]
pub extern "C" fn rustls_client_config_builder_set_persistence(
    builder: *mut rustls_client_config_builder,
    get_cb: rustls_session_store_get_callback,
    put_cb: rustls_session_store_put_callback,
) -> rustls_result {
    ffi_panic_boundary! {
        let get_cb: SessionStoreGetCallback = match get_cb {
            Some(cb) => cb,
            None => return rustls_result::NullParameter,
        };
        let put_cb: SessionStorePutCallback = match put_cb {
            Some(cb) => cb,
            None => return rustls_result::NullParameter,
        };
        let config: &mut ClientConfig = try_mut_from_ptr!(builder);
        config.set_persistence(Arc::new(SessionStoreBroker::new(
            get_cb, put_cb
        )));
        rustls_result::Ok
    }
}
