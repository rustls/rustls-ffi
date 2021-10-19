use std::convert::TryInto;
use std::ffi::{CStr, OsStr};
use std::fs::File;
use std::io::BufReader;
use std::slice;
use std::sync::Arc;
use std::time::SystemTime;

use libc::{c_char, size_t};
use rustls::client::{ResolvesClientCert, ServerCertVerified};
use rustls::{
    sign::CertifiedKey, Certificate, ClientConfig, ClientConnection, ConfigBuilder,
    ProtocolVersion, RootCertStore, SupportedCipherSuite, WantsVerifier, ALL_CIPHER_SUITES,
};

use crate::cipher::{rustls_certified_key, rustls_root_cert_store, rustls_supported_ciphersuite};
use crate::connection::{rustls_connection, Connection};
use crate::error::rustls_result::{InvalidParameter, NullParameter};
use crate::error::{self, result_to_error, rustls_result};
use crate::rslice::NulByte;
use crate::rslice::{rustls_slice_bytes, rustls_slice_slice_bytes, rustls_str};
use crate::{
    ffi_panic_boundary, try_arc_from_ptr, try_box_from_ptr, try_mut_from_ptr, try_ref_from_ptr,
    try_slice, userdata_get, ArcCastPtr, BoxCastPtr, CastConstPtr, CastPtr,
};

/// A client config being constructed. A builder can be modified by,
/// e.g. rustls_client_config_builder_load_roots_from_file. Once you're
/// done configuring settings, call rustls_client_config_builder_build
/// to turn it into a *rustls_client_config. This object is not safe
/// for concurrent mutation. Under the hood, it corresponds to a
/// Box<ClientConfig>.
/// https://docs.rs/rustls/0.20.0/rustls/struct.ClientConfig.html
pub struct rustls_client_config_builder_wants_verifier {
    // We use the opaque struct pattern to tell C about our types without
    // telling them what's inside.
    // https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs
    _private: [u8; 0],
}

impl CastPtr for rustls_client_config_builder_wants_verifier {
    type RustType = ConfigBuilder<ClientConfig, WantsVerifier>;
}

impl BoxCastPtr for rustls_client_config_builder_wants_verifier {}

pub struct rustls_client_config_builder {
    _private: [u8; 0],
}

impl CastPtr for rustls_client_config_builder {
    type RustType = ClientConfig;
}

impl BoxCastPtr for rustls_client_config_builder {}

/// A client config that is done being constructed and is now read-only.
/// Under the hood, this object corresponds to an Arc<ClientConfig>.
/// https://docs.rs/rustls/0.20.0/rustls/struct.ClientConfig.html
pub struct rustls_client_config {
    // We use the opaque struct pattern to tell C about our types without
    // telling them what's inside.
    // https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs
    _private: [u8; 0],
}

impl CastConstPtr for rustls_client_config {
    type RustType = ClientConfig;
}

impl ArcCastPtr for rustls_client_config {}

impl rustls_client_config_builder {
    /// Create a rustls_client_config_builder. Caller owns the memory and must
    /// eventually call rustls_client_config_builder_build, then free the
    /// resulting rustls_client_config.
    /// This uses rustls safe default values
    /// for the cipher suites, key exchange groups and protocol versions.
    /// This starts out with no trusted roots.
    /// Caller must add roots with rustls_client_config_builder_load_roots_from_file
    /// or provide a custom verifier.
    #[no_mangle]
    pub extern "C" fn rustls_client_config_builder_new_with_safe_defaults(
    ) -> *mut rustls_client_config_builder_wants_verifier {
        ffi_panic_boundary! {
            let builder = rustls::ClientConfig::builder().with_safe_defaults();
            BoxCastPtr::to_mut_ptr(builder)
        }
    }

    /// Create a rustls_client_config_builder. Caller owns the memory and must
    /// eventually call rustls_client_config_builder_build, then free the
    /// resulting rustls_client_config. Specify cipher suites in preference order;
    /// the `cipher_suites` parameter must point to an array containing `len`
    /// pointers to `rustls_supported_ciphersuite` previously obtained from
    /// `rustls_all_ciphersuites_get()`. Set the TLS protocol versions to use
    /// when negotiating a TLS session.
    ///
    /// `tls_version` is the version of the protocol, as defined in rfc8446,
    /// ch. 4.2.1 and end of ch. 5.1. Some values are defined in
    /// `rustls_tls_version` for convenience.
    ///
    /// `versions` will only be used during the call and the application retains
    /// ownership. `len` is the number of consecutive `ui16` pointed to by `versions`.
    #[no_mangle]
    pub extern "C" fn rustls_client_config_builder_new(
        cipher_suites: *const *const rustls_supported_ciphersuite,
        cipher_suites_len: size_t,
        tls_versions: *const u16,
        tls_versions_len: size_t,
        builder: *mut *mut rustls_client_config_builder_wants_verifier,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let cipher_suites: &[*const rustls_supported_ciphersuite] = try_slice!(cipher_suites, cipher_suites_len);
            let mut cs_vec: Vec<SupportedCipherSuite> = Vec::new();
            for &cs in cipher_suites.into_iter() {
                let cs = try_ref_from_ptr!(cs);
                match ALL_CIPHER_SUITES.iter().find(|&acs| cs.eq(acs)) {
                    Some(scs) => cs_vec.push(scs.clone()),
                    None => return InvalidParameter,
                }
            }

            let tls_versions: &[u16] = try_slice!(tls_versions, tls_versions_len);
            let mut versions = vec![];
            for version_number in tls_versions {
                let proto = ProtocolVersion::from(*version_number);
                if proto == rustls::version::TLS12.version {
                    versions.push(&rustls::version::TLS12);
                } else if proto == rustls::version::TLS13.version {
                    versions.push(&rustls::version::TLS13);
                }
            }

            let result = rustls::ClientConfig::builder().with_cipher_suites(&cs_vec).with_safe_default_kx_groups().with_protocol_versions(&versions);
            let new = match result {
                Ok(new) => new,
                Err(_) => return rustls_result::InvalidParameter,
            };

            BoxCastPtr::set_mut_ptr(builder, new);
            rustls_result::Ok
        }
    }
}

/// Input to a custom certificate verifier callback. See
/// rustls_client_config_builder_dangerous_set_certificate_verifier().
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct rustls_verify_server_cert_params<'a> {
    pub end_entity_cert_der: rustls_slice_bytes<'a>,
    pub intermediate_certs_der: &'a rustls_slice_slice_bytes<'a>,
    pub dns_name: rustls_str<'a>,
    pub ocsp_response: rustls_slice_bytes<'a>,
}

/// User-provided input to a custom certificate verifier callback. See
/// rustls_client_config_builder_dangerous_set_certificate_verifier().
#[allow(non_camel_case_types)]
pub type rustls_verify_server_cert_user_data = *mut libc::c_void;

// According to the nomicon https://doc.rust-lang.org/nomicon/ffi.html#the-nullable-pointer-optimization):
// > Option<extern "C" fn(c_int) -> c_int> is a correct way to represent a
// > nullable function pointer using the C ABI (corresponding to the C type int (*)(int)).
// So we use Option<...> here. This is the type that is passed from C code.
#[allow(non_camel_case_types)]
pub type rustls_verify_server_cert_callback = Option<
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

impl rustls::client::ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let cb = self.callback;
        let dns_name: &str = match server_name {
            rustls::ServerName::DnsName(n) => n.as_ref().into(),
            _ => return Err(rustls::Error::General("unknown name type".to_string())),
        };
        let dns_name: rustls_str = match dns_name.try_into() {
            Ok(r) => r,
            Err(NulByte {}) => return Err(rustls::Error::General("NUL byte in SNI".to_string())),
        };

        let intermediates: Vec<_> = intermediates
            .into_iter()
            .map(|cert| cert.as_ref())
            .collect();

        let intermediates = rustls_slice_slice_bytes {
            inner: &*intermediates,
        };

        let params = rustls_verify_server_cert_params {
            end_entity_cert_der: end_entity.as_ref().into(),
            intermediate_certs_der: &intermediates,
            dns_name: dns_name.into(),
            ocsp_response: ocsp_response.into(),
        };
        let userdata = userdata_get().map_err(|_| {
            rustls::Error::General("internal error with thread-local storage".to_string())
        })?;
        let result: rustls_result = unsafe { cb(userdata, &params) };
        match result {
            rustls_result::Ok => Ok(ServerCertVerified::assertion()),
            r => match result_to_error(&r) {
                error::Either::Error(te) => Err(te),
                error::Either::String(se) => Err(rustls::Error::General(se)),
            },
        }
    }
}

impl rustls_client_config_builder {
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
    /// (0.20.0) doesn't support building a ClientSession with an IP address
    /// (because it's not a valid DnsNameRef). One workaround is to detect IP
    /// addresses and rewrite them to `example.invalid`, and _also_ to disable
    /// SNI via rustls_client_config_builder_set_enable_sni (IP addresses don't
    /// need SNI).
    ///
    /// If the custom verifier accepts the certificate, it should return
    /// RUSTLS_RESULT_OK. Otherwise, it may return any other rustls_result error.
    /// Feel free to use an appropriate error from the RUSTLS_RESULT_CERT_*
    /// section.
    ///
    /// https://docs.rs/rustls/0.20.0/rustls/client/struct.DangerousClientConfig.html#method.set_certificate_verifier
    #[no_mangle]
    pub extern "C" fn rustls_client_config_builder_dangerous_set_certificate_verifier(
        wants_verifier: *mut rustls_client_config_builder_wants_verifier,
        callback: rustls_verify_server_cert_callback,
        builder: *mut *mut rustls_client_config_builder,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let callback: VerifyCallback = match callback {
                Some(cb) => cb,
                None => return rustls_result::InvalidParameter,
            };

            let new = *try_box_from_ptr!(wants_verifier);
            let verifier: Verifier = Verifier{callback: callback};
            // TODO: no client authentication support for now
            let config = new.with_custom_certificate_verifier(Arc::new(verifier)).with_no_client_auth();
            BoxCastPtr::set_mut_ptr(builder, config);
            rustls_result::Ok
        }
    }

    /// Use the trusted root certificates from the provided store.
    ///
    /// This replaces any trusted roots already configured with copies
    /// from `roots`. This adds 1 to the refcount for `roots`. When you
    /// call rustls_client_config_free or rustls_client_config_builder_free,
    /// those will subtract 1 from the refcount for `roots`.
    #[no_mangle]
    pub extern "C" fn rustls_client_config_builder_use_roots(
        wants_verifier: *mut rustls_client_config_builder_wants_verifier,
        roots: *const rustls_root_cert_store,
        builder: *mut *mut rustls_client_config_builder,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let root_store: &RootCertStore = try_ref_from_ptr!(roots);
            let prev = *try_box_from_ptr!(wants_verifier);
            let config = prev.with_root_certificates(root_store.clone()).with_no_client_auth();
            BoxCastPtr::set_mut_ptr(builder, config);
            rustls_result::Ok
        }
    }

    /// Add trusted root certificates from the named file, which should contain
    /// PEM-formatted certificates.
    #[no_mangle]
    pub extern "C" fn rustls_client_config_builder_load_roots_from_file(
        wants_verifier: *mut rustls_client_config_builder_wants_verifier,
        filename: *const c_char,
        builder: *mut *mut rustls_client_config_builder,
    ) -> rustls_result {
        ffi_panic_boundary! {
        let prev = *try_box_from_ptr!(wants_verifier);
        let filename: &CStr = unsafe {
            if filename.is_null() {
                return rustls_result::NullParameter;
            }
            CStr::from_ptr(filename)
        };

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
            let certs = match rustls_pemfile::certs(&mut bufreader) {
                Ok(certs) => certs,
                Err(_) => return rustls_result::Io,
            };

            let mut roots = RootCertStore::empty();
            let (_, failed) = roots.add_parsable_certificates(&certs);
            if failed > 0 {
                return rustls_result::CertificateParseError;
            }

            // TODO: no client authentication support for now
            let config = prev.with_root_certificates(roots).with_no_client_auth();
            BoxCastPtr::set_mut_ptr(builder, config);

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
    /// https://docs.rs/rustls/0.20.0/rustls/client/struct.ClientConfig.html#structfield.alpn_protocols
    #[no_mangle]
    pub extern "C" fn rustls_client_config_builder_set_alpn_protocols(
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
            config.alpn_protocols = vv;
            rustls_result::Ok
        }
    }

    /// Enable or disable SNI.
    /// https://docs.rs/rustls/0.20.0/rustls/struct.ClientConfig.html#structfield.enable_sni
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

    /// "Free" a client_config_builder_wants_verifier before transmogrifying it into a client_config.
    /// Normally builders are consumed to client_configs via `rustls_client_config_builder_build`
    /// and may not be free'd or otherwise used afterwards.
    /// Use free only when the building of a config has to be aborted before a config
    /// was created.
    #[no_mangle]
    pub extern "C" fn rustls_client_config_builder_wants_verifier_free(
        builder: *mut rustls_client_config_builder_wants_verifier,
    ) {
        ffi_panic_boundary! {
            BoxCastPtr::to_box(builder);
        }
    }

    /// Provide the configuration a list of certificates where the session
    /// will select the first one that is compatible with the server's signature
    /// verification capabilities. Clients that want to support both ECDSA and
    /// RSA certificates will want the ECSDA to go first in the list.
    ///
    /// The built configuration will keep a reference to all certified keys
    /// provided. The client may `rustls_certified_key_free()` afterwards
    /// without the configuration losing them. The same certified key may also
    /// be used in multiple configs.
    ///
    /// EXPERIMENTAL: installing a client authentication callback will replace any
    /// configured certified keys and vice versa.
    #[no_mangle]
    pub extern "C" fn rustls_client_config_builder_set_certified_key(
        builder: *mut rustls_client_config_builder,
        certified_keys: *const *const rustls_certified_key,
        certified_keys_len: size_t,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let config: &mut ClientConfig = try_mut_from_ptr!(builder);
            let keys_ptrs: &[*const rustls_certified_key] = try_slice!(certified_keys, certified_keys_len);
            let mut keys: Vec<Arc<CertifiedKey>> = Vec::new();
            for &key_ptr in keys_ptrs {
                let certified_key: Arc<CertifiedKey> = try_arc_from_ptr!(key_ptr);
                keys.push(certified_key);
            }
            config.client_auth_cert_resolver = Arc::new(ResolvesClientCertFromChoices { keys });
            rustls_result::Ok
        }
    }
}

/// Always send the same client certificate.
struct ResolvesClientCertFromChoices {
    keys: Vec<Arc<CertifiedKey>>,
}

impl ResolvesClientCert for ResolvesClientCertFromChoices {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        sig_schemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        for key in self.keys.iter() {
            if key.key.choose_scheme(sig_schemes).is_some() {
                return Some(key.clone());
            }
        }
        None
    }

    fn has_certs(&self) -> bool {
        !self.keys.is_empty()
    }
}

impl rustls_client_config_builder {
    /// Turn a *rustls_client_config_builder (mutable) into a const *rustls_client_config
    /// (read-only).
    #[no_mangle]
    pub extern "C" fn rustls_client_config_builder_build(
        builder: *mut rustls_client_config_builder,
    ) -> *const rustls_client_config {
        ffi_panic_boundary! {
            let b = try_box_from_ptr!(builder);
            ArcCastPtr::to_const_ptr(*b)
        }
    }

    /// "Free" a client_config_builder before transmogrifying it into a client_config.
    /// Normally builders are consumed to client_configs via `rustls_client_config_builder_build`
    /// and may not be free'd or otherwise used afterwards.
    /// Use free only when the building of a config has to be aborted before a config
    /// was created.
    #[no_mangle]
    pub extern "C" fn rustls_client_config_builder_free(config: *mut rustls_client_config_builder) {
        ffi_panic_boundary! {
            BoxCastPtr::to_box(config);
        }
    }
}

impl rustls_client_config {
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

    /// Create a new rustls_connection containing a client connection and return
    /// it in the output parameter `out`. If this returns an error code, the
    /// memory pointed to by `session_out` remains unchanged. If this returns a
    /// non-error, the memory pointed to by `conn_out` is modified to point at a
    /// valid rustls_connection. The caller now owns the rustls_connection and must
    /// call `rustls_connection_free` when done with it.
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
        let config: Arc<ClientConfig> = try_arc_from_ptr!(config);
        let hostname: &str = match hostname.to_str() {
            Ok(s) => s,
            Err(std::str::Utf8Error { .. }) => return rustls_result::InvalidDnsNameError,
        };
        let server_name: rustls::ServerName = match hostname.try_into() {
            Ok(sn) => sn,
            Err(_) => return rustls_result::InvalidDnsNameError,
        };
        let client = ClientConnection::new(config, server_name).unwrap();

        // We've succeeded. Put the client on the heap, and transfer ownership
        // to the caller. After this point, we must return CRUSTLS_OK so the
        // caller knows it is responsible for this memory.
        let c = Connection::from_client(client);
        BoxCastPtr::set_mut_ptr(conn_out, c);
        rustls_result::Ok
        }
    }
}
