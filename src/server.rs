use std::ffi::c_void;
use std::fmt::{Debug, Formatter};
use std::ptr::null;
use std::slice;
use std::sync::Arc;

use libc::size_t;
use rustls::crypto::ring::ALL_CIPHER_SUITES;
use rustls::server::danger::ClientCertVerifier;
use rustls::server::{
    ClientHello, ResolvesServerCert, ServerConfig, ServerConnection, StoresServerSessions,
    WebPkiClientVerifier,
};
use rustls::sign::CertifiedKey;
use rustls::{ProtocolVersion, SignatureScheme, SupportedCipherSuite, WantsVerifier};

use crate::cipher::{
    rustls_certified_key, rustls_client_cert_verifier, rustls_supported_ciphersuite,
};
use crate::connection::{rustls_connection, Connection};
use crate::error::rustls_result::{InvalidParameter, NullParameter};
use crate::error::{map_error, rustls_result};
use crate::rslice::{rustls_slice_bytes, rustls_slice_slice_bytes, rustls_slice_u16, rustls_str};
use crate::session::{
    rustls_session_store_get_callback, rustls_session_store_put_callback, SessionStoreBroker,
    SessionStoreGetCallback, SessionStorePutCallback,
};
use crate::{
    ffi_panic_boundary, free_arc, free_box, set_boxed_mut_ptr, to_arc_const_ptr, to_boxed_mut_ptr,
    try_box_from_ptr, try_clone_arc, try_mut_from_ptr, try_ref_from_ptr, try_slice, userdata_get,
    Castable, OwnershipArc, OwnershipBox, OwnershipRef,
};

/// A server config being constructed. A builder can be modified by,
/// e.g. rustls_server_config_builder_load_native_roots. Once you're
/// done configuring settings, call rustls_server_config_builder_build
/// to turn it into a *const rustls_server_config. This object is not safe
/// for concurrent mutation.
/// <https://docs.rs/rustls/latest/rustls/struct.ConfigBuilder.html>
pub struct rustls_server_config_builder {
    _private: [u8; 0],
}

pub(crate) struct ServerConfigBuilder {
    base: rustls::ConfigBuilder<ServerConfig, WantsVerifier>,
    verifier: Arc<dyn ClientCertVerifier>,
    cert_resolver: Option<Arc<dyn ResolvesServerCert>>,
    session_storage: Option<Arc<dyn StoresServerSessions + Send + Sync>>,
    alpn_protocols: Vec<Vec<u8>>,
    ignore_client_order: Option<bool>,
}

impl Castable for rustls_server_config_builder {
    type Ownership = OwnershipBox;
    type RustType = ServerConfigBuilder;
}

/// A server config that is done being constructed and is now read-only.
/// Under the hood, this object corresponds to an `Arc<ServerConfig>`.
/// <https://docs.rs/rustls/latest/rustls/struct.ServerConfig.html>
pub struct rustls_server_config {
    _private: [u8; 0],
}

impl Castable for rustls_server_config {
    type Ownership = OwnershipArc;
    type RustType = ServerConfig;
}

impl rustls_server_config_builder {
    /// Create a rustls_server_config_builder. Caller owns the memory and must
    /// eventually call rustls_server_config_builder_build, then free the
    /// resulting rustls_server_config. This uses rustls safe default values
    /// for the cipher suites, key exchange groups and protocol versions.
    #[no_mangle]
    pub extern "C" fn rustls_server_config_builder_new() -> *mut rustls_server_config_builder {
        ffi_panic_boundary! {
            // Unwrap safety: *ring* default provider always has ciphersuites compatible with the
            // default protocol versions.
            let base =
                ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
                    .with_safe_default_protocol_versions()
                    .unwrap();
            let builder = ServerConfigBuilder {
                base,
                verifier: WebPkiClientVerifier::no_client_auth(),
                cert_resolver: None,
                session_storage: None,
                alpn_protocols: vec![],
                ignore_client_order: None,
            };
            to_boxed_mut_ptr(builder)
        }
    }

    /// Create a rustls_server_config_builder. Caller owns the memory and must
    /// eventually call rustls_server_config_builder_build, then free the
    /// resulting rustls_server_config. Specify cipher suites in preference
    /// order; the `cipher_suites` parameter must point to an array containing
    /// `len` pointers to `rustls_supported_ciphersuite` previously obtained
    /// from `rustls_all_ciphersuites_get_entry()`. Set the TLS protocol
    /// versions to use when negotiating a TLS session.
    ///
    /// `tls_version` is the version of the protocol, as defined in rfc8446,
    /// ch. 4.2.1 and end of ch. 5.1. Some values are defined in
    /// `rustls_tls_version` for convenience.
    ///
    /// `versions` will only be used during the call and the application retains
    /// ownership. `len` is the number of consecutive `uint16_t` pointed to by `versions`.
    #[no_mangle]
    pub extern "C" fn rustls_server_config_builder_new_custom(
        cipher_suites: *const *const rustls_supported_ciphersuite,
        cipher_suites_len: size_t,
        tls_versions: *const u16,
        tls_versions_len: size_t,
        builder_out: *mut *mut rustls_server_config_builder,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let cipher_suites: &[*const rustls_supported_ciphersuite] =
                try_slice!(cipher_suites, cipher_suites_len);
            let mut cs_vec: Vec<SupportedCipherSuite> = Vec::new();
            for &cs in cipher_suites.iter() {
                let cs = try_ref_from_ptr!(cs);
                match ALL_CIPHER_SUITES.iter().find(|&acs| cs.eq(acs)) {
                    Some(scs) => cs_vec.push(*scs),
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

            let provider = rustls::crypto::CryptoProvider {
                cipher_suites: cs_vec,
                ..rustls::crypto::ring::default_provider()
            };
            let result = rustls::ServerConfig::builder_with_provider(provider.into())
                .with_protocol_versions(&versions);
            let base = match result {
                Ok(new) => new,
                Err(_) => return rustls_result::InvalidParameter,
            };

            let builder = ServerConfigBuilder {
                base,
                verifier: WebPkiClientVerifier::no_client_auth(),
                cert_resolver: None,
                session_storage: None,
                alpn_protocols: vec![],
                ignore_client_order: None,
            };
            set_boxed_mut_ptr(builder_out, builder);
            rustls_result::Ok
        }
    }

    /// Create a rustls_server_config_builder for TLS sessions that may verify client
    /// certificates. This increases the refcount of `verifier` and doesn't take ownership.
    #[no_mangle]
    pub extern "C" fn rustls_server_config_builder_set_client_verifier(
        builder: *mut rustls_server_config_builder,
        verifier: *const rustls_client_cert_verifier,
    ) {
        ffi_panic_boundary! {
            let builder: &mut ServerConfigBuilder = try_mut_from_ptr!(builder);
            let verifier = try_ref_from_ptr!(verifier);
            builder.verifier = verifier.clone();
        }
    }

    /// "Free" a server_config_builder without building it into a rustls_server_config.
    /// Normally builders are built into rustls_server_configs via `rustls_server_config_builder_build`
    /// and may not be free'd or otherwise used afterwards.
    /// Use free only when the building of a config has to be aborted before a config
    /// was created.
    #[no_mangle]
    pub extern "C" fn rustls_server_config_builder_free(config: *mut rustls_server_config_builder) {
        ffi_panic_boundary! {
            free_box(config);
        }
    }

    /// With `ignore` != 0, the server will ignore the client ordering of cipher
    /// suites, aka preference, during handshake and respect its own ordering
    /// as configured.
    /// <https://docs.rs/rustls/latest/rustls/struct.ServerConfig.html#structfield.ignore_client_order>
    #[no_mangle]
    pub extern "C" fn rustls_server_config_builder_set_ignore_client_order(
        builder: *mut rustls_server_config_builder,
        ignore: bool,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let config: &mut ServerConfigBuilder = try_mut_from_ptr!(builder);
            config.ignore_client_order = Some(ignore);
            rustls_result::Ok
        }
    }

    /// Set the ALPN protocol list to the given protocols. `protocols` must point
    /// to a buffer of `rustls_slice_bytes` (built by the caller) with `len`
    /// elements. Each element of the buffer must point to a slice of bytes that
    /// contains a single ALPN protocol from
    /// <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids>.
    ///
    /// This function makes a copy of the data in `protocols` and does not retain
    /// any pointers, so the caller can free the pointed-to memory after calling.
    ///
    /// <https://docs.rs/rustls/latest/rustls/server/struct.ServerConfig.html#structfield.alpn_protocols>
    #[no_mangle]
    pub extern "C" fn rustls_server_config_builder_set_alpn_protocols(
        builder: *mut rustls_server_config_builder,
        protocols: *const rustls_slice_bytes,
        len: size_t,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let config: &mut ServerConfigBuilder = try_mut_from_ptr!(builder);
            let protocols: &[rustls_slice_bytes] = try_slice!(protocols, len);

            let mut vv: Vec<Vec<u8>> = Vec::new();
            for p in protocols {
                let v: &[u8] = try_slice!(p.data, p.len);
                vv.push(v.to_vec());
            }
            config.alpn_protocols = vv;
            rustls_result::Ok
        }
    }

    /// Provide the configuration a list of certificates where the connection
    /// will select the first one that is compatible with the client's signature
    /// verification capabilities. Servers that want to support both ECDSA and
    /// RSA certificates will want the ECSDA to go first in the list.
    ///
    /// The built configuration will keep a reference to all certified keys
    /// provided. The client may `rustls_certified_key_free()` afterwards
    /// without the configuration losing them. The same certified key may also
    /// be used in multiple configs.
    ///
    /// EXPERIMENTAL: installing a client_hello callback will replace any
    /// configured certified keys and vice versa.
    #[no_mangle]
    pub extern "C" fn rustls_server_config_builder_set_certified_keys(
        builder: *mut rustls_server_config_builder,
        certified_keys: *const *const rustls_certified_key,
        certified_keys_len: size_t,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let builder: &mut ServerConfigBuilder = try_mut_from_ptr!(builder);
            let keys_ptrs: &[*const rustls_certified_key] =
                try_slice!(certified_keys, certified_keys_len);
            let mut keys: Vec<Arc<CertifiedKey>> = Vec::new();
            for &key_ptr in keys_ptrs {
                let certified_key: Arc<CertifiedKey> = try_clone_arc!(key_ptr);
                keys.push(certified_key);
            }
            builder.cert_resolver = Some(Arc::new(ResolvesServerCertFromChoices::new(&keys)));
            rustls_result::Ok
        }
    }

    /// Turn a *rustls_server_config_builder (mutable) into a const *rustls_server_config
    /// (read-only).
    #[no_mangle]
    pub extern "C" fn rustls_server_config_builder_build(
        builder: *mut rustls_server_config_builder,
    ) -> *const rustls_server_config {
        ffi_panic_boundary! {
            let builder = try_box_from_ptr!(builder);
            let base = builder.base.with_client_cert_verifier(builder.verifier);
            let mut config = if let Some(r) = builder.cert_resolver {
                base.with_cert_resolver(r)
            } else {
                return null();
            };
            if let Some(ss) = builder.session_storage {
                config.session_storage = ss;
            }
            config.alpn_protocols = builder.alpn_protocols;
            if let Some(ignore_client_order) = builder.ignore_client_order {
                config.ignore_client_order = ignore_client_order;
            }
            to_arc_const_ptr(config)
        }
    }
}

impl rustls_server_config {
    /// "Free" a rustls_server_config previously returned from
    /// rustls_server_config_builder_build. Since rustls_server_config is actually an
    /// atomically reference-counted pointer, extant server connections may still
    /// hold an internal reference to the Rust object. However, C code must
    /// consider this pointer unusable after "free"ing it.
    /// Calling with NULL is fine. Must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_server_config_free(config: *const rustls_server_config) {
        ffi_panic_boundary! {
            free_arc(config);
        }
    }

    /// Create a new rustls_connection containing a server connection, and return it
    /// in the output parameter `out`. If this returns an error code, the memory
    /// pointed to by `conn_out` remains unchanged. If this returns a non-error,
    /// the memory pointed to by `conn_out` is modified to point
    /// at a valid rustls_connection. The caller now owns the rustls_connection
    /// and must call `rustls_connection_free` when done with it.
    #[no_mangle]
    pub extern "C" fn rustls_server_connection_new(
        config: *const rustls_server_config,
        conn_out: *mut *mut rustls_connection,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let config: Arc<ServerConfig> = try_clone_arc!(config);

            let server_connection = match ServerConnection::new(config) {
                Ok(sc) => sc,
                Err(e) => return map_error(e),
            };
            // We've succeeded. Put the server on the heap, and transfer ownership
            // to the caller. After this point, we must return rustls_result::Ok so the
            // caller knows it is responsible for this memory.
            let c = Connection::from_server(server_connection);
            set_boxed_mut_ptr(conn_out, c);
            rustls_result::Ok
        }
    }
}

/// Copy the server name from the server name indication (SNI) extension to `buf` which can
/// hold up  to `count` bytes, and the length of that server name in `out_n`. The string is
/// stored in UTF-8 with no terminating NUL byte.
/// Returns RUSTLS_RESULT_INSUFFICIENT_SIZE if the SNI hostname is longer than `count`.
/// Returns Ok with *out_n == 0 if there is no SNI hostname available on this connection
/// because it hasn't been processed yet, or because the client did not send SNI.
/// <https://docs.rs/rustls/latest/rustls/server/struct.ServerConnection.html#method.server_name>
#[no_mangle]
pub extern "C" fn rustls_server_connection_get_server_name(
    conn: *const rustls_connection,
    buf: *mut u8,
    count: size_t,
    out_n: *mut size_t,
) -> rustls_result {
    ffi_panic_boundary! {
        let conn: &Connection = try_ref_from_ptr!(conn);
        if buf.is_null() {
            return NullParameter;
        }
        if out_n.is_null() {
            return NullParameter;
        }
        let server_connection = match conn.as_server() {
            Some(s) => s,
            _ => return rustls_result::InvalidParameter,
        };
        let sni_hostname = match server_connection.server_name() {
            Some(sni_hostname) => sni_hostname,
            None => {
                unsafe {
                    *out_n = 0;
                }
                return rustls_result::Ok;
            }
        };
        let len: usize = sni_hostname.len();
        if len > count {
            unsafe { *out_n = 0 }
            return rustls_result::InsufficientSize;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(sni_hostname.as_ptr(), buf, len);
            *out_n = len;
        }
        rustls_result::Ok
    }
}

/// Choose the server certificate to be used for a connection based on certificate
/// type. Will pick the first CertfiedKey available that is suitable for
/// the SignatureSchemes supported by the client.
#[derive(Debug)]
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
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        for key in self.choices.iter() {
            if key
                .key
                .choose_scheme(client_hello.signature_schemes())
                .is_some()
            {
                return Some(key.clone());
            }
        }
        None
    }
}

/// The TLS Client Hello information provided to a ClientHelloCallback function.
/// `server_name` is the value of the ServerNameIndication extension provided
/// by the client. If the client did not send an SNI, the length of this
/// `rustls_string` will be 0. The signature_schemes field carries the values
/// supplied by the client or, if the client did not send this TLS extension,
/// the default schemes in the rustls library. See:
/// <https://docs.rs/rustls/latest/rustls/internal/msgs/enums/enum.SignatureScheme.html>.
/// `alpn` carries the list of ALPN protocol names that the client proposed to
/// the server. Again, the length of this list will be 0 if none were supplied.
///
/// All this data, when passed to a callback function, is only accessible during
/// the call and may not be modified. Users of this API must copy any values that
/// they want to access when the callback returned.
///
/// EXPERIMENTAL: this feature of rustls-ffi is likely to change in the future, as
/// the rustls library is re-evaluating their current approach to client hello handling.
#[repr(C)]
pub struct rustls_client_hello<'a> {
    server_name: rustls_str<'a>,
    signature_schemes: rustls_slice_u16<'a>,
    alpn: *const rustls_slice_slice_bytes<'a>,
}

impl<'a> Castable for rustls_client_hello<'a> {
    type Ownership = OwnershipRef;
    type RustType = rustls_client_hello<'a>;
}

/// Any context information the callback will receive when invoked.
pub type rustls_client_hello_userdata = *mut c_void;

/// Prototype of a callback that can be installed by the application at the
/// `rustls_server_config`. This callback will be invoked by a `rustls_connection`
/// once the TLS client hello message has been received.
/// `userdata` will be set based on rustls_connection_set_userdata.
/// `hello` gives the value of the available client announcements, as interpreted
/// by rustls. See the definition of `rustls_client_hello` for details.
///
/// NOTE:
/// - the passed in `hello` and all its values are only available during the
///   callback invocations.
/// - the passed callback function must be safe to call multiple times concurrently
///   with the same userdata, unless there is only a single config and connection
///   where it is installed.
///
/// EXPERIMENTAL: this feature of rustls-ffi is likely to change in the future, as
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
}

impl ClientHelloResolver {
    pub fn new(callback: ClientHelloCallback) -> ClientHelloResolver {
        ClientHelloResolver { callback }
    }
}

impl ResolvesServerCert for ClientHelloResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let server_name: &str = {
            match client_hello.server_name() {
                Some(c) => c,
                None => "",
            }
        };
        let server_name: rustls_str = match server_name.try_into() {
            Ok(r) => r,
            Err(_) => return None,
        };
        let mapped_sigs: Vec<u16> = client_hello
            .signature_schemes()
            .iter()
            .map(|s| u16::from(*s))
            .collect();
        // Unwrap the Option. None becomes an empty slice.
        let alpn = match client_hello.alpn() {
            Some(iter) => iter.collect(),
            None => vec![],
        };

        let alpn = rustls_slice_slice_bytes { inner: &alpn };
        let signature_schemes: rustls_slice_u16 = (&*mapped_sigs).into();
        let hello = rustls_client_hello {
            server_name,
            signature_schemes,
            alpn: &alpn,
        };

        let cb = self.callback;
        let userdata = match userdata_get() {
            Ok(u) => u,
            Err(_) => return None,
        };
        let key_ptr: *const rustls_certified_key = unsafe { cb(userdata, &hello) };
        let certified_key: &CertifiedKey = try_ref_from_ptr!(key_ptr);
        Some(Arc::new(certified_key.clone()))
    }
}

/// This struct can be considered thread safe, as long
/// as the registered callbacks are thread safe. This is
/// documented as a requirement in the API.
unsafe impl Sync for ClientHelloResolver {}
unsafe impl Send for ClientHelloResolver {}

impl Debug for ClientHelloResolver {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientHelloResolver").finish()
    }
}

impl rustls_server_config_builder {
    /// Register a callback to be invoked when a connection created from this config
    /// sees a TLS ClientHello message. If `userdata` has been set with
    /// rustls_connection_set_userdata, it will be passed to the callback.
    /// Otherwise the userdata param passed to the callback will be NULL.
    ///
    /// Any existing `ResolvesServerCert` implementation currently installed in the
    /// `rustls_server_config` will be replaced. This also means registering twice
    /// will overwrite the first registration. It is not permitted to pass a NULL
    /// value for `callback`.
    ///
    /// EXPERIMENTAL: this feature of rustls-ffi is likely to change in the future, as
    /// the rustls library is re-evaluating their current approach to client hello handling.
    /// Installing a client_hello callback will replace any configured certified keys
    /// and vice versa. Same holds true for the set_certified_keys variant.
    #[no_mangle]
    pub extern "C" fn rustls_server_config_builder_set_hello_callback(
        builder: *mut rustls_server_config_builder,
        callback: rustls_client_hello_callback,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let callback: ClientHelloCallback = match callback {
                Some(cb) => cb,
                None => return rustls_result::NullParameter,
            };
            let builder: &mut ServerConfigBuilder = try_mut_from_ptr!(builder);
            builder.cert_resolver = Some(Arc::new(ClientHelloResolver::new(callback)));
            rustls_result::Ok
        }
    }
}

// Turn a slice of u16's into a vec of SignatureScheme as needed by rustls.
fn sigschemes(input: &[u16]) -> Vec<SignatureScheme> {
    input.iter().copied().map(Into::into).collect()
}

/// Select a `rustls_certified_key` from the list that matches the cryptographic
/// parameters of a TLS client hello. Note that this does not do any SNI matching.
/// The input certificates should already have been filtered to ones matching the
/// SNI from the client hello.
///
/// This is intended for servers that are configured with several keys for the
/// same domain name(s), for example ECDSA and RSA types. The presented keys are
/// inspected in the order given and keys first in the list are given preference,
/// all else being equal. However rustls is free to choose whichever it considers
/// to be the best key with its knowledge about security issues and possible future
/// extensions of the protocol.
///
/// Return RUSTLS_RESULT_OK if a key was selected and RUSTLS_RESULT_NOT_FOUND
/// if none was suitable.
#[no_mangle]
pub extern "C" fn rustls_client_hello_select_certified_key(
    hello: *const rustls_client_hello,
    certified_keys: *const *const rustls_certified_key,
    certified_keys_len: size_t,
    out_key: *mut *const rustls_certified_key,
) -> rustls_result {
    ffi_panic_boundary! {
        let hello = try_ref_from_ptr!(hello);
        let schemes: Vec<SignatureScheme> = sigschemes(try_slice!(
            hello.signature_schemes.data,
            hello.signature_schemes.len
        ));
        if out_key.is_null() {
            return NullParameter;
        }
        let keys_ptrs: &[*const rustls_certified_key] =
            try_slice!(certified_keys, certified_keys_len);
        for &key_ptr in keys_ptrs {
            let key_ref: &CertifiedKey = try_ref_from_ptr!(key_ptr);
            if key_ref.key.choose_scheme(&schemes).is_some() {
                unsafe {
                    *out_key = key_ptr;
                }
                return rustls_result::Ok;
            }
        }
        rustls_result::NotFound
    }
}

impl rustls_server_config_builder {
    /// Register callbacks for persistence of TLS session IDs and secrets. Both
    /// keys and values are highly sensitive data, containing enough information
    /// to break the security of the connections involved.
    ///
    /// If `userdata` has been set with rustls_connection_set_userdata, it
    /// will be passed to the callbacks. Otherwise the userdata param passed to
    /// the callbacks will be NULL.
    #[no_mangle]
    pub extern "C" fn rustls_server_config_builder_set_persistence(
        builder: *mut rustls_server_config_builder,
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
            let builder: &mut ServerConfigBuilder = try_mut_from_ptr!(builder);
            builder.session_storage = Some(Arc::new(SessionStoreBroker::new(get_cb, put_cb)));
            rustls_result::Ok
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ptr::null_mut;

    use super::*;

    #[test]
    fn test_config_builder() {
        let builder: *mut rustls_server_config_builder =
            rustls_server_config_builder::rustls_server_config_builder_new();
        let h1 = "http/1.1".as_bytes();
        let h2 = "h2".as_bytes();
        let alpn: Vec<rustls_slice_bytes> = vec![h1.into(), h2.into()];
        rustls_server_config_builder::rustls_server_config_builder_set_alpn_protocols(
            builder,
            alpn.as_ptr(),
            alpn.len(),
        );
        let config = rustls_server_config_builder::rustls_server_config_builder_build(builder);
        {
            let config2 = try_ref_from_ptr!(config);
            assert_eq!(config2.alpn_protocols, vec![h1, h2]);
        }
        rustls_server_config::rustls_server_config_free(config);
    }

    // Build a server connection and test the getters and initial values.
    #[test]
    fn test_server_config_builder_new_empty() {
        let builder: *mut rustls_server_config_builder =
            rustls_server_config_builder::rustls_server_config_builder_new();
        // Building a config with no certificate and key configured results in null.
        assert_eq!(
            rustls_server_config_builder::rustls_server_config_builder_build(builder),
            null()
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_server_connection_new() {
        let builder: *mut rustls_server_config_builder =
            rustls_server_config_builder::rustls_server_config_builder_new();
        let cert_pem = include_str!("../testdata/localhost/cert.pem").as_bytes();
        let key_pem = include_str!("../testdata/localhost/key.pem").as_bytes();
        let mut certified_key: *const rustls_certified_key = null();
        let result = rustls_certified_key::rustls_certified_key_build(
            cert_pem.as_ptr(),
            cert_pem.len(),
            key_pem.as_ptr(),
            key_pem.len(),
            &mut certified_key,
        );
        if !matches!(result, rustls_result::Ok) {
            panic!(
                "expected RUSTLS_RESULT_OK from rustls_certified_key_build, got {:?}",
                result
            );
        }
        rustls_server_config_builder::rustls_server_config_builder_set_certified_keys(
            builder,
            &certified_key,
            1,
        );

        let config = rustls_server_config_builder::rustls_server_config_builder_build(builder);
        assert_ne!(config, null());

        let mut conn: *mut rustls_connection = null_mut();
        let result = rustls_server_config::rustls_server_connection_new(config, &mut conn);
        if !matches!(result, rustls_result::Ok) {
            panic!("expected RUSTLS_RESULT_OK, got {:?}", result);
        }
        assert_eq!(rustls_connection::rustls_connection_wants_read(conn), true);
        assert_eq!(
            rustls_connection::rustls_connection_wants_write(conn),
            false
        );
        assert_eq!(
            rustls_connection::rustls_connection_is_handshaking(conn),
            true
        );

        let some_byte = 42u8;
        let mut alpn_protocol: *const u8 = &some_byte;
        let mut alpn_protocol_len: usize = 1;
        rustls_connection::rustls_connection_get_alpn_protocol(
            conn,
            &mut alpn_protocol,
            &mut alpn_protocol_len,
        );
        assert_eq!(alpn_protocol, null());
        assert_eq!(alpn_protocol_len, 0);

        assert_eq!(
            rustls_connection::rustls_connection_get_negotiated_ciphersuite(conn),
            null()
        );
        assert_eq!(
            rustls_connection::rustls_connection_get_peer_certificate(conn, 0),
            null()
        );

        assert_eq!(
            rustls_connection::rustls_connection_get_protocol_version(conn),
            0
        );
        rustls_connection::rustls_connection_free(conn);
    }
}
