use std::ffi::CStr;
use std::fmt::{Debug, Formatter};
use std::slice;
use std::sync::Arc;

use libc::{c_char, size_t};
use pki_types::{CertificateDer, UnixTime};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::ResolvesClientCert;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::{
    sign::CertifiedKey, ClientConfig, ClientConnection, DigitallySignedStruct, Error,
    ProtocolVersion, SignatureScheme, SupportedProtocolVersion,
};

use crate::cipher::{rustls_certified_key, rustls_server_cert_verifier};
use crate::connection::{rustls_connection, Connection};
use crate::crypto_provider::rustls_crypto_provider;
use crate::error::rustls_result::{InvalidParameter, NullParameter};
use crate::error::{self, map_error, rustls_result};
use crate::rslice::NulByte;
use crate::rslice::{rustls_slice_bytes, rustls_slice_slice_bytes, rustls_str};
use crate::{
    arc_castable, box_castable, crypto_provider, ffi_panic_boundary, free_arc, free_box,
    set_arc_mut_ptr, set_boxed_mut_ptr, to_boxed_mut_ptr, try_box_from_ptr, try_clone_arc,
    try_mut_from_ptr, try_mut_from_ptr_ptr, try_ref_from_ptr, try_ref_from_ptr_ptr, try_slice,
    userdata_get,
};

box_castable! {
    /// A client config being constructed.
    ///
    /// A builder can be modified by, e.g. `rustls_client_config_builder_load_roots_from_file`.
    /// Once you're done configuring settings, call `rustls_client_config_builder_build`
    /// to turn it into a *rustls_client_config.
    ///
    /// Alternatively, if an error occurs or, you don't wish to build a config,
    /// call `rustls_client_config_builder_free` to free the builder directly.
    ///
    /// This object is not safe for concurrent mutation. Under the hood,
    /// it corresponds to a `Box<ClientConfig>`.
    /// <https://docs.rs/rustls/latest/rustls/struct.ConfigBuilder.html>
    pub struct rustls_client_config_builder(ClientConfigBuilder);
}

pub(crate) struct ClientConfigBuilder {
    provider: Option<Arc<CryptoProvider>>,
    versions: Vec<&'static SupportedProtocolVersion>,
    verifier: Option<Arc<dyn ServerCertVerifier>>,
    alpn_protocols: Vec<Vec<u8>>,
    enable_sni: bool,
    cert_resolver: Option<Arc<dyn ResolvesClientCert>>,
}

arc_castable! {
    /// A client config that is done being constructed and is now read-only.
    ///
    /// Under the hood, this object corresponds to an `Arc<ClientConfig>`.
    /// <https://docs.rs/rustls/latest/rustls/struct.ClientConfig.html>
    pub struct rustls_client_config(ClientConfig);
}

impl rustls_client_config_builder {
    /// Create a rustls_client_config_builder using the process default crypto provider.
    ///
    /// Caller owns the memory and must eventually call `rustls_client_config_builder_build`,
    /// then free the resulting `rustls_client_config`.
    ///
    /// Alternatively, if an error occurs or, you don't wish to build a config,
    /// call `rustls_client_config_builder_free` to free the builder directly.
    ///
    /// This uses the process default provider's values for the cipher suites and key
    /// exchange groups, as well as safe defaults for protocol versions.
    ///
    /// This starts out with no trusted roots. Caller must add roots with
    /// rustls_client_config_builder_load_roots_from_file or provide a custom verifier.
    #[no_mangle]
    pub extern "C" fn rustls_client_config_builder_new() -> *mut rustls_client_config_builder {
        ffi_panic_boundary! {
            let builder = ClientConfigBuilder {
                provider: crypto_provider::get_default_or_install_from_crate_features(),
                versions: rustls::DEFAULT_VERSIONS.to_vec(),
                verifier: None,
                cert_resolver: None,
                alpn_protocols: vec![],
                enable_sni: true,
            };
            to_boxed_mut_ptr(builder)
        }
    }

    /// Create a rustls_client_config_builder using the specified crypto provider.
    ///
    /// Caller owns the memory and must eventually call `rustls_client_config_builder_build`,
    /// then free the resulting `rustls_client_config`.
    ///
    /// Alternatively, if an error occurs or, you don't wish to build a config,
    /// call `rustls_client_config_builder_free` to free the builder directly.
    ///
    /// `tls_version` sets the TLS protocol versions to use when negotiating a TLS session.
    /// `tls_version` is the version of the protocol, as defined in rfc8446,
    /// ch. 4.2.1 and end of ch. 5.1. Some values are defined in
    /// `rustls_tls_version` for convenience, and the arrays
    /// RUSTLS_DEFAULT_VERSIONS or RUSTLS_ALL_VERSIONS can be used directly.
    ///
    /// `tls_versions` will only be used during the call and the application retains
    /// ownership. `tls_versions_len` is the number of consecutive `uint16_t`
    /// pointed to by `tls_versions`.
    ///
    /// Ciphersuites are configured separately via the crypto provider. See
    /// `rustls_crypto_provider_builder_set_cipher_suites` for more information.
    #[no_mangle]
    pub extern "C" fn rustls_client_config_builder_new_custom(
        provider: *const rustls_crypto_provider,
        tls_versions: *const u16,
        tls_versions_len: size_t,
        builder_out: *mut *mut rustls_client_config_builder,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let provider = try_clone_arc!(provider);
            let tls_versions = try_slice!(tls_versions, tls_versions_len);
            let mut versions = vec![];
            for version_number in tls_versions {
                let proto = ProtocolVersion::from(*version_number);
                if proto == rustls::version::TLS12.version {
                    versions.push(&rustls::version::TLS12);
                } else if proto == rustls::version::TLS13.version {
                    versions.push(&rustls::version::TLS13);
                }
            }
            let builder_out = try_mut_from_ptr_ptr!(builder_out);

            let config_builder = ClientConfigBuilder {
                provider: Some(provider),
                versions,
                verifier: None,
                cert_resolver: None,
                alpn_protocols: vec![],
                enable_sni: true,
            };

            set_boxed_mut_ptr(builder_out, config_builder);
            rustls_result::Ok
        }
    }
}

/// Input to a custom certificate verifier callback.
///
/// See `rustls_client_config_builder_dangerous_set_certificate_verifier()`.
///
/// server_name can contain a hostname, an IPv4 address in textual form, or an
/// IPv6 address in textual form.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct rustls_verify_server_cert_params<'a> {
    pub end_entity_cert_der: rustls_slice_bytes<'a>,
    pub intermediate_certs_der: &'a rustls_slice_slice_bytes<'a>,
    pub server_name: rustls_str<'a>,
    pub ocsp_response: rustls_slice_bytes<'a>,
}

/// User-provided input to a custom certificate verifier callback.
///
/// See `rustls_client_config_builder_dangerous_set_certificate_verifier()`.
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
    ) -> u32,
>;

// This is the same as a rustls_verify_server_cert_callback after unwrapping
// the Option (which is equivalent to checking for null).
type VerifyCallback = unsafe extern "C" fn(
    userdata: rustls_verify_server_cert_user_data,
    params: *const rustls_verify_server_cert_params,
) -> u32;

// An implementation of rustls::ServerCertVerifier based on a C callback.
struct Verifier {
    provider: Arc<CryptoProvider>,
    callback: VerifyCallback,
}

/// Safety: Verifier is Send because we don't allocate or deallocate any of its
/// fields.
unsafe impl Send for Verifier {}

/// Safety: Verifier is Sync if the C code that passes us a callback that
/// obeys the concurrency safety requirements documented in
/// rustls_client_config_builder_dangerous_set_certificate_verifier.
unsafe impl Sync for Verifier {}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer,
        intermediates: &[CertificateDer],
        server_name: &pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let cb = self.callback;
        let server_name = server_name.to_str();
        let server_name = match server_name.as_ref().try_into() {
            Ok(r) => r,
            Err(NulByte {}) => return Err(Error::General("NUL byte in SNI".to_string())),
        };

        let intermediates: Vec<_> = intermediates.iter().map(|cert| cert.as_ref()).collect();

        let intermediates = rustls_slice_slice_bytes {
            inner: &intermediates,
        };

        let params = rustls_verify_server_cert_params {
            end_entity_cert_der: end_entity.as_ref().into(),
            intermediate_certs_der: &intermediates,
            server_name,
            ocsp_response: ocsp_response.into(),
        };
        let userdata = userdata_get()
            .map_err(|_| Error::General("internal error with thread-local storage".to_string()))?;
        let result = unsafe { cb(userdata, &params) };
        match rustls_result::from(result) {
            rustls_result::Ok => Ok(ServerCertVerified::assertion()),
            r => Err(error::cert_result_to_error(r)),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl Debug for Verifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verifier").finish()
    }
}

impl rustls_client_config_builder {
    /// Set a custom server certificate verifier using the builder crypto provider.
    /// Returns rustls_result::NoDefaultCryptoProvider if no process default crypto
    /// provider has been set, and the builder was not constructed with an explicit
    /// provider choice.
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
    /// Currently this library offers no functions to parse the certificates,
    /// so you'll need to bring your own certificate parsing library
    /// if you need to parse them.
    ///
    /// If the custom verifier accepts the certificate, it should return
    /// RUSTLS_RESULT_OK. Otherwise, it may return any other rustls_result error.
    /// Feel free to use an appropriate error from the RUSTLS_RESULT_CERT_*
    /// section.
    ///
    /// <https://docs.rs/rustls/latest/rustls/client/struct.DangerousClientConfig.html#method.set_certificate_verifier>
    #[no_mangle]
    pub extern "C" fn rustls_client_config_builder_dangerous_set_certificate_verifier(
        config_builder: *mut rustls_client_config_builder,
        callback: rustls_verify_server_cert_callback,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let config_builder = try_mut_from_ptr!(config_builder);
            let callback = match callback {
                Some(cb) => cb,
                None => return InvalidParameter,
            };

            let provider = match &config_builder.provider {
                Some(provider) => provider.clone(),
                None => return rustls_result::NoDefaultCryptoProvider,
            };

            config_builder.verifier = Some(Arc::new(Verifier { provider, callback }));
            rustls_result::Ok
        }
    }

    /// Configure the server certificate verifier.
    ///
    /// This increases the reference count of `verifier` and does not take ownership.
    #[no_mangle]
    pub extern "C" fn rustls_client_config_builder_set_server_verifier(
        builder: *mut rustls_client_config_builder,
        verifier: *const rustls_server_cert_verifier,
    ) {
        ffi_panic_boundary! {
            let builder = try_mut_from_ptr!(builder);
            builder.verifier = Some(try_ref_from_ptr!(verifier).clone());
        }
    }

    /// Set the ALPN protocol list to the given protocols.
    ///
    /// `protocols` must point to a buffer of `rustls_slice_bytes` (built by the caller) with `len`
    /// elements.
    ///
    /// Each element of the buffer must be a rustls_slice_bytes whose
    /// data field points to a single ALPN protocol ID.
    ///
    /// Standard ALPN protocol IDs are defined at
    /// <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids>.
    ///
    /// This function makes a copy of the data in `protocols` and does not retain
    /// any pointers, so the caller can free the pointed-to memory after calling.
    ///
    /// <https://docs.rs/rustls/latest/rustls/client/struct.ClientConfig.html#structfield.alpn_protocols>
    #[no_mangle]
    pub extern "C" fn rustls_client_config_builder_set_alpn_protocols(
        builder: *mut rustls_client_config_builder,
        protocols: *const rustls_slice_bytes,
        len: size_t,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let config = try_mut_from_ptr!(builder);
            let protocols = try_slice!(protocols, len);

            let mut vv = Vec::with_capacity(protocols.len());
            for p in protocols {
                let v = try_slice!(p.data, p.len);
                vv.push(v.to_vec());
            }
            config.alpn_protocols = vv;
            rustls_result::Ok
        }
    }

    /// Enable or disable SNI.
    /// <https://docs.rs/rustls/latest/rustls/struct.ClientConfig.html#structfield.enable_sni>
    #[no_mangle]
    pub extern "C" fn rustls_client_config_builder_set_enable_sni(
        config: *mut rustls_client_config_builder,
        enable: bool,
    ) {
        ffi_panic_boundary! {
            let config = try_mut_from_ptr!(config);
            config.enable_sni = enable;
        }
    }

    /// Provide the configuration a list of certificates where the connection
    /// will select the first one that is compatible with the server's signature
    /// verification capabilities.
    ///
    /// Clients that want to support both ECDSA and RSA certificates will want the
    /// ECSDA to go first in the list.
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
            let config = try_mut_from_ptr!(builder);
            let keys_ptrs = try_slice!(certified_keys, certified_keys_len);
            let mut keys = Vec::new();
            for &key_ptr in keys_ptrs {
                let certified_key = try_clone_arc!(key_ptr);
                keys.push(certified_key);
            }
            config.cert_resolver = Some(Arc::new(ResolvesClientCertFromChoices { keys }));
            rustls_result::Ok
        }
    }
}

/// Always send the same client certificate.
#[derive(Debug)]
struct ResolvesClientCertFromChoices {
    keys: Vec<Arc<CertifiedKey>>,
}

impl ResolvesClientCert for ResolvesClientCertFromChoices {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        sig_schemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
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
        config_out: *mut *const rustls_client_config,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let builder = try_box_from_ptr!(builder);
            let config_out = try_ref_from_ptr_ptr!(config_out);

            let provider = match builder.provider {
                Some(provider) => provider,
                None => return rustls_result::NoDefaultCryptoProvider,
            };

            let verifier = match builder.verifier {
                Some(v) => v,
                None => return rustls_result::NoServerCertVerifier,
            };

            let config = match ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&builder.versions)
            {
                Ok(c) => c,
                Err(err) => return map_error(err),
            };

            let config = config
                .dangerous()
                .with_custom_certificate_verifier(verifier);
            let mut config = match builder.cert_resolver {
                Some(r) => config.with_client_cert_resolver(r),
                None => config.with_no_client_auth(),
            };
            config.alpn_protocols = builder.alpn_protocols;
            config.enable_sni = builder.enable_sni;

            set_arc_mut_ptr(config_out, config);
            rustls_result::Ok
        }
    }

    /// "Free" a client_config_builder without building it into a rustls_client_config.
    ///
    /// Normally builders are built into rustls_client_config via `rustls_client_config_builder_build`
    /// and may not be free'd or otherwise used afterwards.
    ///
    /// Use free only when the building of a config has to be aborted before a config
    /// was created.
    #[no_mangle]
    pub extern "C" fn rustls_client_config_builder_free(config: *mut rustls_client_config_builder) {
        ffi_panic_boundary! {
            free_box(config);
        }
    }
}

impl rustls_client_config {
    /// "Free" a `rustls_client_config` previously returned from
    /// `rustls_client_config_builder_build`.
    ///
    /// Since `rustls_client_config` is actually an atomically reference-counted pointer,
    /// extant client connections may still hold an internal reference to the Rust object.
    ///
    /// However, C code must consider this pointer unusable after "free"ing it.
    ///
    /// Calling with NULL is fine. Must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_client_config_free(config: *const rustls_client_config) {
        ffi_panic_boundary! {
            free_arc(config);
        }
    }

    /// Create a new rustls_connection containing a client connection and return
    /// it in the output parameter `conn_out`.
    ///
    /// If this returns an error code, the memory pointed to by `conn_out` remains
    /// unchanged.
    ///
    /// If this returns a non-error, the memory pointed to by `conn_out`
    /// is modified to point at a valid `rustls_connection`.  The caller now owns
    /// the `rustls_connection` and must call `rustls_connection_free` when done with it.
    ///
    /// The server_name parameter can contain a hostname or an IP address in
    /// textual form (IPv4 or IPv6). This function will return an error if it
    /// cannot be parsed as one of those types.
    #[no_mangle]
    pub extern "C" fn rustls_client_connection_new(
        config: *const rustls_client_config,
        server_name: *const c_char,
        conn_out: *mut *mut rustls_connection,
    ) -> rustls_result {
        ffi_panic_boundary! {
            if conn_out.is_null() {
                return NullParameter;
            }
            let server_name = unsafe {
                if server_name.is_null() {
                    return NullParameter;
                }
                CStr::from_ptr(server_name)
            };
            let config = try_clone_arc!(config);
            let conn_out = try_mut_from_ptr_ptr!(conn_out);
            let server_name = match server_name.to_str() {
                Ok(s) => s,
                Err(std::str::Utf8Error { .. }) => return rustls_result::InvalidDnsNameError,
            };
            let server_name = match server_name.try_into() {
                Ok(sn) => sn,
                Err(_) => return rustls_result::InvalidDnsNameError,
            };
            let client = ClientConnection::new(config, server_name).unwrap();

            // We've succeeded. Put the client on the heap, and transfer ownership
            // to the caller. After this point, we must return rustls_result::Ok so the
            // caller knows it is responsible for this memory.
            let c = Connection::from_client(client);
            set_boxed_mut_ptr(conn_out, c);
            rustls_result::Ok
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ptr::{null, null_mut};

    use super::*;

    #[test]
    fn test_config_builder() {
        let builder = rustls_client_config_builder::rustls_client_config_builder_new();
        let mut verifier = null_mut();
        let result =
            rustls_server_cert_verifier::rustls_platform_server_cert_verifier(&mut verifier);
        assert_eq!(result, rustls_result::Ok);
        assert!(!verifier.is_null());
        rustls_client_config_builder::rustls_client_config_builder_set_server_verifier(
            builder, verifier,
        );
        let h1 = "http/1.1".as_bytes();
        let h2 = "h2".as_bytes();
        let alpn = [h1.into(), h2.into()];
        rustls_client_config_builder::rustls_client_config_builder_set_alpn_protocols(
            builder,
            alpn.as_ptr(),
            alpn.len(),
        );
        rustls_client_config_builder::rustls_client_config_builder_set_enable_sni(builder, false);
        let mut config = null();
        let result =
            rustls_client_config_builder::rustls_client_config_builder_build(builder, &mut config);
        assert_eq!(result, rustls_result::Ok);
        assert!(!config.is_null());
        {
            let config2 = try_ref_from_ptr!(config);
            assert!(!config2.enable_sni);
            assert_eq!(config2.alpn_protocols, vec![h1, h2]);
        }
        rustls_client_config::rustls_client_config_free(config);
        rustls_server_cert_verifier::rustls_server_cert_verifier_free(verifier);
    }

    // Build a client connection and test the getters and initial values.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_client_connection_new() {
        let builder = rustls_client_config_builder::rustls_client_config_builder_new();
        let mut verifier = null_mut();
        let result =
            rustls_server_cert_verifier::rustls_platform_server_cert_verifier(&mut verifier);
        assert_eq!(result, rustls_result::Ok);
        assert!(!verifier.is_null());
        rustls_client_config_builder::rustls_client_config_builder_set_server_verifier(
            builder, verifier,
        );
        let mut config = null();
        let result =
            rustls_client_config_builder::rustls_client_config_builder_build(builder, &mut config);
        assert_eq!(result, rustls_result::Ok);
        assert!(!config.is_null());
        let mut conn = null_mut();
        let result = rustls_client_config::rustls_client_connection_new(
            config,
            "example.com\0".as_ptr() as *const c_char,
            &mut conn,
        );
        if !matches!(result, rustls_result::Ok) {
            panic!("expected RUSTLS_RESULT_OK, got {:?}", result);
        }
        assert!(!rustls_connection::rustls_connection_wants_read(conn));
        assert!(rustls_connection::rustls_connection_wants_write(conn));
        assert!(rustls_connection::rustls_connection_is_handshaking(conn));

        let some_byte = 42u8;
        let mut alpn_protocol: *const u8 = &some_byte;
        let mut alpn_protocol_len = 1;
        rustls_connection::rustls_connection_get_alpn_protocol(
            conn,
            &mut alpn_protocol,
            &mut alpn_protocol_len,
        );
        assert_eq!(alpn_protocol, null());
        assert_eq!(alpn_protocol_len, 0);

        assert_eq!(
            rustls_connection::rustls_connection_get_negotiated_ciphersuite(conn),
            0
        );
        let cs_name = rustls_connection::rustls_connection_get_negotiated_ciphersuite_name(conn);
        assert_eq!(unsafe { cs_name.to_str() }, "");
        assert_eq!(
            rustls_connection::rustls_connection_get_peer_certificate(conn, 0),
            null()
        );

        assert_eq!(
            rustls_connection::rustls_connection_get_protocol_version(conn),
            0
        );
        rustls_connection::rustls_connection_free(conn);
        rustls_server_cert_verifier::rustls_server_cert_verifier_free(verifier);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_client_connection_new_ipaddress() {
        let builder = rustls_client_config_builder::rustls_client_config_builder_new();
        let mut verifier = null_mut();
        let result =
            rustls_server_cert_verifier::rustls_platform_server_cert_verifier(&mut verifier);
        assert_eq!(result, rustls_result::Ok);
        assert!(!verifier.is_null());
        rustls_client_config_builder::rustls_client_config_builder_set_server_verifier(
            builder, verifier,
        );
        let mut config = null();
        let result =
            rustls_client_config_builder::rustls_client_config_builder_build(builder, &mut config);
        assert_eq!(result, rustls_result::Ok);
        assert!(!config.is_null());
        let mut conn = null_mut();
        let result = rustls_client_config::rustls_client_connection_new(
            config,
            "198.51.100.198\0".as_ptr() as *const c_char,
            &mut conn,
        );
        if !matches!(result, rustls_result::Ok) {
            panic!("expected RUSTLS_RESULT_OK, got {:?}", result);
        }
        rustls_server_cert_verifier::rustls_server_cert_verifier_free(verifier);
    }

    #[test]
    fn test_client_builder_no_verifier_err() {
        let builder = rustls_client_config_builder::rustls_client_config_builder_new();
        let mut config = null();
        let result =
            rustls_client_config_builder::rustls_client_config_builder_build(builder, &mut config);
        assert_eq!(result, rustls_result::NoServerCertVerifier);
    }
}
