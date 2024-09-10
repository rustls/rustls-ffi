use libc::{c_char, size_t};
use std::ffi::{CStr, OsStr};
use std::fs::File;
use std::io::{BufReader, Cursor};
use std::marker::PhantomData;
use std::ptr::null;
use std::slice;
use std::sync::Arc;

use pki_types::{CertificateDer, CertificateRevocationListDer};
use rustls::client::danger::ServerCertVerifier;
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::server::danger::ClientCertVerifier;
use rustls::server::WebPkiClientVerifier;
use rustls::sign::CertifiedKey;
use rustls::{DistinguishedName, RootCertStore, SupportedCipherSuite};
use rustls_pemfile::{certs, crls};
use webpki::{RevocationCheckDepth, UnknownStatusPolicy};

use crate::crypto_provider::{rustls_crypto_provider, rustls_signing_key};
use crate::enums::rustls_tls_version;
use crate::error::{self, map_error, rustls_result};
use crate::rslice::{rustls_slice_bytes, rustls_str};
use crate::{
    arc_castable, box_castable, crypto_provider, ffi_panic_boundary, free_arc, free_box,
    ref_castable, set_arc_mut_ptr, set_boxed_mut_ptr, to_arc_const_ptr, to_boxed_mut_ptr,
    try_box_from_ptr, try_clone_arc, try_mut_from_ptr, try_mut_from_ptr_ptr, try_ref_from_ptr,
    try_ref_from_ptr_ptr, try_slice, try_take,
};
use rustls_result::{AlreadyUsed, NullParameter};

ref_castable! {
    /// An X.509 certificate, as used in rustls.
    /// Corresponds to `CertificateDer` in the Rust pki-types API.
    /// <https://docs.rs/rustls-pki-types/latest/rustls_pki_types/struct.CertificateDer.html>
    pub struct rustls_certificate(CertificateDer<'a>);
}

/// Get the DER data of the certificate itself.
/// The data is owned by the certificate and has the same lifetime.
#[no_mangle]
pub extern "C" fn rustls_certificate_get_der(
    cert: *const rustls_certificate,
    out_der_data: *mut *const u8,
    out_der_len: *mut size_t,
) -> rustls_result {
    ffi_panic_boundary! {
        let cert = try_ref_from_ptr!(cert);
        if out_der_data.is_null() || out_der_len.is_null() {
            return NullParameter;
        }
        let der = cert.as_ref();
        unsafe {
            *out_der_data = der.as_ptr();
            *out_der_len = der.len();
        }
        rustls_result::Ok
    }
}

ref_castable! {
    /// A cipher suite supported by rustls.
    pub struct rustls_supported_ciphersuite(SupportedCipherSuite);
}

impl rustls_supported_ciphersuite {
    /// Return a 16-bit unsigned integer corresponding to this cipher suite's assignment from
    /// <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4>.
    ///
    /// The bytes from the assignment are interpreted in network order.
    #[no_mangle]
    pub extern "C" fn rustls_supported_ciphersuite_get_suite(
        supported_ciphersuite: *const rustls_supported_ciphersuite,
    ) -> u16 {
        let supported_ciphersuite = try_ref_from_ptr!(supported_ciphersuite);
        u16::from(
            match supported_ciphersuite {
                rustls::SupportedCipherSuite::Tls12(sc) => &sc.common,
                rustls::SupportedCipherSuite::Tls13(sc) => &sc.common,
            }
            .suite,
        )
    }
}

/// Returns the name of the ciphersuite as a `rustls_str`.
///
/// If the provided ciphersuite is invalid, the `rustls_str` will contain the
/// empty string. The lifetime of the `rustls_str` is the lifetime of the program,
/// it does not need to be freed.
#[no_mangle]
pub extern "C" fn rustls_supported_ciphersuite_get_name(
    supported_ciphersuite: *const rustls_supported_ciphersuite,
) -> rustls_str<'static> {
    let supported_ciphersuite = try_ref_from_ptr!(supported_ciphersuite);
    let s = supported_ciphersuite.suite().as_str().unwrap_or("");
    match rustls_str::try_from(s) {
        Ok(s) => s,
        Err(_) => rustls_str::from_str_unchecked(""),
    }
}

/// Returns the `rustls_tls_version` of the ciphersuite.
///
/// See also `RUSTLS_ALL_VERSIONS`.
#[no_mangle]
pub extern "C" fn rustls_supported_ciphersuite_protocol_version(
    supported_ciphersuite: *const rustls_supported_ciphersuite,
) -> rustls_tls_version {
    ffi_panic_boundary! {
        rustls_tls_version::from(try_ref_from_ptr!(supported_ciphersuite).version())
    }
}

arc_castable! {
    /// The complete chain of certificates to send during a TLS handshake,
    /// plus a private key that matches the end-entity (leaf) certificate.
    ///
    /// Corresponds to `CertifiedKey` in the Rust API.
    /// <https://docs.rs/rustls/latest/rustls/sign/struct.CertifiedKey.html>
    pub struct rustls_certified_key(CertifiedKey);
}

impl rustls_certified_key {
    /// Build a `rustls_certified_key` from a certificate chain and a private key
    /// and the default process-wide crypto provider.
    ///
    /// `cert_chain` must point to a buffer of `cert_chain_len` bytes, containing
    /// a series of PEM-encoded certificates, with the end-entity (leaf)
    /// certificate first.
    ///
    /// `private_key` must point to a buffer of `private_key_len` bytes, containing
    /// a PEM-encoded private key in either PKCS#1, PKCS#8 or SEC#1 format when
    /// using `aws-lc-rs` as the crypto provider. Supported formats may vary by
    /// provider.
    ///
    /// On success, this writes a pointer to the newly created
    /// `rustls_certified_key` in `certified_key_out`. That pointer must later
    /// be freed with `rustls_certified_key_free` to avoid memory leaks. Note that
    /// internally, this is an atomically reference-counted pointer, so even after
    /// the original caller has called `rustls_certified_key_free`, other objects
    /// may retain a pointer to the object. The memory will be freed when all
    /// references are gone.
    ///
    /// This function does not take ownership of any of its input pointers. It
    /// parses the pointed-to data and makes a copy of the result. You may
    /// free the cert_chain and private_key pointers after calling it.
    ///
    /// Typically, you will build a `rustls_certified_key`, use it to create a
    /// `rustls_server_config` (which increments the reference count), and then
    /// immediately call `rustls_certified_key_free`. That leaves the
    /// `rustls_server_config` in possession of the sole reference, so the
    /// `rustls_certified_key`'s memory will automatically be released when
    /// the `rustls_server_config` is freed.
    #[no_mangle]
    pub extern "C" fn rustls_certified_key_build(
        cert_chain: *const u8,
        cert_chain_len: size_t,
        private_key: *const u8,
        private_key_len: size_t,
        certified_key_out: *mut *const rustls_certified_key,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let default_provider =
                match crypto_provider::get_default_or_install_from_crate_features() {
                    Some(default_provider) => default_provider,
                    None => return rustls_result::NoDefaultCryptoProvider,
                };
            let private_key_pem = try_slice!(private_key, private_key_len);

            let private_key_der =
                match rustls_pemfile::private_key(&mut Cursor::new(private_key_pem)) {
                    Ok(Some(p)) => p,
                    _ => return rustls_result::PrivateKeyParseError,
                };

            let private_key = match default_provider
                .key_provider
                .load_private_key(private_key_der)
            {
                Ok(key) => key,
                Err(e) => return map_error(e),
            };

            Self::rustls_certified_key_build_with_signing_key(
                cert_chain,
                cert_chain_len,
                to_boxed_mut_ptr(private_key),
                certified_key_out,
            )
        }
    }

    /// Build a `rustls_certified_key` from a certificate chain and a
    /// `rustls_signing_key`.
    ///
    /// `cert_chain` must point to a buffer of `cert_chain_len` bytes, containing
    /// a series of PEM-encoded certificates, with the end-entity (leaf)
    /// certificate first.
    ///
    /// `signing_key` must point to a `rustls_signing_key` loaded using a
    /// `rustls_crypto_provider` and `rustls_crypto_provider_load_key()`.
    ///
    /// On success, this writes a pointer to the newly created
    /// `rustls_certified_key` in `certified_key_out`. That pointer must later
    /// be freed with `rustls_certified_key_free` to avoid memory leaks. Note that
    /// internally, this is an atomically reference-counted pointer, so even after
    /// the original caller has called `rustls_certified_key_free`, other objects
    /// may retain a pointer to the object. The memory will be freed when all
    /// references are gone.
    ///
    /// This function does not take ownership of any of its input pointers. It
    /// parses the pointed-to data and makes a copy of the result. You may
    /// free the cert_chain and private_key pointers after calling it.
    ///
    /// Typically, you will build a `rustls_certified_key`, use it to create a
    /// `rustls_server_config` (which increments the reference count), and then
    /// immediately call `rustls_certified_key_free`. That leaves the
    /// `rustls_server_config` in possession of the sole reference, so the
    /// `rustls_certified_key`'s memory will automatically be released when
    /// the `rustls_server_config` is freed.
    #[no_mangle]
    pub extern "C" fn rustls_certified_key_build_with_signing_key(
        cert_chain: *const u8,
        cert_chain_len: size_t,
        signing_key: *mut rustls_signing_key,
        certified_key_out: *mut *const rustls_certified_key,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let mut cert_chain = try_slice!(cert_chain, cert_chain_len);
            let signing_key = try_box_from_ptr!(signing_key);
            let certified_key_out = try_ref_from_ptr_ptr!(certified_key_out);

            let parsed_chain = match certs(&mut cert_chain).collect::<Result<Vec<_>, _>>() {
                Ok(v) => v,
                Err(_) => return rustls_result::CertificateParseError,
            };

            set_arc_mut_ptr(
                certified_key_out,
                CertifiedKey::new(parsed_chain, *signing_key),
            );
            rustls_result::Ok
        }
    }

    /// Return the i-th rustls_certificate in the rustls_certified_key.
    ///
    /// 0 gives the end-entity certificate. 1 and higher give certificates from the chain.
    ///
    /// Indexes higher than the last available certificate return NULL.
    ///
    /// The returned certificate is valid until the rustls_certified_key is freed.
    #[no_mangle]
    pub extern "C" fn rustls_certified_key_get_certificate<'a>(
        certified_key: *const rustls_certified_key,
        i: size_t,
    ) -> *const rustls_certificate<'a> {
        ffi_panic_boundary! {
            let certified_key = try_ref_from_ptr!(certified_key);
            match certified_key.cert.get(i) {
                Some(cert) => cert as *const CertificateDer as *const _,
                None => null(),
            }
        }
    }

    /// Create a copy of the rustls_certified_key with the given OCSP response data
    /// as DER encoded bytes.
    ///
    /// The OCSP response may be given as NULL to clear any possibly present OCSP
    /// data from the cloned key.
    ///
    /// The cloned key is independent from its original and needs to be freed
    /// by the application.
    #[no_mangle]
    pub extern "C" fn rustls_certified_key_clone_with_ocsp(
        certified_key: *const rustls_certified_key,
        ocsp_response: *const rustls_slice_bytes,
        cloned_key_out: *mut *const rustls_certified_key,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let cloned_key_out = unsafe {
                match cloned_key_out.as_mut() {
                    Some(c) => c,
                    None => return NullParameter,
                }
            };
            let certified_key = try_ref_from_ptr!(certified_key);
            let mut new_key = certified_key.clone();
            if !ocsp_response.is_null() {
                let ocsp_slice = unsafe { &*ocsp_response };
                new_key.ocsp = Some(Vec::from(try_slice!(ocsp_slice.data, ocsp_slice.len)));
            } else {
                new_key.ocsp = None;
            }
            *cloned_key_out = to_arc_const_ptr(new_key);
            rustls_result::Ok
        }
    }

    /// "Free" a certified_key previously returned from `rustls_certified_key_build`.
    ///
    /// Since certified_key is actually an atomically reference-counted pointer,
    /// extant certified_key may still hold an internal reference to the Rust object.
    ///
    /// However, C code must consider this pointer unusable after "free"ing it.
    ///
    /// Calling with NULL is fine. Must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_certified_key_free(key: *const rustls_certified_key) {
        ffi_panic_boundary! {
            free_arc(key);
        }
    }
}

box_castable! {
    /// A `rustls_root_cert_store` being constructed.
    ///
    /// A builder can be modified by adding trust anchor root certificates with
    /// `rustls_root_cert_store_builder_add_pem`. Once you're done adding root certificates,
    /// call `rustls_root_cert_store_builder_build` to turn it into a `rustls_root_cert_store`.
    /// This object is not safe for concurrent mutation.
    pub struct rustls_root_cert_store_builder(Option<RootCertStoreBuilder>);
}

pub(crate) struct RootCertStoreBuilder {
    roots: RootCertStore,
}

impl rustls_root_cert_store_builder {
    /// Create a `rustls_root_cert_store_builder`.
    ///
    /// Caller owns the memory and may free it with `rustls_root_cert_store_free`, regardless of
    /// whether `rustls_root_cert_store_builder_build` was called.
    ///
    /// If you wish to abandon the builder without calling `rustls_root_cert_store_builder_build`,
    /// it must be freed with `rustls_root_cert_store_builder_free`.
    #[no_mangle]
    pub extern "C" fn rustls_root_cert_store_builder_new() -> *mut rustls_root_cert_store_builder {
        ffi_panic_boundary! {
            let store = rustls::RootCertStore::empty();
            to_boxed_mut_ptr(Some(RootCertStoreBuilder { roots: store }))
        }
    }

    /// Add one or more certificates to the root cert store builder using PEM
    /// encoded data.
    ///
    /// When `strict` is true an error will return a `CertificateParseError`
    /// result. So will an attempt to parse data that has zero certificates.
    ///
    /// When `strict` is false, unparseable root certificates will be ignored.
    /// This may be useful on systems that have syntactically invalid root
    /// certificates.
    #[no_mangle]
    pub extern "C" fn rustls_root_cert_store_builder_add_pem(
        builder: *mut rustls_root_cert_store_builder,
        pem: *const u8,
        pem_len: size_t,
        strict: bool,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let certs_pem = try_slice!(pem, pem_len);
            let builder = try_mut_from_ptr!(builder);
            let builder = match builder {
                None => return AlreadyUsed,
                Some(b) => b,
            };

            let certs_der: Result<Vec<CertificateDer>, _> =
                rustls_pemfile::certs(&mut Cursor::new(certs_pem)).collect();
            let certs_der = match certs_der {
                Ok(vv) => vv,
                Err(_) => return rustls_result::CertificateParseError,
            };
            // We first copy into a temporary root store so we can uphold our
            // API guideline that there are no partial failures or partial
            // successes.
            let mut new_store = RootCertStore::empty();
            let (parsed, rejected) = new_store.add_parsable_certificates(certs_der);
            if strict && (rejected > 0 || parsed == 0) {
                return rustls_result::CertificateParseError;
            }

            builder.roots.roots.append(&mut new_store.roots);

            rustls_result::Ok
        }
    }

    /// Add one or more certificates to the root cert store builder using PEM
    /// encoded data read from the named file.
    ///
    /// When `strict` is true an error will return a `CertificateParseError`
    /// result. So will an attempt to parse data that has zero certificates.
    ///
    /// When `strict` is false, unparseable root certificates will be ignored.
    /// This may be useful on systems that have syntactically invalid root
    /// certificates.
    #[no_mangle]
    pub extern "C" fn rustls_root_cert_store_builder_load_roots_from_file(
        builder: *mut rustls_root_cert_store_builder,
        filename: *const c_char,
        strict: bool,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let builder = try_mut_from_ptr!(builder);
            let builder = match builder {
                None => return AlreadyUsed,
                Some(b) => b,
            };

            let filename = unsafe {
                if filename.is_null() {
                    return NullParameter;
                }
                CStr::from_ptr(filename)
            };

            let filename = filename.to_bytes();
            let filename = match std::str::from_utf8(filename) {
                Ok(s) => s,
                Err(_) => return rustls_result::Io,
            };
            let filename = OsStr::new(filename);
            let mut cafile = match File::open(filename) {
                Ok(f) => f,
                Err(_) => return rustls_result::Io,
            };

            let mut bufreader = BufReader::new(&mut cafile);
            let certs: Result<Vec<CertificateDer>, _> = certs(&mut bufreader).collect();
            let certs = match certs {
                Ok(certs) => certs,
                Err(_) => return rustls_result::Io,
            };

            // We first copy into a temporary root store so we can uphold our
            // API guideline that there are no partial failures or partial
            // successes.
            let mut roots = RootCertStore::empty();
            let (parsed, rejected) = roots.add_parsable_certificates(certs);
            if strict && (rejected > 0 || parsed == 0) {
                return rustls_result::CertificateParseError;
            }

            builder.roots.roots.append(&mut roots.roots);
            rustls_result::Ok
        }
    }

    /// Create a new `rustls_root_cert_store` from the builder.
    ///
    /// The builder is consumed and cannot be used again, but must still be freed.
    ///
    /// The root cert store can be used in several `rustls_web_pki_client_cert_verifier_builder_new`
    /// instances and must be freed by the application when no longer needed. See the documentation of
    /// `rustls_root_cert_store_free` for details about lifetime.
    #[no_mangle]
    pub extern "C" fn rustls_root_cert_store_builder_build(
        builder: *mut rustls_root_cert_store_builder,
        root_cert_store_out: *mut *const rustls_root_cert_store,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let builder = try_mut_from_ptr!(builder);
            let builder = try_take!(builder);
            let root_cert_store_out = try_ref_from_ptr_ptr!(root_cert_store_out);
            set_arc_mut_ptr(root_cert_store_out, builder.roots);

            rustls_result::Ok
        }
    }

    /// Free a `rustls_root_cert_store_builder` previously returned from
    /// `rustls_root_cert_store_builder_new`.
    ///
    /// Calling with NULL is fine. Must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_root_cert_store_builder_free(
        builder: *mut rustls_root_cert_store_builder,
    ) {
        ffi_panic_boundary! {
            free_box(builder);
        }
    }
}

arc_castable! {
    /// A root certificate store.
    /// <https://docs.rs/rustls/latest/rustls/struct.RootCertStore.html>
    pub struct rustls_root_cert_store(RootCertStore);
}

impl rustls_root_cert_store {
    /// Free a rustls_root_cert_store previously returned from rustls_root_cert_store_builder_build.
    ///
    /// Calling with NULL is fine. Must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_root_cert_store_free(store: *const rustls_root_cert_store) {
        ffi_panic_boundary! {
            free_arc(store);
        }
    }
}

box_castable! {
    /// A built client certificate verifier that can be provided to a `rustls_server_config_builder`
    /// with `rustls_server_config_builder_set_client_verifier`.
    //
    // Rustls' ConfigBuilder requires an `Arc<dyn ClientCertVerifier>` here, meaning we
    // must follow the pattern described in CONTRIBUTING.md[^0] for handling dynamically sized
    // types (DSTs) across the FFI boundary.
    // [^0]: <https://github.com/rustls/rustls-ffi/blob/main/CONTRIBUTING.md#dynamically-sized-types>
    pub struct rustls_client_cert_verifier(Arc<dyn ClientCertVerifier>);
}

impl rustls_client_cert_verifier {
    /// Free a `rustls_client_cert_verifier` previously returned from
    /// `rustls_client_cert_verifier_builder_build`. Calling with NULL is fine. Must not be
    /// called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_client_cert_verifier_free(verifier: *mut rustls_client_cert_verifier) {
        ffi_panic_boundary! {
            free_box(verifier);
        }
    }
}

pub(crate) struct ClientCertVerifierBuilder {
    provider: Option<Arc<CryptoProvider>>,
    roots: Arc<RootCertStore>,
    root_hint_subjects: Vec<DistinguishedName>,
    crls: Vec<CertificateRevocationListDer<'static>>,
    revocation_depth: RevocationCheckDepth,
    revocation_policy: UnknownStatusPolicy,
    allow_unauthenticated: bool,
}

box_castable! {
    /// A client certificate verifier being constructed.
    ///
    /// A builder can be modified by, e.g. `rustls_web_pki_client_cert_verifier_builder_add_crl`.
    ///
    /// Once you're done configuring settings, call `rustls_web_pki_client_cert_verifier_builder_build`
    /// to turn it into a `rustls_client_cert_verifier`.
    ///
    /// This object is not safe for concurrent mutation.
    ///
    /// See <https://docs.rs/rustls/latest/rustls/server/struct.ClientCertVerifierBuilder.html>
    /// for more information.
    pub struct rustls_web_pki_client_cert_verifier_builder(Option<ClientCertVerifierBuilder>);
}

impl rustls_web_pki_client_cert_verifier_builder {
    /// Create a `rustls_web_pki_client_cert_verifier_builder` using the process-wide default
    /// cryptography provider.
    ///
    /// Caller owns the memory and may eventually call `rustls_web_pki_client_cert_verifier_builder_free`
    /// to free it, whether or not `rustls_web_pki_client_cert_verifier_builder_build` was called.
    ///
    /// Without further modification the builder will produce a client certificate verifier that
    /// will require a client present a client certificate that chains to one of the trust anchors
    /// in the provided `rustls_root_cert_store`. The root cert store must not be empty.
    ///
    /// Revocation checking will not be performed unless
    /// `rustls_web_pki_client_cert_verifier_builder_add_crl` is used to add certificate revocation
    /// lists (CRLs) to the builder. If CRLs are added, revocation checking will be performed
    /// for the entire certificate chain unless
    /// `rustls_web_pki_client_cert_verifier_only_check_end_entity_revocation` is used. Unknown
    /// revocation status for certificates considered for revocation status will be treated as
    /// an error unless `rustls_web_pki_client_cert_verifier_allow_unknown_revocation_status` is
    /// used.
    ///
    /// Unauthenticated clients will not be permitted unless
    /// `rustls_web_pki_client_cert_verifier_builder_allow_unauthenticated` is used.
    ///
    /// This copies the contents of the `rustls_root_cert_store`. It does not take
    /// ownership of the pointed-to data.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_client_cert_verifier_builder_new(
        store: *const rustls_root_cert_store,
    ) -> *mut rustls_web_pki_client_cert_verifier_builder {
        ffi_panic_boundary! {
            let store = try_clone_arc!(store);
            to_boxed_mut_ptr(Some(ClientCertVerifierBuilder {
                provider: crypto_provider::get_default_or_install_from_crate_features(),
                root_hint_subjects: store.subjects(),
                roots: store,
                crls: Vec::default(),
                revocation_depth: RevocationCheckDepth::Chain,
                revocation_policy: UnknownStatusPolicy::Deny,
                allow_unauthenticated: false,
            }))
        }
    }

    /// Create a `rustls_web_pki_client_cert_verifier_builder` using the specified
    /// cryptography provider.
    ///
    /// Caller owns the memory and may eventually call
    /// `rustls_web_pki_client_cert_verifier_builder_free` to free it, whether or
    /// not `rustls_web_pki_client_cert_verifier_builder_build` was called.
    ///
    /// Without further modification the builder will produce a client certificate verifier that
    /// will require a client present a client certificate that chains to one of the trust anchors
    /// in the provided `rustls_root_cert_store`. The root cert store must not be empty.
    ///
    /// Revocation checking will not be performed unless
    /// `rustls_web_pki_client_cert_verifier_builder_add_crl` is used to add certificate revocation
    /// lists (CRLs) to the builder. If CRLs are added, revocation checking will be performed
    /// for the entire certificate chain unless
    /// `rustls_web_pki_client_cert_verifier_only_check_end_entity_revocation` is used. Unknown
    /// revocation status for certificates considered for revocation status will be treated as
    /// an error unless `rustls_web_pki_client_cert_verifier_allow_unknown_revocation_status` is
    /// used.
    ///
    /// Unauthenticated clients will not be permitted unless
    /// `rustls_web_pki_client_cert_verifier_builder_allow_unauthenticated` is used.
    ///
    /// This copies the contents of the `rustls_root_cert_store`. It does not take
    /// ownership of the pointed-to data.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_client_cert_verifier_builder_new_with_provider(
        provider: *const rustls_crypto_provider,
        store: *const rustls_root_cert_store,
    ) -> *mut rustls_web_pki_client_cert_verifier_builder {
        ffi_panic_boundary! {
            let provider = try_clone_arc!(provider);
            let store = try_clone_arc!(store);
            to_boxed_mut_ptr(Some(ClientCertVerifierBuilder {
                provider: Some(provider),
                root_hint_subjects: store.subjects(),
                roots: store,
                crls: Vec::default(),
                revocation_depth: RevocationCheckDepth::Chain,
                revocation_policy: UnknownStatusPolicy::Deny,
                allow_unauthenticated: false,
            }))
        }
    }

    /// Add one or more certificate revocation lists (CRLs) to the client certificate verifier
    /// builder by reading the CRL content from the provided buffer of PEM encoded content.
    ///
    /// By default revocation checking will be performed on the entire certificate chain. To only
    /// check the revocation status of the end entity certificate, use
    /// `rustls_web_pki_client_cert_verifier_only_check_end_entity_revocation`.
    ///
    /// This function returns an error if the provided buffer is not valid PEM encoded content.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_client_cert_verifier_builder_add_crl(
        builder: *mut rustls_web_pki_client_cert_verifier_builder,
        crl_pem: *const u8,
        crl_pem_len: size_t,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let client_verifier_builder = try_mut_from_ptr!(builder);
            let client_verifier_builder = match client_verifier_builder {
                None => return AlreadyUsed,
                Some(v) => v,
            };

            let crl_pem = try_slice!(crl_pem, crl_pem_len);
            let crls_der: Result<Vec<CertificateRevocationListDer>, _> =
                crls(&mut Cursor::new(crl_pem)).collect();
            let crls_der = match crls_der {
                Ok(vv) => vv,
                Err(_) => return rustls_result::CertificateRevocationListParseError,
            };
            if crls_der.is_empty() {
                return rustls_result::CertificateRevocationListParseError;
            }

            client_verifier_builder.crls.extend(crls_der);
            rustls_result::Ok
        }
    }

    /// When CRLs are provided with `rustls_web_pki_client_cert_verifier_builder_add_crl`, only
    /// check the revocation status of end entity certificates, ignoring any intermediate certificates
    /// in the chain.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_client_cert_verifier_only_check_end_entity_revocation(
        builder: *mut rustls_web_pki_client_cert_verifier_builder,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let client_verifier_builder = try_mut_from_ptr!(builder);
            let client_verifier_builder = match client_verifier_builder {
                None => return AlreadyUsed,
                Some(v) => v,
            };

            client_verifier_builder.revocation_depth = RevocationCheckDepth::EndEntity;
            rustls_result::Ok
        }
    }

    /// When CRLs are provided with `rustls_web_pki_client_cert_verifier_builder_add_crl`, and it
    /// isn't possible to determine the revocation status of a considered certificate, do not treat
    /// it as an error condition.
    ///
    /// Overrides the default behavior where unknown revocation status is considered an error.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_client_cert_verifier_allow_unknown_revocation_status(
        builder: *mut rustls_web_pki_client_cert_verifier_builder,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let client_verifier_builder = try_mut_from_ptr!(builder);
            let client_verifier_builder = match client_verifier_builder {
                None => return AlreadyUsed,
                Some(v) => v,
            };

            client_verifier_builder.revocation_policy = UnknownStatusPolicy::Allow;
            rustls_result::Ok
        }
    }

    /// Allow unauthenticated anonymous clients in addition to those that present a client
    /// certificate that chains to one of the verifier's configured trust anchors.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_client_cert_verifier_builder_allow_unauthenticated(
        builder: *mut rustls_web_pki_client_cert_verifier_builder,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let client_verifier_builder = try_mut_from_ptr!(builder);
            let client_verifier_builder = match client_verifier_builder {
                None => return AlreadyUsed,
                Some(v) => v,
            };

            client_verifier_builder.allow_unauthenticated = true;
            rustls_result::Ok
        }
    }

    /// Clear the list of trust anchor hint subjects.
    ///
    /// By default, the client cert verifier will use the subjects provided by the root cert
    /// store configured for client authentication. Calling this function will remove these
    /// hint subjects, indicating the client should make a free choice of which certificate
    /// to send.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_client_cert_verifier_clear_root_hint_subjects(
        builder: *mut rustls_web_pki_client_cert_verifier_builder,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let client_verifier_builder = try_mut_from_ptr!(builder);
            let client_verifier_builder = match client_verifier_builder {
                None => return AlreadyUsed,
                Some(v) => v,
            };

            client_verifier_builder.root_hint_subjects.clear();
            rustls_result::Ok
        }
    }

    /// Add additional distinguished names to the list of trust anchor hint subjects.
    ///
    /// By default, the client cert verifier will use the subjects provided by the root cert
    /// store configured for client authentication. Calling this function will add to these
    /// existing hint subjects. Calling this function with an empty `store` will have no
    /// effect, use `rustls_web_pki_client_cert_verifier_clear_root_hint_subjects` to clear
    /// the subject hints.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_client_cert_verifier_add_root_hint_subjects(
        builder: *mut rustls_web_pki_client_cert_verifier_builder,
        store: *const rustls_root_cert_store,
    ) -> rustls_result {
        let client_verifier_builder = try_mut_from_ptr!(builder);
        let client_verifier_builder = match client_verifier_builder {
            None => return AlreadyUsed,
            Some(v) => v,
        };

        let store = try_clone_arc!(store);
        client_verifier_builder.root_hint_subjects = store.subjects();
        rustls_result::Ok
    }

    /// Create a new client certificate verifier from the builder.
    ///
    /// The builder is consumed and cannot be used again, but must still be freed.
    ///
    /// The verifier can be used in several `rustls_server_config` instances and must be
    /// freed by the application when no longer needed. See the documentation of
    /// `rustls_web_pki_client_cert_verifier_builder_free` for details about lifetime.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_client_cert_verifier_builder_build(
        builder: *mut rustls_web_pki_client_cert_verifier_builder,
        verifier_out: *mut *mut rustls_client_cert_verifier,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let client_verifier_builder = try_mut_from_ptr!(builder);
            let client_verifier_builder = try_take!(client_verifier_builder);
            let verifier_out = try_mut_from_ptr_ptr!(verifier_out);

            let builder = match client_verifier_builder.provider {
                Some(provider) => WebPkiClientVerifier::builder_with_provider(
                    client_verifier_builder.roots,
                    provider,
                ),
                None => WebPkiClientVerifier::builder(client_verifier_builder.roots),
            };

            let mut builder = builder.with_crls(client_verifier_builder.crls);
            match client_verifier_builder.revocation_depth {
                RevocationCheckDepth::EndEntity => {
                    builder = builder.only_check_end_entity_revocation()
                }
                RevocationCheckDepth::Chain => {}
            }
            match client_verifier_builder.revocation_policy {
                UnknownStatusPolicy::Allow => builder = builder.allow_unknown_revocation_status(),
                UnknownStatusPolicy::Deny => {}
            }
            if client_verifier_builder.allow_unauthenticated {
                builder = builder.allow_unauthenticated();
            }
            if client_verifier_builder.root_hint_subjects.is_empty() {
                builder = builder.clear_root_hint_subjects();
            } else {
                builder =
                    builder.add_root_hint_subjects(client_verifier_builder.root_hint_subjects);
            }

            let verifier = match builder.build() {
                Ok(v) => v,
                Err(e) => return error::map_verifier_builder_error(e),
            };

            set_boxed_mut_ptr(verifier_out, verifier);
            rustls_result::Ok
        }
    }

    /// Free a `rustls_client_cert_verifier_builder` previously returned from
    /// `rustls_client_cert_verifier_builder_new`.
    ///
    /// Calling with NULL is fine. Must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_client_cert_verifier_builder_free(
        builder: *mut rustls_web_pki_client_cert_verifier_builder,
    ) {
        ffi_panic_boundary! {
            free_box(builder);
        }
    }
}

box_castable! {
    /// A server certificate verifier being constructed.
    ///
    /// A builder can be modified by, e.g. `rustls_web_pki_server_cert_verifier_builder_add_crl`.
    ///
    /// Once you're done configuring settings, call `rustls_web_pki_server_cert_verifier_builder_build`
    /// to turn it into a `rustls_server_cert_verifier`. This object is not safe for concurrent mutation.
    ///
    /// See <https://docs.rs/rustls/latest/rustls/client/struct.ServerCertVerifierBuilder.html>
    /// for more information.
    pub struct rustls_web_pki_server_cert_verifier_builder(Option<ServerCertVerifierBuilder>);
}

pub(crate) struct ServerCertVerifierBuilder {
    provider: Option<Arc<CryptoProvider>>,
    roots: Arc<RootCertStore>,
    crls: Vec<CertificateRevocationListDer<'static>>,
    revocation_depth: RevocationCheckDepth,
    revocation_policy: UnknownStatusPolicy,
}

impl ServerCertVerifierBuilder {
    /// Create a `rustls_web_pki_server_cert_verifier_builder` using the process-wide default
    /// crypto provider. Caller owns the memory and may free it with
    ///
    /// Caller owns the memory and may free it with `rustls_web_pki_server_cert_verifier_builder_free`,
    /// regardless of whether `rustls_web_pki_server_cert_verifier_builder_build` was called.
    ///
    /// Without further modification the builder will produce a server certificate verifier that
    /// will require a server present a certificate that chains to one of the trust anchors
    /// in the provided `rustls_root_cert_store`. The root cert store must not be empty.
    ///
    /// Revocation checking will not be performed unless
    /// `rustls_web_pki_server_cert_verifier_builder_add_crl` is used to add certificate revocation
    /// lists (CRLs) to the builder.  If CRLs are added, revocation checking will be performed
    /// for the entire certificate chain unless
    /// `rustls_web_pki_server_cert_verifier_only_check_end_entity_revocation` is used. Unknown
    /// revocation status for certificates considered for revocation status will be treated as
    /// an error unless `rustls_web_pki_server_cert_verifier_allow_unknown_revocation_status` is
    /// used.
    ///
    /// This copies the contents of the `rustls_root_cert_store`. It does not take
    /// ownership of the pointed-to data.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_server_cert_verifier_builder_new(
        store: *const rustls_root_cert_store,
    ) -> *mut rustls_web_pki_server_cert_verifier_builder {
        ffi_panic_boundary! {
            let store = try_clone_arc!(store);
            to_boxed_mut_ptr(Some(ServerCertVerifierBuilder {
                provider: crypto_provider::get_default_or_install_from_crate_features(),
                roots: store,
                crls: Vec::default(),
                revocation_depth: RevocationCheckDepth::Chain,
                revocation_policy: UnknownStatusPolicy::Deny,
            }))
        }
    }

    /// Create a `rustls_web_pki_server_cert_verifier_builder` using the specified
    /// crypto provider. Caller owns the memory and may free it with
    /// `rustls_web_pki_server_cert_verifier_builder_free`, regardless of whether
    /// `rustls_web_pki_server_cert_verifier_builder_build` was called.
    ///
    /// Without further modification the builder will produce a server certificate verifier that
    /// will require a server present a certificate that chains to one of the trust anchors
    /// in the provided `rustls_root_cert_store`. The root cert store must not be empty.
    ///
    /// Revocation checking will not be performed unless
    /// `rustls_web_pki_server_cert_verifier_builder_add_crl` is used to add certificate revocation
    /// lists (CRLs) to the builder.  If CRLs are added, revocation checking will be performed
    /// for the entire certificate chain unless
    /// `rustls_web_pki_server_cert_verifier_only_check_end_entity_revocation` is used. Unknown
    /// revocation status for certificates considered for revocation status will be treated as
    /// an error unless `rustls_web_pki_server_cert_verifier_allow_unknown_revocation_status` is
    /// used.
    ///
    /// This copies the contents of the `rustls_root_cert_store`. It does not take
    /// ownership of the pointed-to data.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_server_cert_verifier_builder_new_with_provider(
        provider: *const rustls_crypto_provider,
        store: *const rustls_root_cert_store,
    ) -> *mut rustls_web_pki_server_cert_verifier_builder {
        ffi_panic_boundary! {
            let provider = try_clone_arc!(provider);
            let store = try_clone_arc!(store);
            to_boxed_mut_ptr(Some(ServerCertVerifierBuilder {
                provider: Some(provider),
                roots: store,
                crls: Vec::default(),
                revocation_depth: RevocationCheckDepth::Chain,
                revocation_policy: UnknownStatusPolicy::Deny,
            }))
        }
    }

    /// Add one or more certificate revocation lists (CRLs) to the server certificate verifier
    /// builder by reading the CRL content from the provided buffer of PEM encoded content.
    ///
    /// By default revocation checking will be performed on the entire certificate chain. To only
    /// check the revocation status of the end entity certificate, use
    /// `rustls_web_pki_server_cert_verifier_only_check_end_entity_revocation`.
    ///
    /// This function returns an error if the provided buffer is not valid PEM encoded content.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_server_cert_verifier_builder_add_crl(
        builder: *mut rustls_web_pki_server_cert_verifier_builder,
        crl_pem: *const u8,
        crl_pem_len: size_t,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let server_verifier_builder = try_mut_from_ptr!(builder);
            let server_verifier_builder = match server_verifier_builder {
                None => return AlreadyUsed,
                Some(v) => v,
            };

            let crl_pem = try_slice!(crl_pem, crl_pem_len);
            let crls_der: Result<Vec<CertificateRevocationListDer>, _> =
                crls(&mut Cursor::new(crl_pem)).collect();
            let crls_der = match crls_der {
                Ok(vv) => vv,
                Err(_) => return rustls_result::CertificateRevocationListParseError,
            };
            if crls_der.is_empty() {
                return rustls_result::CertificateRevocationListParseError;
            }

            server_verifier_builder.crls.extend(crls_der);

            rustls_result::Ok
        }
    }

    /// When CRLs are provided with `rustls_web_pki_server_cert_verifier_builder_add_crl`, only
    /// check the revocation status of end entity certificates, ignoring any intermediate certificates
    /// in the chain.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_server_cert_verifier_only_check_end_entity_revocation(
        builder: *mut rustls_web_pki_server_cert_verifier_builder,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let server_verifier_builder = try_mut_from_ptr!(builder);
            let server_verifier_builder = match server_verifier_builder {
                None => return AlreadyUsed,
                Some(v) => v,
            };

            server_verifier_builder.revocation_depth = RevocationCheckDepth::EndEntity;
            rustls_result::Ok
        }
    }

    /// When CRLs are provided with `rustls_web_pki_server_cert_verifier_builder_add_crl`, and it
    /// isn't possible to determine the revocation status of a considered certificate, do not treat
    /// it as an error condition.
    ///
    /// Overrides the default behavior where unknown revocation status is considered an error.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_server_cert_verifier_allow_unknown_revocation_status(
        builder: *mut rustls_web_pki_server_cert_verifier_builder,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let server_verifier_builder = try_mut_from_ptr!(builder);
            let server_verifier_builder = match server_verifier_builder {
                None => return AlreadyUsed,
                Some(v) => v,
            };

            server_verifier_builder.revocation_policy = UnknownStatusPolicy::Allow;
            rustls_result::Ok
        }
    }

    /// Create a new server certificate verifier from the builder.
    ///
    /// The builder is consumed and cannot be used again, but must still be freed.
    ///
    /// The verifier can be used in several `rustls_client_config` instances and must be
    /// freed by the application when no longer needed. See the documentation of
    /// `rustls_web_pki_server_cert_verifier_builder_free` for details about lifetime.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_server_cert_verifier_builder_build(
        builder: *mut rustls_web_pki_server_cert_verifier_builder,
        verifier_out: *mut *mut rustls_server_cert_verifier,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let server_verifier_builder = try_mut_from_ptr!(builder);
            let server_verifier_builder = try_take!(server_verifier_builder);
            let verifier_out = try_mut_from_ptr_ptr!(verifier_out);

            let builder = match server_verifier_builder.provider {
                Some(provider) => WebPkiServerVerifier::builder_with_provider(
                    server_verifier_builder.roots,
                    provider,
                ),
                None => WebPkiServerVerifier::builder(server_verifier_builder.roots),
            };

            let mut builder = builder.with_crls(server_verifier_builder.crls);
            match server_verifier_builder.revocation_depth {
                RevocationCheckDepth::EndEntity => {
                    builder = builder.only_check_end_entity_revocation()
                }
                RevocationCheckDepth::Chain => {}
            }
            match server_verifier_builder.revocation_policy {
                UnknownStatusPolicy::Allow => builder = builder.allow_unknown_revocation_status(),
                UnknownStatusPolicy::Deny => {}
            }

            let verifier = match builder.build() {
                Ok(v) => v,
                Err(e) => return error::map_verifier_builder_error(e),
            };

            set_boxed_mut_ptr(verifier_out, verifier);

            rustls_result::Ok
        }
    }

    /// Free a `rustls_server_cert_verifier_builder` previously returned from
    /// `rustls_server_cert_verifier_builder_new`.
    ///
    /// Calling with NULL is fine. Must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_web_pki_server_cert_verifier_builder_free(
        builder: *mut rustls_web_pki_server_cert_verifier_builder,
    ) {
        ffi_panic_boundary! {
            free_box(builder);
        }
    }
}

box_castable! {
    /// A built server certificate verifier that can be provided to a `rustls_client_config_builder`
    /// with `rustls_client_config_builder_set_server_verifier`.
    //
    // Rustls' ConfigBuilder requires an `Arc<dyn ServerCertVerifier>` here, meaning we
    // must follow the pattern described in CONTRIBUTING.md[^0] for handling dynamically sized
    // types (DSTs) across the FFI boundary.
    // [^0]: <https://github.com/rustls/rustls-ffi/blob/main/CONTRIBUTING.md#dynamically-sized-types>
    pub struct rustls_server_cert_verifier(Arc<dyn ServerCertVerifier>);
}

impl rustls_server_cert_verifier {
    /// Create a verifier that uses the default behavior for the current platform.
    ///
    /// This uses [`rustls-platform-verifier`][].
    ///
    /// The verifier can be used in several `rustls_client_config` instances and must be freed by
    /// the application using `rustls_server_cert_verifier_free` when no longer needed.
    ///
    /// [`rustls-platform-verifier`]: https://github.com/rustls/rustls-platform-verifier
    #[no_mangle]
    pub extern "C" fn rustls_platform_server_cert_verifier(
        verifier_out: *mut *mut rustls_server_cert_verifier,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let verifier_out = try_mut_from_ptr_ptr!(verifier_out);
            let provider = match crypto_provider::get_default_or_install_from_crate_features() {
                Some(provider) => provider,
                None => return rustls_result::NoDefaultCryptoProvider,
            };
            let verifier: Arc<dyn ServerCertVerifier> =
                Arc::new(rustls_platform_verifier::Verifier::new().with_provider(provider));
            set_boxed_mut_ptr(verifier_out, verifier);
            rustls_result::Ok
        }
    }

    /// Create a verifier that uses the default behavior for the current platform.
    ///
    /// This uses [`rustls-platform-verifier`][] and the specified crypto provider.
    ///
    /// The verifier can be used in several `rustls_client_config` instances and must be freed by
    /// the application using `rustls_server_cert_verifier_free` when no longer needed.
    ///
    /// [`rustls-platform-verifier`]: https://github.com/rustls/rustls-platform-verifier
    #[no_mangle]
    pub extern "C" fn rustls_platform_server_cert_verifier_with_provider(
        provider: *const rustls_crypto_provider,
    ) -> *mut rustls_server_cert_verifier {
        ffi_panic_boundary! {
            let provider = try_clone_arc!(provider);
            let verifier: Arc<dyn ServerCertVerifier> =
                Arc::new(rustls_platform_verifier::Verifier::new().with_provider(provider));
            to_boxed_mut_ptr(verifier)
        }
    }

    /// Free a `rustls_server_cert_verifier` previously returned from
    /// `rustls_server_cert_verifier_builder_build` or `rustls_platform_server_cert_verifier`.
    ///
    /// Calling with NULL is fine. Must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_server_cert_verifier_free(verifier: *mut rustls_server_cert_verifier) {
        ffi_panic_boundary! {
            free_box(verifier);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::crypto_provider::{
        rustls_default_crypto_provider_ciphersuites_get,
        rustls_default_crypto_provider_ciphersuites_len,
    };

    #[test]
    fn default_cipher_suites() {
        let num_suites = rustls_default_crypto_provider_ciphersuites_len();
        assert!(num_suites > 2);
        for i in 0..num_suites {
            let suite = rustls_default_crypto_provider_ciphersuites_get(i);
            let name = rustls_supported_ciphersuite_get_name(suite);
            let name = unsafe { name.to_str() };
            let proto = rustls_supported_ciphersuite_protocol_version(suite);
            println!("{}: {} {:?}", i, name, proto);
        }
    }
}
