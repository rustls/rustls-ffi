use libc::size_t;
use std::convert::TryFrom;
use std::io::Cursor;
use std::ptr::null;
use std::slice;
use std::sync::Arc;

use rustls::server::{
    AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient, UnparsedCertRevocationList,
};
use rustls::sign::CertifiedKey;
use rustls::{
    Certificate, PrivateKey, RootCertStore, SupportedCipherSuite, ALL_CIPHER_SUITES,
    DEFAULT_CIPHER_SUITES,
};
use rustls_pemfile::{certs, crls, pkcs8_private_keys, rsa_private_keys};

use crate::error::{map_error, rustls_result};
use crate::rslice::{rustls_slice_bytes, rustls_str};
use crate::{
    ffi_panic_boundary, try_box_from_ptr, try_mut_from_ptr, try_ref_from_ptr, try_slice,
    ArcCastPtr, BoxCastPtr, CastConstPtr, CastPtr,
};
use rustls_result::{AlreadyUsed, NullParameter};
use std::ops::Deref;

/// An X.509 certificate, as used in rustls.
/// Corresponds to `Certificate` in the Rust API.
/// <https://docs.rs/rustls/latest/rustls/struct.Certificate.html>
pub struct rustls_certificate {
    // We use the opaque struct pattern to tell C about our types without
    // telling them what's inside.
    // https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs
    _private: [u8; 0],
}

impl CastPtr for rustls_certificate {
    type RustType = Certificate;
}

impl rustls_certificate {
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
                return NullParameter
            }
            let der = cert.as_ref();
            unsafe {
                *out_der_data = der.as_ptr();
                *out_der_len = der.len();
            }
            rustls_result::Ok
        }
    }
}

/// A cipher suite supported by rustls.
pub struct rustls_supported_ciphersuite {
    _private: [u8; 0],
}

impl CastPtr for rustls_supported_ciphersuite {
    type RustType = SupportedCipherSuite;
}

impl rustls_supported_ciphersuite {
    /// Return a 16-bit unsigned integer corresponding to this cipher suite's assignment from
    /// <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4>.
    /// The bytes from the assignment are interpreted in network order.
    #[no_mangle]
    pub extern "C" fn rustls_supported_ciphersuite_get_suite(
        supported_ciphersuite: *const rustls_supported_ciphersuite,
    ) -> u16 {
        let supported_ciphersuite = try_ref_from_ptr!(supported_ciphersuite);
        match supported_ciphersuite {
            rustls::SupportedCipherSuite::Tls12(sc) => &sc.common,
            rustls::SupportedCipherSuite::Tls13(sc) => &sc.common,
        }
        .suite
        .get_u16()
    }
}

/// Returns the name of the ciphersuite as a `rustls_str`. If the provided
/// ciphersuite is invalid, the rustls_str will contain the empty string. The
/// lifetime of the `rustls_str` is the lifetime of the program, it does not
/// need to be freed.
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

/// Return the length of rustls' list of supported cipher suites.
#[no_mangle]
pub extern "C" fn rustls_all_ciphersuites_len() -> usize {
    ALL_CIPHER_SUITES.len()
}

/// Get a pointer to a member of rustls' list of supported cipher suites. This will return non-NULL
/// for i < rustls_all_ciphersuites_len().
/// The returned pointer is valid for the lifetime of the program and may be used directly when
/// building a ClientConfig or ServerConfig.
#[no_mangle]
pub extern "C" fn rustls_all_ciphersuites_get_entry(
    i: size_t,
) -> *const rustls_supported_ciphersuite {
    match ALL_CIPHER_SUITES.get(i) {
        Some(cs) => cs as *const SupportedCipherSuite as *const _,
        None => null(),
    }
}

/// Return the length of rustls' list of default cipher suites.
#[no_mangle]
pub extern "C" fn rustls_default_ciphersuites_len() -> usize {
    DEFAULT_CIPHER_SUITES.len()
}

/// Get a pointer to a member of rustls' list of supported cipher suites. This will return non-NULL
/// for i < rustls_default_ciphersuites_len().
/// The returned pointer is valid for the lifetime of the program and may be used directly when
/// building a ClientConfig or ServerConfig.
#[no_mangle]
pub extern "C" fn rustls_default_ciphersuites_get_entry(
    i: size_t,
) -> *const rustls_supported_ciphersuite {
    match DEFAULT_CIPHER_SUITES.get(i) {
        Some(cs) => cs as *const SupportedCipherSuite as *const _,
        None => null(),
    }
}

/// Rustls' list of supported cipher suites. This is an array of pointers, and
/// its length is given by `RUSTLS_ALL_CIPHER_SUITES_LEN`. The pointers will
/// always be valid. The contents and order of this array may change between
/// releases.
#[no_mangle]
pub static mut RUSTLS_ALL_CIPHER_SUITES: [*const rustls_supported_ciphersuite; 9] = [
    &rustls::cipher_suite::TLS13_AES_256_GCM_SHA384 as *const SupportedCipherSuite as *const _,
    &rustls::cipher_suite::TLS13_AES_128_GCM_SHA256 as *const SupportedCipherSuite as *const _,
    &rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256 as *const SupportedCipherSuite
        as *const _,
    &rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 as *const SupportedCipherSuite
        as *const _,
    &rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 as *const SupportedCipherSuite
        as *const _,
    &rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        as *const SupportedCipherSuite as *const _,
    &rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 as *const SupportedCipherSuite
        as *const _,
    &rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 as *const SupportedCipherSuite
        as *const _,
    &rustls::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        as *const SupportedCipherSuite as *const _,
];

/// The length of the array `RUSTLS_ALL_CIPHER_SUITES`.
#[no_mangle]
pub static RUSTLS_ALL_CIPHER_SUITES_LEN: usize = unsafe { RUSTLS_ALL_CIPHER_SUITES.len() };

/// Rustls' list of default cipher suites. This is an array of pointers, and
/// its length is given by `RUSTLS_DEFAULT_CIPHER_SUITES_LEN`. The pointers
/// will always be valid. The contents and order of this array may change
/// between releases.
#[no_mangle]
pub static mut RUSTLS_DEFAULT_CIPHER_SUITES: [*const rustls_supported_ciphersuite; 9] = [
    &rustls::cipher_suite::TLS13_AES_256_GCM_SHA384 as *const SupportedCipherSuite as *const _,
    &rustls::cipher_suite::TLS13_AES_128_GCM_SHA256 as *const SupportedCipherSuite as *const _,
    &rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256 as *const SupportedCipherSuite
        as *const _,
    &rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 as *const SupportedCipherSuite
        as *const _,
    &rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 as *const SupportedCipherSuite
        as *const _,
    &rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        as *const SupportedCipherSuite as *const _,
    &rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 as *const SupportedCipherSuite
        as *const _,
    &rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 as *const SupportedCipherSuite
        as *const _,
    &rustls::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        as *const SupportedCipherSuite as *const _,
];

/// The length of the array `RUSTLS_DEFAULT_CIPHER_SUITES`.
#[no_mangle]
pub static RUSTLS_DEFAULT_CIPHER_SUITES_LEN: usize = unsafe { RUSTLS_DEFAULT_CIPHER_SUITES.len() };

#[cfg(test)]
mod tests {
    use super::*;
    use std::slice;
    use std::str;

    #[test]
    fn all_cipher_suites_arrays() {
        assert_eq!(RUSTLS_ALL_CIPHER_SUITES_LEN, ALL_CIPHER_SUITES.len());
        for (original, ffi) in ALL_CIPHER_SUITES
            .iter()
            .zip(unsafe { RUSTLS_ALL_CIPHER_SUITES }.iter().copied())
        {
            let ffi_cipher_suite = try_ref_from_ptr!(ffi);
            assert_eq!(original, ffi_cipher_suite);
        }
    }

    #[test]
    fn default_cipher_suites_arrays() {
        assert_eq!(
            RUSTLS_DEFAULT_CIPHER_SUITES_LEN,
            DEFAULT_CIPHER_SUITES.len()
        );
        for (original, ffi) in DEFAULT_CIPHER_SUITES
            .iter()
            .zip(unsafe { RUSTLS_DEFAULT_CIPHER_SUITES }.iter().copied())
        {
            let ffi_cipher_suite = try_ref_from_ptr!(ffi);
            assert_eq!(original, ffi_cipher_suite);
        }
    }

    #[test]
    fn ciphersuite_get_name() {
        let suite = rustls_all_ciphersuites_get_entry(0);
        let s = rustls_supported_ciphersuite_get_name(suite);
        let want = "TLS13_AES_256_GCM_SHA384";
        unsafe {
            let got = str::from_utf8(slice::from_raw_parts(s.data as *const u8, s.len)).unwrap();
            assert_eq!(want, got)
        }
    }

    #[test]
    fn test_all_ciphersuites_len() {
        let len = rustls_all_ciphersuites_len();
        assert!(len > 2);
    }
}

/// The complete chain of certificates to send during a TLS handshake,
/// plus a private key that matches the end-entity (leaf) certificate.
/// Corresponds to `CertifiedKey` in the Rust API.
/// <https://docs.rs/rustls/latest/rustls/sign/struct.CertifiedKey.html>
pub struct rustls_certified_key {
    // We use the opaque struct pattern to tell C about our types without
    // telling them what's inside.
    // https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs
    _private: [u8; 0],
}

impl CastPtr for rustls_certified_key {
    type RustType = CertifiedKey;
}

impl ArcCastPtr for rustls_certified_key {}

impl rustls_certified_key {
    /// Build a `rustls_certified_key` from a certificate chain and a private key.
    /// `cert_chain` must point to a buffer of `cert_chain_len` bytes, containing
    /// a series of PEM-encoded certificates, with the end-entity (leaf)
    /// certificate first.
    ///
    /// `private_key` must point to a buffer of `private_key_len` bytes, containing
    /// a PEM-encoded private key in either PKCS#1 or PKCS#8 format.
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
            let certified_key_out: &mut *const rustls_certified_key = unsafe {
                match certified_key_out.as_mut() {
                    Some(c) => c,
                    None => return NullParameter,
                }
            };
            let certified_key = match rustls_certified_key::certified_key_build(
                cert_chain, cert_chain_len, private_key, private_key_len) {
                Ok(key) => Box::new(key),
                Err(rr) => return rr,
            };
            let certified_key = Arc::into_raw(Arc::new(*certified_key)) as *const _;
            *certified_key_out = certified_key;
            rustls_result::Ok
        }
    }

    /// Return the i-th rustls_certificate in the rustls_certified_key. 0 gives the
    /// end-entity certificate. 1 and higher give certificates from the chain.
    /// Indexes higher than the last available certificate return NULL.
    ///
    /// The returned certificate is valid until the rustls_certified_key is freed.
    #[no_mangle]
    pub extern "C" fn rustls_certified_key_get_certificate(
        certified_key: *const rustls_certified_key,
        i: size_t,
    ) -> *const rustls_certificate {
        ffi_panic_boundary! {
            let certified_key: &CertifiedKey = try_ref_from_ptr!(certified_key);
            match certified_key.cert.get(i) {
                Some(cert) => cert as *const Certificate as *const _,
                None => null()
            }
        }
    }

    /// Create a copy of the rustls_certified_key with the given OCSP response data
    /// as DER encoded bytes. The OCSP response may be given as NULL to clear any
    /// possibly present OCSP data from the cloned key.
    /// The cloned key is independent from its original and needs to be freed
    /// by the application.
    #[no_mangle]
    pub extern "C" fn rustls_certified_key_clone_with_ocsp(
        certified_key: *const rustls_certified_key,
        ocsp_response: *const rustls_slice_bytes,
        cloned_key_out: *mut *const rustls_certified_key,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let cloned_key_out: &mut *const rustls_certified_key = unsafe {
                match cloned_key_out.as_mut() {
                    Some(c) => c,
                    None => return NullParameter,
                }
            };
            let certified_key: &CertifiedKey = try_ref_from_ptr!(certified_key);
            let mut new_key = certified_key.deref().clone();
            if !ocsp_response.is_null() {
                let ocsp_slice = unsafe{ &*ocsp_response };
                new_key.ocsp = Some(Vec::from(try_slice!(ocsp_slice.data, ocsp_slice.len)));
            } else {
                new_key.ocsp = None;
            }
            *cloned_key_out = ArcCastPtr::to_const_ptr(new_key);
            rustls_result::Ok
        }
    }

    /// "Free" a certified_key previously returned from
    /// rustls_certified_key_build. Since certified_key is actually an
    /// atomically reference-counted pointer, extant certified_key may still
    /// hold an internal reference to the Rust object. However, C code must
    /// consider this pointer unusable after "free"ing it.
    /// Calling with NULL is fine. Must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_certified_key_free(key: *const rustls_certified_key) {
        ffi_panic_boundary! {
            rustls_certified_key::free(key);
        }
    }

    fn certified_key_build(
        cert_chain: *const u8,
        cert_chain_len: size_t,
        private_key: *const u8,
        private_key_len: size_t,
    ) -> Result<CertifiedKey, rustls_result> {
        let mut cert_chain: &[u8] = unsafe {
            if cert_chain.is_null() {
                return Err(NullParameter);
            }
            slice::from_raw_parts(cert_chain, cert_chain_len)
        };
        let private_key: &[u8] = unsafe {
            if private_key.is_null() {
                return Err(NullParameter);
            }
            slice::from_raw_parts(private_key, private_key_len)
        };
        let mut private_keys: Vec<Vec<u8>> = match pkcs8_private_keys(&mut Cursor::new(private_key))
        {
            Ok(v) => v,
            Err(_) => return Err(rustls_result::PrivateKeyParseError),
        };
        let private_key: PrivateKey = match private_keys.pop() {
            Some(p) => PrivateKey(p),
            None => {
                private_keys = match rsa_private_keys(&mut Cursor::new(private_key)) {
                    Ok(v) => v,
                    Err(_) => return Err(rustls_result::PrivateKeyParseError),
                };
                let rsa_private_key: PrivateKey = match private_keys.pop() {
                    Some(p) => PrivateKey(p),
                    None => return Err(rustls_result::PrivateKeyParseError),
                };
                rsa_private_key
            }
        };
        let signing_key = match rustls::sign::any_supported_type(&private_key) {
            Ok(key) => key,
            Err(_) => return Err(rustls_result::PrivateKeyParseError),
        };
        let parsed_chain: Vec<Certificate> = match certs(&mut cert_chain) {
            Ok(v) => v.into_iter().map(Certificate).collect(),
            Err(_) => return Err(rustls_result::CertificateParseError),
        };

        Ok(rustls::sign::CertifiedKey::new(parsed_chain, signing_key))
    }
}

/// A root certificate store.
/// <https://docs.rs/rustls/latest/rustls/struct.RootCertStore.html>
pub struct rustls_root_cert_store {
    // We use the opaque struct pattern to tell C about our types without
    // telling them what's inside.
    // https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs
    _private: [u8; 0],
}

impl CastPtr for rustls_root_cert_store {
    type RustType = RootCertStore;
}

impl BoxCastPtr for rustls_root_cert_store {}

impl rustls_root_cert_store {
    /// Create a rustls_root_cert_store. Caller owns the memory and must
    /// eventually call rustls_root_cert_store_free. The store starts out empty.
    /// Caller must add root certificates with rustls_root_cert_store_add_pem.
    /// <https://docs.rs/rustls/latest/rustls/struct.RootCertStore.html#method.empty>
    #[no_mangle]
    pub extern "C" fn rustls_root_cert_store_new() -> *mut rustls_root_cert_store {
        ffi_panic_boundary! {
            let store = rustls::RootCertStore::empty();
            BoxCastPtr::to_mut_ptr(store)
        }
    }

    /// Add one or more certificates to the root cert store using PEM encoded data.
    ///
    /// When `strict` is true an error will return a `CertificateParseError`
    /// result. So will an attempt to parse data that has zero certificates.
    ///
    /// When `strict` is false, unparseable root certificates will be ignored.
    /// This may be useful on systems that have syntactically invalid root
    /// certificates.
    #[no_mangle]
    pub extern "C" fn rustls_root_cert_store_add_pem(
        store: *mut rustls_root_cert_store,
        pem: *const u8,
        pem_len: size_t,
        strict: bool,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let certs_pem: &[u8] = try_slice!(pem, pem_len);
            let store: &mut RootCertStore = try_mut_from_ptr!(store);

            let certs_der = match rustls_pemfile::certs(&mut Cursor::new(certs_pem)) {
                Ok(vv) => vv,
                Err(_) => return rustls_result::CertificateParseError,
            };
            // We first copy into a temporary root store so we can uphold our
            // API guideline that there are no partial failures or partial
            // successes.
            let mut new_store = RootCertStore::empty();
            let (parsed, rejected) = new_store.add_parsable_certificates(&certs_der);
            if strict && (rejected > 0 || parsed == 0) {
                return rustls_result::CertificateParseError;
            }

            store.roots.append(&mut new_store.roots);
            rustls_result::Ok
        }
    }

    /// Free a rustls_root_cert_store previously returned from rustls_root_cert_store_builder_build.
    /// Calling with NULL is fine. Must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_root_cert_store_free(store: *mut rustls_root_cert_store) {
        ffi_panic_boundary! {
            let store = try_box_from_ptr!(store);
            drop(store)
        }
    }
}

/// A builder for a `rustls_allow_any_authenticated_client_verifier`. This builder object can be
/// used to configure certificate revocation lists, and then turned into a
/// `rustls_allow_any_authenticated_client_verifier` once ready.
pub struct rustls_allow_any_authenticated_client_builder {
    _private: [u8; 0],
}

impl CastPtr for rustls_allow_any_authenticated_client_builder {
    // NOTE: contained value is consumed even on error, so this can contain None. but the caller
    // still needs to free it
    type RustType = Option<AllowAnyAuthenticatedClient>;
}

impl BoxCastPtr for rustls_allow_any_authenticated_client_builder {}

impl rustls_allow_any_authenticated_client_builder {
    /// Create a new allow any authenticated client certificate verifier builder using the root store.
    ///
    /// This copies the contents of the rustls_root_cert_store. It does not take
    /// ownership of the pointed-to memory.
    ///
    /// This object can then be used to load any CRLs.
    ///
    /// Once that is complete, convert it into a real `rustls_allow_any_authenticated_client_verifier`
    /// by calling `rustls_allow_any_authenticated_client_verifier_new()`.
    #[no_mangle]
    pub extern "C" fn rustls_allow_any_authenticated_client_builder_new(
        store: *const rustls_root_cert_store,
    ) -> *mut rustls_allow_any_authenticated_client_builder {
        ffi_panic_boundary! {
            let store: &RootCertStore = try_ref_from_ptr!(store);
            let client_cert_verifier = Some(AllowAnyAuthenticatedClient::new(store.clone()));
            BoxCastPtr::to_mut_ptr(client_cert_verifier)
        }
    }

    /// Add one or more certificate revocation lists (CRLs) to the client certificate verifier by
    /// reading the CRL content from the provided buffer of PEM encoded content.
    ///
    /// This function returns an error if the provided buffer is not valid PEM encoded content,
    /// or if the CRL content is invalid or unsupported.
    #[no_mangle]
    pub extern "C" fn rustls_allow_any_authenticated_client_builder_add_crl(
        builder: *mut rustls_allow_any_authenticated_client_builder,
        crl_pem: *const u8,
        crl_pem_len: size_t,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let client_cert_verifier_builder: &mut Option<AllowAnyAuthenticatedClient> = try_mut_from_ptr!(builder);

            let crl_pem: &[u8] = try_slice!(crl_pem, crl_pem_len);
            let crls_der: Vec<UnparsedCertRevocationList> = match crls(&mut Cursor::new(crl_pem)) {
                Ok(vv) => vv.into_iter().map(UnparsedCertRevocationList).collect(),
                Err(_) => return rustls_result::CertificateRevocationListParseError,
            };

            let client_cert_verifier = match client_cert_verifier_builder.take() {
                None => {
                    return AlreadyUsed;
                },
                Some(x) => x,
            };

            match client_cert_verifier.with_crls(crls_der) {
                Ok(v) => client_cert_verifier_builder.replace(v),
                Err(e) => return map_error(rustls::Error::InvalidCertRevocationList(e)),
            };

            rustls_result::Ok
        }
    }

    /// Free a `rustls_allow_any_authenticated_client_builder` previously returned from
    /// `rustls_allow_any_authenticated_client_builder_new`.
    /// Calling with NULL is fine. Must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_allow_any_authenticated_client_builder_free(
        builder: *mut rustls_allow_any_authenticated_client_builder,
    ) {
        ffi_panic_boundary! {
            let store = try_box_from_ptr!(builder);
            drop(store)
        }
    }
}

/// A verifier of client certificates that requires all certificates to be
/// trusted based on a given `rustls_root_cert_store`. Usable in building server
/// configurations. Connections without such a client certificate will not
/// be accepted.
pub struct rustls_allow_any_authenticated_client_verifier {
    _private: [u8; 0],
}

impl CastConstPtr for rustls_allow_any_authenticated_client_verifier {
    type RustType = AllowAnyAuthenticatedClient;
}

impl ArcCastPtr for rustls_allow_any_authenticated_client_verifier {}

impl rustls_allow_any_authenticated_client_verifier {
    /// Create a new allow any authenticated client certificate verifier from a builder.
    ///
    /// The builder is consumed and cannot be used again, but must still be freed.
    ///
    /// The verifier can be used in several `rustls_server_config` instances. Must be freed by
    /// the application when no longer needed. See the documentation of
    /// `rustls_allow_any_authenticated_client_verifier_free` for details about lifetime.
    /// This copies the contents of the `rustls_root_cert_store`. It does not take
    /// ownership of the pointed-to memory.
    #[no_mangle]
    pub extern "C" fn rustls_allow_any_authenticated_client_verifier_new(
        builder: *mut rustls_allow_any_authenticated_client_builder,
    ) -> *const rustls_allow_any_authenticated_client_verifier {
        ffi_panic_boundary! {
            let client_cert_verifier_builder: &mut Option<AllowAnyAuthenticatedClient> = try_mut_from_ptr!(builder);

            let client_cert_verifier = match client_cert_verifier_builder.take() {
                None => {
                    return null() as *const _;
                },
                Some(x) => x,
            };
            return Arc::into_raw(client_cert_verifier.boxed()) as *const _;
        }
    }

    /// "Free" a verifier previously returned from
    /// `rustls_allow_any_authenticated_client_verifier_new`. Since
    /// `rustls_allow_any_authenticated_client_verifier` is actually an
    /// atomically reference-counted pointer, extant server_configs may still
    /// hold an internal reference to the Rust object. However, C code must
    /// consider this pointer unusable after "free"ing it.
    /// Calling with NULL is fine. Must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_allow_any_authenticated_client_verifier_free(
        verifier: *const rustls_allow_any_authenticated_client_verifier,
    ) {
        ffi_panic_boundary! {
            rustls_allow_any_authenticated_client_verifier::free(verifier);
        }
    }
}

/// A builder for a `rustls_allow_any_anonymous_or_authenticated_client_verifier`. This builder
/// object can be used to configure certificate revocation lists, and then turned into a
/// `rustls_allow_any_anonymous_or_authenticated_client_verifier` once ready.
pub struct rustls_allow_any_anonymous_or_authenticated_client_builder {
    _private: [u8; 0],
}

impl CastPtr for rustls_allow_any_anonymous_or_authenticated_client_builder {
    // NOTE: contained value is consumed even on error, so this can contain None. but the caller
    // still needs to free it
    type RustType = Option<AllowAnyAnonymousOrAuthenticatedClient>;
}

impl BoxCastPtr for rustls_allow_any_anonymous_or_authenticated_client_builder {}

impl rustls_allow_any_anonymous_or_authenticated_client_builder {
    /// Create a new allow any anonymous or authenticated client certificate verifier builder
    /// using the root store.
    ///
    /// This copies the contents of the rustls_root_cert_store. It does not take
    /// ownership of the pointed-to memory.
    ///
    /// This object can then be used to load any CRLs.
    ///
    /// Once that is complete, convert it into a real
    /// `rustls_allow_any_anonymous_or_authenticated_client_verifier`
    /// by calling `rustls_allow_any_anonymous_or_authenticated_client_verifier_new()`.
    #[no_mangle]
    pub extern "C" fn rustls_client_cert_verifier_optional_builder_new(
        store: *const rustls_root_cert_store,
    ) -> *mut rustls_allow_any_anonymous_or_authenticated_client_builder {
        ffi_panic_boundary! {
            let store: &RootCertStore = try_ref_from_ptr!(store);
            let client_cert_verifier = Some(AllowAnyAnonymousOrAuthenticatedClient::new(store.clone()));
            BoxCastPtr::to_mut_ptr(client_cert_verifier)
        }
    }

    /// Add one or more certificate revocation lists (CRLs) to the client certificate verifier by
    /// reading the CRL content from the provided buffer of PEM encoded content.
    ///
    /// This function returns an error if the provided buffer is not valid PEM encoded content,
    /// or if the CRL content is invalid or unsupported.
    #[no_mangle]
    pub extern "C" fn rustls_client_cert_verifier_optional_builder_add_crl(
        builder: *mut rustls_allow_any_anonymous_or_authenticated_client_builder,
        crl_pem: *const u8,
        crl_pem_len: size_t,
    ) -> rustls_result {
        ffi_panic_boundary! {
            let client_cert_verifier_builder: &mut Option<AllowAnyAnonymousOrAuthenticatedClient> = try_mut_from_ptr!(builder);

            let crl_pem: &[u8] = try_slice!(crl_pem, crl_pem_len);
            let crls_der: Vec<UnparsedCertRevocationList> = match crls(&mut Cursor::new(crl_pem)) {
                Ok(vv) => vv.into_iter().map(UnparsedCertRevocationList).collect(),
                Err(_) => return rustls_result::CertificateRevocationListParseError,
            };

            let client_cert_verifier = match client_cert_verifier_builder.take() {
                None => {
                    return AlreadyUsed;
                },
                Some(x) => x,
            };

            match client_cert_verifier.with_crls(crls_der) {
                Ok(v) => client_cert_verifier_builder.replace(v),
                Err(e) => return map_error(rustls::Error::InvalidCertRevocationList(e)),
            };

            rustls_result::Ok
        }
    }

    /// Free a `rustls_allow_any_anonymous_or_authenticated_client_builder` previously returned from
    /// `rustls_client_cert_verifier_optional_builder_new`.
    /// Calling with NULL is fine. Must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_client_cert_verifier_optional_builder_free(
        builder: *mut rustls_allow_any_anonymous_or_authenticated_client_builder,
    ) {
        ffi_panic_boundary! {
            let store = try_box_from_ptr!(builder);
            drop(store)
        }
    }
}

/// Alternative to `rustls_allow_any_authenticated_client_verifier` that allows connections
/// with or without a client certificate. If the client offers a certificate,
/// it will be verified (and rejected if it is not valid). If the client
/// does not offer a certificate, the connection will succeed.
///
/// The application can retrieve the certificate, if any, with
/// `rustls_connection_get_peer_certificate`.
pub struct rustls_allow_any_anonymous_or_authenticated_client_verifier {
    _private: [u8; 0],
}

impl CastConstPtr for rustls_allow_any_anonymous_or_authenticated_client_verifier {
    type RustType = AllowAnyAnonymousOrAuthenticatedClient;
}

impl ArcCastPtr for rustls_allow_any_anonymous_or_authenticated_client_verifier {}

impl rustls_allow_any_anonymous_or_authenticated_client_verifier {
    /// Create a new allow any anonymous or authenticated client certificate verifier builder
    /// from the builder.
    ///
    /// The builder is consumed and cannot be used again, but must still be freed.
    ///
    /// The verifier can be used in several `rustls_server_config` instances. Must be
    /// freed by the application when no longer needed. See the documentation of
    /// `rustls_allow_any_anonymous_or_authenticated_client_verifier_free` for details about lifetime.
    /// This copies the contents of the `rustls_root_cert_store`. It does not take
    /// ownership of the pointed-to data.
    #[no_mangle]
    pub extern "C" fn rustls_allow_any_anonymous_or_authenticated_client_verifier_new(
        builder: *mut rustls_allow_any_anonymous_or_authenticated_client_builder,
    ) -> *const rustls_allow_any_anonymous_or_authenticated_client_verifier {
        ffi_panic_boundary! {
            let client_cert_verifier_builder: &mut Option<AllowAnyAnonymousOrAuthenticatedClient> = try_mut_from_ptr!(builder);

            let client_cert_verifier = match client_cert_verifier_builder.take() {
                None => {
                    return null() as *const _;
                },
                Some(x) => x,
            };
            return Arc::into_raw(client_cert_verifier.boxed()) as *const _;
        }
    }

    /// "Free" a verifier previously returned from
    /// `rustls_allow_any_anonymous_or_authenticated_client_verifier_new`. Since
    /// `rustls_allow_any_anonymous_or_authenticated_client_verifier`
    /// is actually an atomically reference-counted pointer, extant `server_configs` may still
    /// hold an internal reference to the Rust object. However, C code must
    /// consider this pointer unusable after "free"ing it.
    /// Calling with NULL is fine. Must not be called twice with the same value.
    #[no_mangle]
    pub extern "C" fn rustls_allow_any_anonymous_or_authenticated_client_verifier_free(
        verifier: *const rustls_allow_any_anonymous_or_authenticated_client_verifier,
    ) {
        ffi_panic_boundary! {
            rustls_allow_any_anonymous_or_authenticated_client_verifier::free(verifier);
        }
    }
}
