use libc::size_t;
use std::io::Cursor;
use std::ptr::null;
use std::slice;
use std::sync::Arc;

use rustls::sign::CertifiedKey;
use rustls::{
    AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient, RootCertStore,
    SupportedCipherSuite, ALL_CIPHERSUITES,
};
use rustls::{Certificate, PrivateKey};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};

use crate::error::rustls_result;
use crate::rslice::rustls_slice_bytes;
use crate::{ffi_panic_boundary, try_mut_from_ptr, try_ref_from_ptr, try_slice, CastPtr};
use rustls_result::NullParameter;
use std::ops::Deref;

/// An X.509 certificate, as used in rustls.
/// Corresponds to `Certificate` in the Rust API.
/// https://docs.rs/rustls/0.19.0/rustls/struct.CertifiedKey.html
pub struct rustls_certificate {
    // We use the opaque struct pattern to tell C about our types without
    // telling them what's inside.
    // https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs
    _private: [u8; 0],
}

impl CastPtr for rustls_certificate {
    type RustType = Certificate;
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
        let out_der_data: &mut *const u8 = try_mut_from_ptr!(out_der_data);
        let out_der_len: &mut size_t = try_mut_from_ptr!(out_der_len);
        let der = cert.as_ref();
        *out_der_data = der.as_ptr();
        *out_der_len = der.len();
        rustls_result::Ok
    }
}

/// The complete chain of certificates to send during a TLS handshake,
/// plus a private key that matches the end-entity (leaf) certificate.
/// Corresponds to `CertifiedKey` in the Rust API.
/// https://docs.rs/rustls/0.19.0/rustls/sign/struct.CertifiedKey.html
pub struct rustls_certified_key {
    // We use the opaque struct pattern to tell C about our types without
    // telling them what's inside.
    // https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs
    _private: [u8; 0],
}

impl CastPtr for rustls_certified_key {
    type RustType = CertifiedKey;
}

/// A cipher suite supported by rustls.
pub struct rustls_supported_ciphersuite {
    _private: [u8; 0],
}

impl CastPtr for rustls_supported_ciphersuite {
    type RustType = SupportedCipherSuite;
}

/// Return a 16-bit unsigned integer corresponding to this cipher suite's assignment from
/// <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4>.
/// The bytes from the assignment are interpreted in network order.
#[no_mangle]
pub extern "C" fn rustls_supported_ciphersuite_get_suite(
    supported_ciphersuite: *const rustls_supported_ciphersuite,
) -> u16 {
    let supported_ciphersuite = try_ref_from_ptr!(supported_ciphersuite);
    supported_ciphersuite.suite.get_u16()
}

/// Return the length of rustls' list of supported cipher suites.
#[no_mangle]
pub extern "C" fn rustls_all_ciphersuites_len() -> usize {
    ALL_CIPHERSUITES.len()
}

/// Get a pointer to a member of rustls' list of supported cipher suites. This will return non-NULL
/// for i < rustls_all_ciphersuites_len().
/// The returned pointer is valid for the lifetime of the program and may be used directly when
/// building a ClientConfig or ServerConfig.
#[no_mangle]
pub extern "C" fn rustls_all_ciphersuites_get_entry(
    i: size_t,
) -> *const rustls_supported_ciphersuite {
    match ALL_CIPHERSUITES.get(i) {
        Some(&cs) => cs as *const SupportedCipherSuite as *const _,
        None => null(),
    }
}

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
        let certified_key = match certified_key_build(
            cert_chain, cert_chain_len, private_key, private_key_len) {
            Ok(key) => Box::new(key),
            Err(rr) => return rr,
        };
        let certified_key = Arc::into_raw(Arc::new(*certified_key)) as *const _;
        *certified_key_out = certified_key;
        return rustls_result::Ok
    }
}

/// Return the i-th rustls_certificate in the rustls_certified_key. 0 gives the
/// end-entity certificate. 1 and higher give certificates from the chain.
/// Indexes higher the the last available certificate return NULL.
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
        *cloned_key_out = Arc::into_raw(Arc::new(new_key)) as *const _;
        return rustls_result::Ok
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
        if key.is_null() {
            return;
        }
        // To free the certified_key, we reconstruct the Arc. It should have a refcount of 1,
        // representing the C code's copy. When it drops, that refcount will go down to 0
        // and the inner ServerConfig will be dropped.
        unsafe { drop(Arc::from_raw(key)) };
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
        slice::from_raw_parts(cert_chain, cert_chain_len as usize)
    };
    let private_key: &[u8] = unsafe {
        if private_key.is_null() {
            return Err(NullParameter);
        }
        slice::from_raw_parts(private_key, private_key_len as usize)
    };
    let mut private_keys: Vec<Vec<u8>> = match pkcs8_private_keys(&mut Cursor::new(private_key)) {
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

    Ok(rustls::sign::CertifiedKey::new(
        parsed_chain,
        Arc::new(signing_key),
    ))
}

/// A root cert store that is done being constructed and is now read-only.
/// Under the hood, this object corresponds to an Arc<RootCertStore>.
/// https://docs.rs/rustls/0.19.0/rustls/struct.RootCertStore.html
pub struct rustls_root_cert_store {
    // We use the opaque struct pattern to tell C about our types without
    // telling them what's inside.
    // https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs
    _private: [u8; 0],
}

impl CastPtr for rustls_root_cert_store {
    type RustType = RootCertStore;
}

/// Create a rustls_root_cert_store. Caller owns the memory and must
/// eventually call rustls_root_cert_store_free. The store starts out empty.
/// Caller must add root certificates with rustls_root_cert_store_add_pem.
/// https://docs.rs/rustls/0.19.0/rustls/struct.RootCertStore.html#method.empty
#[no_mangle]
pub extern "C" fn rustls_root_cert_store_new() -> *mut rustls_root_cert_store {
    ffi_panic_boundary! {
        let store = rustls::RootCertStore::empty();
        let s = Box::new(store);
        Box::into_raw(s) as *mut _
    }
}

/// Add one or more certificates to the root cert store using PEM encoded data.
///
/// When `strict` is true an error will return a `CertificateParseError`
/// result. So will an attempt to parse data that has zero certificates.

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

        // We first copy into a temporary root store so we can uphold our
        // API guideline that there are no partial failures or partial
        // successes.
        let mut new_store = RootCertStore::empty();
        match new_store.add_pem_file(&mut Cursor::new(certs_pem)) {
            Ok((parsed, rejected)) => {
                if strict && (rejected > 0 || parsed == 0) {
                    return rustls_result::CertificateParseError;
                }
            },
            Err(_) => return rustls_result::CertificateParseError,
        }

        store.roots.append(&mut new_store.roots);
        rustls_result::Ok
    }
}

/// "Free" a rustls_root_cert_store previously returned from
/// rustls_root_cert_store_builder_build. Since rustls_root_cert_store is actually an
/// atomically reference-counted pointer, extant rustls_root_cert_store may still
/// hold an internal reference to the Rust object. However, C code must
/// consider this pointer unusable after "free"ing it.
/// Calling with NULL is fine. Must not be called twice with the same value.
#[no_mangle]
pub extern "C" fn rustls_root_cert_store_free(store: *mut rustls_root_cert_store) {
    ffi_panic_boundary! {
        let store: &mut RootCertStore = try_mut_from_ptr!(store);
        // Convert the pointer to a Box and drop it.
        unsafe { drop(Box::from_raw(store)) }
    }
}

/// A verifier of client certificates that requires all certificates to be
/// trusted based on a given`rustls_root_cert_store`. Usable in building server
/// configurations. Connections without such a client certificate will not
/// be accepted.
pub struct rustls_client_cert_verifier {
    _private: [u8; 0],
}

impl CastPtr for rustls_client_cert_verifier {
    type RustType = AllowAnyAuthenticatedClient;
}

/// Create a new client certificate verifier for the root store. The verifier
/// can be used in several rustls_server_config instances. Must be freed by
/// the application when no longer needed. See the documentation of
/// rustls_client_cert_verifier_free for details about lifetime.
#[no_mangle]
pub extern "C" fn rustls_client_cert_verifier_new(
    store: *mut rustls_root_cert_store,
) -> *const rustls_client_cert_verifier {
    let store: &mut RootCertStore = try_mut_from_ptr!(store);
    return Arc::into_raw(AllowAnyAuthenticatedClient::new(store.clone())) as *const _;
}

/// "Free" a verifier previously returned from
/// rustls_client_cert_verifier_new. Since rustls_client_cert_verifier is actually an
/// atomically reference-counted pointer, extant server_configs may still
/// hold an internal reference to the Rust object. However, C code must
/// consider this pointer unusable after "free"ing it.
/// Calling with NULL is fine. Must not be called twice with the same value.
#[no_mangle]
pub extern "C" fn rustls_client_cert_verifier_free(verifier: *const rustls_client_cert_verifier) {
    ffi_panic_boundary! {
        if verifier.is_null() {
            return;
        }
        // To free the verifier, we reconstruct the Arc. It should have a refcount of 1,
        // representing the C code's copy. When it drops, that refcount will go down to 0
        // and the inner object will be dropped.
        unsafe { drop(Arc::from_raw(verifier)) };
    }
}

/// Alternative to `rustls_client_cert_verifier` that allows connections
/// with or without a client certificate. If the client offers a certificate,
/// it will be verified (and rejected if it is not valid). If the client
/// does not offer a certificate, the connection will succeed.
///
/// The application can retrieve the certificate, if any, with
/// rustls_server_session_get_peer_certificate.
pub struct rustls_client_cert_verifier_optional {
    _private: [u8; 0],
}

impl CastPtr for rustls_client_cert_verifier_optional {
    type RustType = AllowAnyAnonymousOrAuthenticatedClient;
}

/// Create a new rustls_client_cert_verifier_optional for the root store. The
/// verifier can be used in several rustls_server_config instances. Must be
/// freed by the application when no longer needed. See the documentation of
/// rustls_client_cert_verifier_optional_free for details about lifetime.
#[no_mangle]
pub extern "C" fn rustls_client_cert_verifier_optional_new(
    store: *mut rustls_root_cert_store,
) -> *const rustls_client_cert_verifier_optional {
    let store: &mut RootCertStore = try_mut_from_ptr!(store);
    return Arc::into_raw(AllowAnyAnonymousOrAuthenticatedClient::new(store.clone())) as *const _;
}

/// "Free" a verifier previously returned from
/// rustls_client_cert_verifier_optional_new. Since rustls_client_cert_verifier_optional
/// is actually an atomically reference-counted pointer, extant server_configs may still
/// hold an internal reference to the Rust object. However, C code must
/// consider this pointer unusable after "free"ing it.
/// Calling with NULL is fine. Must not be called twice with the same value.
#[no_mangle]
pub extern "C" fn rustls_client_cert_verifier_optional_free(
    verifier: *const rustls_client_cert_verifier_optional,
) {
    ffi_panic_boundary! {
        if verifier.is_null() {
            return;
        }
        // To free the verifier, we reconstruct the Arc. It should have a refcount of 1,
        // representing the C code's copy. When it drops, that refcount will go down to 0
        // and the inner object will be dropped.
        unsafe { drop(Arc::from_raw(verifier)) };
    }
}
