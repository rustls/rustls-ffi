use libc::size_t;
use std::io::Cursor;
use std::slice;
use std::sync::Arc;

use rustls::sign::CertifiedKey;
use rustls::{Certificate, PrivateKey};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};

use crate::error::rustls_result;
use crate::{ffi_panic_boundary, CastPtr};
use rustls_result::NullParameter;

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
