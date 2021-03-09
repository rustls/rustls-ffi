use std::{cmp::min, slice};

use crate::error::rustls_result;
use crate::{
    ffi_panic_boundary, ffi_panic_boundary_generic, ffi_panic_boundary_unit, try_ref_from_ptr,
};
use libc::{c_char, size_t};
use std::io::Cursor;
use std::os::raw::c_ushort;
use std::sync::Arc;

use rustls::{Certificate, PrivateKey};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};

use rustls::sign::CertifiedKey;
use rustls_result::NullParameter;

/// All SignatureScheme currently defined in rustls.
/// At the moment not exposed by rustls itself.
#[no_mangle]
pub(crate) static ALL_SIGNATURE_SCHEMES: &[rustls::SignatureScheme] = &[
    rustls::SignatureScheme::RSA_PKCS1_SHA1,
    rustls::SignatureScheme::ECDSA_SHA1_Legacy,
    rustls::SignatureScheme::RSA_PKCS1_SHA256,
    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
    rustls::SignatureScheme::RSA_PKCS1_SHA384,
    rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
    rustls::SignatureScheme::RSA_PKCS1_SHA512,
    rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
    rustls::SignatureScheme::RSA_PSS_SHA256,
    rustls::SignatureScheme::RSA_PSS_SHA384,
    rustls::SignatureScheme::RSA_PSS_SHA512,
    rustls::SignatureScheme::ED25519,
    rustls::SignatureScheme::ED448,
];

/// rustls has the names in its Debug trait implementation, which
/// we use for all known schemes. For all others we return the hex value.
/// Note that this u16 values are used in protocol handshake by both sides,
/// so we have to expect unknown values to arrive here.
fn signature_scheme_name(n: u16) -> String {
    for scheme in ALL_SIGNATURE_SCHEMES {
        if scheme.get_u16() == n {
            return format!("{:?}", scheme);
        }
    }
    format!("Unknown({:#06x})", n)
}

/// Collect the u16 values of the given SignatureScheme slice, so they
/// can be exposed in our API.
pub(crate) fn rustls_cipher_map_signature_schemes(schemes: &[rustls::SignatureScheme]) -> Vec<u16> {
    let mut mapped_schemes: Vec<u16> = Vec::new();
    for s in schemes {
        mapped_schemes.push(s.get_u16());
    }
    mapped_schemes
}

/// Get the name of a SignatureScheme, represented by the `scheme` short value,
/// if known by the rustls library. For unknown schemes, this returns a string
/// with the scheme value in hex notation.
/// Mainly useful for debugging output.
/// The caller provides `buf` for holding the string and gives its size as `len`
/// bytes. On return `out_n` carries the number of bytes copied into `buf`. The
/// `buf` is not NUL-terminated.
///
#[no_mangle]
pub extern "C" fn rustls_cipher_get_signature_scheme_name(
    scheme: c_ushort,
    buf: *mut c_char,
    len: size_t,
    out_n: *mut size_t,
) {
    ffi_panic_boundary_unit! {
        let write_buf: &mut [u8] = unsafe {
            let out_n: &mut size_t = match out_n.as_mut() {
                Some(out_n) => out_n,
                None => return,
            };
            *out_n = 0;
            if buf.is_null() {
                return;
            }
            slice::from_raw_parts_mut(buf as *mut u8, len as usize)
        };
        let name = signature_scheme_name(scheme);
        let len: usize = min(write_buf.len() - 1, name.len());
        write_buf[..len].copy_from_slice(&name.as_bytes()[..len]);
        unsafe {
            *out_n = len;
        }
    }
}

/// The complete chain of certificates plus private key for
/// being certified against someones list of trust anchors (commonly
/// called root store). Corresponds to `CertifiedKey` in the Rust API.
pub struct rustls_certified_key {
    // We use the opaque struct pattern to tell C about our types without
    // telling them what's inside.
    // https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs
    _private: [u8; 0],
}

#[no_mangle]
pub extern "C" fn rustls_certified_key_build(
    cert_chain: *const u8,
    cert_chain_len: size_t,
    private_key: *const u8,
    private_key_len: size_t,
    certified_key_out: *mut *const rustls_certified_key,
) -> rustls_result {
    ffi_panic_boundary! {
        let certified_key = match certified_key_build(
            cert_chain, cert_chain_len, private_key, private_key_len) {
            Ok(key) => Box::new(key),
            Err(rr) => return rr,
        };
        unsafe {
            *certified_key_out = Arc::into_raw(Arc::new(*certified_key)) as *const _;
        }
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
pub extern "C" fn rustls_certified_key_free(config: *const rustls_certified_key) {
    ffi_panic_boundary_unit! {
        let key: &CertifiedKey = try_ref_from_ptr!(config, &mut CertifiedKey, ());
        // To free the certified_key, we reconstruct the Arc. It should have a refcount of 1,
        // representing the C code's copy. When it drops, that refcount will go down to 0
        // and the inner ServerConfig will be dropped.
        let arc: Arc<CertifiedKey> = unsafe { Arc::from_raw(key) };
        let strong_count = Arc::strong_count(&arc);
        if strong_count < 1 {
            eprintln!(
                "rustls_certified_key_free: invariant failed: arc.strong_count was < 1: {}. \
                You must not free the same certified_key multiple times.",
                strong_count
            );
        }
    }
}

pub(crate) fn certified_key_build(
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
