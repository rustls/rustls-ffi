use std::{cmp::min, slice};

use crate::{ffi_panic_boundary_generic, ffi_panic_boundary_unit};
use libc::{c_char, size_t};
use std::os::raw::c_ushort;

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
