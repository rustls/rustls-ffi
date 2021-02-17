use std::{cmp::min, slice};

use crate::{ffi_panic_boundary_generic, ffi_panic_boundary_unit};
use libc::{c_char, size_t};
use std::os::raw::c_ushort;


static ALL_SIGNATURE_SCHEMES: &[rustls::SignatureScheme] = &[
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

fn signature_scheme_name(n: u16) -> String {
    for scheme in ALL_SIGNATURE_SCHEMES {
        if scheme.get_u16() == n {
            return format!("{:?}", scheme)
        }
    };
    String::from("Unknown")
}

pub(crate) fn map_signature_schemes(schemes: &[rustls::SignatureScheme]) -> Vec<u16> {
    let mut mapped_schemes :Vec<u16> = Vec::new();
    for s in schemes {
        mapped_schemes.push(s.get_u16());
    }
    mapped_schemes
}

#[no_mangle]
pub extern "C" fn rustls_signature_scheme_name(
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
