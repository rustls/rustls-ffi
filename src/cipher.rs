use rustls::SupportedCipherSuite;

use crate::enums::rustls_tls_version;
use crate::ffi::{ref_castable, try_ref_from_ptr};
use crate::panic::ffi_panic_boundary;
use crate::rslice::rustls_str;

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
                SupportedCipherSuite::Tls12(sc) => &sc.common,
                SupportedCipherSuite::Tls13(sc) => &sc.common,
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

#[cfg(test)]
mod tests {
    use crate::crypto_provider::{
        rustls_default_crypto_provider_ciphersuites_get,
        rustls_default_crypto_provider_ciphersuites_len,
    };

    use super::*;

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
