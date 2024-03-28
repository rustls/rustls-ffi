#[repr(C)]
#[allow(dead_code)]
/// Definitions of known TLS protocol versions.
pub enum rustls_tls_version {
    Sslv2 = 0x0200,
    Sslv3 = 0x0300,
    Tlsv1_0 = 0x0301,
    Tlsv1_1 = 0x0302,
    Tlsv1_2 = 0x0303,
    Tlsv1_3 = 0x0304,
}

/// Rustls' list of supported protocol versions. The length of the array is
/// given by `RUSTLS_ALL_VERSIONS_LEN`.
#[no_mangle]
pub static RUSTLS_ALL_VERSIONS: [u16; 2] = [
    rustls_tls_version::Tlsv1_3 as u16,
    rustls_tls_version::Tlsv1_2 as u16,
];

/// The length of the array `RUSTLS_ALL_VERSIONS`.
#[no_mangle]
pub static RUSTLS_ALL_VERSIONS_LEN: usize = RUSTLS_ALL_VERSIONS.len();

/// Rustls' default list of protocol versions. The length of the array is
/// given by `RUSTLS_DEFAULT_VERSIONS_LEN`.
#[no_mangle]
pub static RUSTLS_DEFAULT_VERSIONS: [u16; 2] = [
    rustls_tls_version::Tlsv1_3 as u16,
    rustls_tls_version::Tlsv1_2 as u16,
];

/// The length of the array `RUSTLS_DEFAULT_VERSIONS`.
#[no_mangle]
pub static RUSTLS_DEFAULT_VERSIONS_LEN: usize = RUSTLS_DEFAULT_VERSIONS.len();

#[cfg(test)]
mod tests {
    use super::*;

    use rustls::{ALL_VERSIONS, DEFAULT_VERSIONS};

    #[test]
    fn all_versions_arrays() {
        assert_eq!(RUSTLS_ALL_VERSIONS_LEN, ALL_VERSIONS.len());
        for (original, ffi) in ALL_VERSIONS.iter().zip(RUSTLS_ALL_VERSIONS.iter()) {
            assert_eq!(u16::from(original.version), *ffi);
        }
    }

    #[test]
    fn default_versions_arrays() {
        assert_eq!(RUSTLS_DEFAULT_VERSIONS_LEN, DEFAULT_VERSIONS.len());
        for (original, ffi) in DEFAULT_VERSIONS.iter().zip(RUSTLS_DEFAULT_VERSIONS.iter()) {
            assert_eq!(u16::from(original.version), *ffi);
        }
    }
}
