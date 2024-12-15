use rustls::{HandshakeKind, ProtocolVersion, SupportedProtocolVersion};

use crate::ffi_panic_boundary;
use crate::rslice::rustls_str;

#[derive(Debug, Default)]
#[repr(C)]
/// Definitions of known TLS protocol versions.
pub enum rustls_tls_version {
    #[default]
    Unknown = 0x0000,
    Sslv2 = 0x0200,
    Sslv3 = 0x0300,
    Tlsv1_0 = 0x0301,
    Tlsv1_1 = 0x0302,
    Tlsv1_2 = 0x0303,
    Tlsv1_3 = 0x0304,
}

impl From<&SupportedProtocolVersion> for rustls_tls_version {
    fn from(version: &SupportedProtocolVersion) -> Self {
        match version.version {
            ProtocolVersion::SSLv2 => rustls_tls_version::Sslv2,
            ProtocolVersion::SSLv3 => rustls_tls_version::Sslv3,
            ProtocolVersion::TLSv1_0 => rustls_tls_version::Tlsv1_0,
            ProtocolVersion::TLSv1_1 => rustls_tls_version::Tlsv1_1,
            ProtocolVersion::TLSv1_2 => rustls_tls_version::Tlsv1_2,
            ProtocolVersion::TLSv1_3 => rustls_tls_version::Tlsv1_3,
            _ => rustls_tls_version::Unknown,
        }
    }
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

#[derive(Debug, Default)]
#[repr(C)]
/// Describes which sort of handshake happened.
pub enum rustls_handshake_kind {
    /// The type of handshake could not be determined.
    ///
    /// This variant should not be used.
    #[default]
    Unknown = 0x0,

    /// A full TLS handshake.
    ///
    /// This is the typical TLS connection initiation process when resumption is
    /// not yet unavailable, and the initial client hello was accepted by the server.
    Full = 0x1,

    /// A full TLS handshake, with an extra round-trip for a hello retry request.
    ///
    /// The server can respond with a hello retry request (HRR) if the initial client
    /// hello is unacceptable for several reasons, the most likely if no supported key
    /// shares were offered by the client.
    FullWithHelloRetryRequest = 0x2,

    /// A resumed TLS handshake.
    ///
    /// Resumed handshakes involve fewer round trips and less cryptography than
    /// full ones, but can only happen when the peers have previously done a full
    /// handshake together, and then remember data about it.
    Resumed = 0x3,
}

/// Convert a `rustls_handshake_kind` to a string with a friendly description of the kind
/// of handshake.
///
/// The returned `rustls_str` has a static lifetime equal to that of the program and does
/// not need to be manually freed.
#[no_mangle]
pub extern "C" fn rustls_handshake_kind_str(kind: rustls_handshake_kind) -> rustls_str<'static> {
    ffi_panic_boundary! {
        rustls_str::from_str_unchecked(match kind {
            rustls_handshake_kind::Unknown => "unknown",
            rustls_handshake_kind::Full => "full",
            rustls_handshake_kind::FullWithHelloRetryRequest => "full with hello retry request",
            rustls_handshake_kind::Resumed => "resumed",
        })
    }
}

impl From<HandshakeKind> for rustls_handshake_kind {
    fn from(kind: HandshakeKind) -> Self {
        match kind {
            HandshakeKind::Full => Self::Full,
            HandshakeKind::FullWithHelloRetryRequest => Self::FullWithHelloRetryRequest,
            HandshakeKind::Resumed => Self::Resumed,
        }
    }
}

#[cfg(test)]
mod tests {
    use rustls::{ALL_VERSIONS, DEFAULT_VERSIONS};

    use super::*;

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
