#[repr(C)]
#[allow(dead_code)]
/// Definitions of known TLS protocol versions.
pub enum rustls_tls_version {
    Sslv2 = 0x0200,
    Ssslv3 = 0x0300,
    Tlsv1_0 = 0x0301,
    Tlsv1_1 = 0x0302,
    Tlsv1_2 = 0x0303,
    Tlsv1_3 = 0x0304,
}

pub(crate) fn rustls_tls_version_from_u16(version_num: u16) -> rustls::ProtocolVersion {
    match version_num {
        // This is very bad and will be fixes in rustls by
        // <https://github.com/ctz/rustls/pull/583>.
        //
        // In Rust:
        //                rustls::ProtocolVersion::SSLv2
        // does NOT match rustls::ProtocolVersion::Unknown(0x0200)
        //
        0x0200 => rustls::ProtocolVersion::SSLv2,
        0x0300 => rustls::ProtocolVersion::SSLv3,
        0x0301 => rustls::ProtocolVersion::TLSv1_0,
        0x0302 => rustls::ProtocolVersion::TLSv1_1,
        0x0303 => rustls::ProtocolVersion::TLSv1_2,
        0x0304 => rustls::ProtocolVersion::TLSv1_3,
        n => rustls::ProtocolVersion::Unknown(n),
    }
}
