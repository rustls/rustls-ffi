#[repr(C)]
#[allow(dead_code)]
pub enum rustls_tls_version {
    SSLv2 = 0x0200,
    SSLv3 = 0x0300,
    TLSv1_0 = 0x0301,
    TLSv1_1 = 0x0302,
    TLSv1_2 = 0x0303,
    TLSv1_3 = 0x0304,
}

pub(crate) fn rustls_tls_version_from_u16(version_num: u16) -> Option<rustls::ProtocolVersion> {
    match version_num {
        0x0200 => Some(rustls::ProtocolVersion::SSLv2),
        0x0300 => Some(rustls::ProtocolVersion::SSLv3),
        0x0301 => Some(rustls::ProtocolVersion::TLSv1_0),
        0x0302 => Some(rustls::ProtocolVersion::TLSv1_1),
        0x0303 => Some(rustls::ProtocolVersion::TLSv1_2),
        0x0304 => Some(rustls::ProtocolVersion::TLSv1_3),
        _ => None,
    }
}
