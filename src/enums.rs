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
