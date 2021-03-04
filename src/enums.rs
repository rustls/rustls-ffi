#[repr(C)]
#[warn(dead_code)]
pub enum rustls_protocol_version {
    SSLv2 = 0x0200,
    SSLv3 = 0x0300,
    TLSv1_0 = 0x0301,
    TLSv1_1 = 0x0302,
    TLSv1_2 = 0x0303,
    TLSv1_3 = 0x0304,
}
