use std::{cmp::min, convert::TryFrom, fmt::Display, slice};

use crate::ffi_panic_boundary;
use libc::{c_char, c_uint, size_t};
use num_enum::TryFromPrimitive;
use rustls::Error;

/// A return value for a function that may return either success (0) or a
/// non-zero value representing an error. The values should match socket
/// error numbers for your operating system - for example, the integers for
/// ETIMEDOUT, EAGAIN, or similar.
#[repr(transparent)]
pub struct rustls_io_result(pub libc::c_int);

impl rustls_result {
    /// After a rustls function returns an error, you may call
    /// this to get a pointer to a buffer containing a detailed error
    /// message. The contents of the error buffer will be out_n bytes long,
    /// UTF-8 encoded, and not NUL-terminated.
    #[no_mangle]
    pub extern "C" fn rustls_error(
        result: c_uint,
        buf: *mut c_char,
        len: size_t,
        out_n: *mut size_t,
    ) {
        ffi_panic_boundary! {
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
            let result: rustls_result = rustls_result::try_from(result).unwrap_or(rustls_result::InvalidParameter);
            let error_str = result.to_string();
            let len: usize = min(write_buf.len() - 1, error_str.len());
            write_buf[..len].copy_from_slice(&error_str.as_bytes()[..len]);
            unsafe {
                *out_n = len;
            }
        }
    }

    #[no_mangle]
    pub extern "C" fn rustls_result_is_cert_error(result: rustls_result) -> bool {
        match result_to_error(&result) {
            Either::Error(e) => matches!(
                e,
                Error::InvalidCertificateData(_)
                    | Error::InvalidCertificateEncoding
                    | Error::InvalidCertificateSignature
                    | Error::InvalidCertificateSignatureType
                    | Error::InvalidSct(_)
            ),
            _ => false,
        }
    }
}

#[test]
fn test_rustls_error() {
    let mut buf = [0 as c_char; 512];
    let mut n = 0;
    rustls_result::rustls_error(0, &mut buf as *mut _, buf.len(), &mut n);
    let output: String = String::from_utf8(buf[0..n].iter().map(|b| *b as u8).collect()).unwrap();
    assert_eq!(&output, "a parameter had an invalid value");

    rustls_result::rustls_error(7000, &mut buf as *mut _, buf.len(), &mut n);
    let output: String = String::from_utf8(buf[0..n].iter().map(|b| *b as u8).collect()).unwrap();
    assert_eq!(&output, "OK");

    rustls_result::rustls_error(7101, &mut buf as *mut _, buf.len(), &mut n);
    let output: String = String::from_utf8(buf[0..n].iter().map(|b| *b as u8).collect()).unwrap();
    assert_eq!(&output, "peer sent no certificates");
}

#[allow(dead_code)]
#[repr(u32)]
#[derive(Debug, TryFromPrimitive)]
pub enum rustls_result {
    Ok = 7000,
    Io = 7001,
    NullParameter = 7002,
    InvalidDnsNameError = 7003,
    Panic = 7004,
    CertificateParseError = 7005,
    PrivateKeyParseError = 7006,
    InsufficientSize = 7007,
    NotFound = 7008,
    InvalidParameter = 7009,
    UnexpectedEof = 7010,
    PlaintextEmpty = 7011,

    // From https://docs.rs/rustls/0.20.0/rustls/enum.Error.html
    CorruptMessage = 7100,
    NoCertificatesPresented = 7101,
    DecryptError = 7102,
    FailedToGetCurrentTime = 7103,
    FailedToGetRandomBytes = 7113,
    HandshakeNotComplete = 7104,
    PeerSentOversizedRecord = 7105,
    NoApplicationProtocol = 7106,
    BadMaxFragmentSize = 7114,
    UnsupportedNameType = 7115,
    EncryptError = 7116,
    CertInvalidEncoding = 7117,
    CertInvalidSignatureType = 7118,
    CertInvalidSignature = 7119,
    CertInvalidData = 7120, // Last added

    // From Error, with fields that get dropped.
    PeerIncompatibleError = 7107,
    PeerMisbehavedError = 7108,
    InappropriateMessage = 7109,
    InappropriateHandshakeMessage = 7110,
    CorruptMessagePayload = 7111,
    General = 7112,

    // From Error, with fields that get flattened.
    // https://docs.rs/rustls/0.20.0/rustls/internal/msgs/enums/enum.AlertDescription.html
    AlertCloseNotify = 7200,
    AlertUnexpectedMessage = 7201,
    AlertBadRecordMac = 7202,
    AlertDecryptionFailed = 7203,
    AlertRecordOverflow = 7204,
    AlertDecompressionFailure = 7205,
    AlertHandshakeFailure = 7206,
    AlertNoCertificate = 7207,
    AlertBadCertificate = 7208,
    AlertUnsupportedCertificate = 7209,
    AlertCertificateRevoked = 7210,
    AlertCertificateExpired = 7211,
    AlertCertificateUnknown = 7212,
    AlertIllegalParameter = 7213,
    AlertUnknownCA = 7214,
    AlertAccessDenied = 7215,
    AlertDecodeError = 7216,
    AlertDecryptError = 7217,
    AlertExportRestriction = 7218,
    AlertProtocolVersion = 7219,
    AlertInsufficientSecurity = 7220,
    AlertInternalError = 7221,
    AlertInappropriateFallback = 7222,
    AlertUserCanceled = 7223,
    AlertNoRenegotiation = 7224,
    AlertMissingExtension = 7225,
    AlertUnsupportedExtension = 7226,
    AlertCertificateUnobtainable = 7227,
    AlertUnrecognisedName = 7228,
    AlertBadCertificateStatusResponse = 7229,
    AlertBadCertificateHashValue = 7230,
    AlertUnknownPSKIdentity = 7231,
    AlertCertificateRequired = 7232,
    AlertNoApplicationProtocol = 7233,
    AlertUnknown = 7234,

    // https://docs.rs/sct/0.5.0/sct/enum.Error.html
    CertSCTMalformed = 7319,
    CertSCTInvalidSignature = 7320,
    CertSCTTimestampInFuture = 7321,
    CertSCTUnsupportedVersion = 7322,
    CertSCTUnknownLog = 7323,
}

pub(crate) fn map_error(input: rustls::Error) -> rustls_result {
    use rustls::internal::msgs::enums::AlertDescription as alert;
    use rustls_result::*;
    use sct::Error as sct;

    match input {
        Error::InappropriateMessage { .. } => InappropriateMessage,
        Error::InappropriateHandshakeMessage { .. } => InappropriateHandshakeMessage,
        Error::CorruptMessage => CorruptMessage,
        Error::CorruptMessagePayload(_) => CorruptMessagePayload,
        Error::NoCertificatesPresented => NoCertificatesPresented,
        Error::DecryptError => DecryptError,
        Error::PeerIncompatibleError(_) => PeerIncompatibleError,
        Error::PeerMisbehavedError(_) => PeerMisbehavedError,
        Error::UnsupportedNameType => UnsupportedNameType,
        Error::EncryptError => EncryptError,

        Error::FailedToGetCurrentTime => FailedToGetCurrentTime,
        Error::FailedToGetRandomBytes => FailedToGetRandomBytes,
        Error::HandshakeNotComplete => HandshakeNotComplete,
        Error::PeerSentOversizedRecord => PeerSentOversizedRecord,
        Error::NoApplicationProtocol => NoApplicationProtocol,
        Error::BadMaxFragmentSize => BadMaxFragmentSize,

        Error::InvalidCertificateEncoding => CertInvalidEncoding,
        Error::InvalidCertificateSignatureType => CertInvalidSignatureType,
        Error::InvalidCertificateSignature => CertInvalidSignature,
        Error::InvalidCertificateData(_) => CertInvalidData,

        Error::General(_) => General,

        Error::AlertReceived(e) => match e {
            alert::CloseNotify => AlertCloseNotify,
            alert::UnexpectedMessage => AlertUnexpectedMessage,
            alert::BadRecordMac => AlertBadRecordMac,
            alert::DecryptionFailed => AlertDecryptionFailed,
            alert::RecordOverflow => AlertRecordOverflow,
            alert::DecompressionFailure => AlertDecompressionFailure,
            alert::HandshakeFailure => AlertHandshakeFailure,
            alert::NoCertificate => AlertNoCertificate,
            alert::BadCertificate => AlertBadCertificate,
            alert::UnsupportedCertificate => AlertUnsupportedCertificate,
            alert::CertificateRevoked => AlertCertificateRevoked,
            alert::CertificateExpired => AlertCertificateExpired,
            alert::CertificateUnknown => AlertCertificateUnknown,
            alert::IllegalParameter => AlertIllegalParameter,
            alert::UnknownCA => AlertUnknownCA,
            alert::AccessDenied => AlertAccessDenied,
            alert::DecodeError => AlertDecodeError,
            alert::DecryptError => AlertDecryptError,
            alert::ExportRestriction => AlertExportRestriction,
            alert::ProtocolVersion => AlertProtocolVersion,
            alert::InsufficientSecurity => AlertInsufficientSecurity,
            alert::InternalError => AlertInternalError,
            alert::InappropriateFallback => AlertInappropriateFallback,
            alert::UserCanceled => AlertUserCanceled,
            alert::NoRenegotiation => AlertNoRenegotiation,
            alert::MissingExtension => AlertMissingExtension,
            alert::UnsupportedExtension => AlertUnsupportedExtension,
            alert::CertificateUnobtainable => AlertCertificateUnobtainable,
            alert::UnrecognisedName => AlertUnrecognisedName,
            alert::BadCertificateStatusResponse => AlertBadCertificateStatusResponse,
            alert::BadCertificateHashValue => AlertBadCertificateHashValue,
            alert::UnknownPSKIdentity => AlertUnknownPSKIdentity,
            alert::CertificateRequired => AlertCertificateRequired,
            alert::NoApplicationProtocol => AlertNoApplicationProtocol,
            alert::Unknown(_) => AlertUnknown,
        },
        Error::InvalidSct(e) => match e {
            sct::MalformedSct => CertSCTMalformed,
            sct::InvalidSignature => CertSCTInvalidSignature,
            sct::TimestampInFuture => CertSCTTimestampInFuture,
            sct::UnsupportedSctVersion => CertSCTUnsupportedVersion,
            sct::UnknownLog => CertSCTUnknownLog,
        },
    }
}

impl Display for rustls_result {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg: String = match result_to_error(self) {
            Either::String(s) => s,
            Either::Error(e) => e.to_string(),
        };
        write!(f, "{}", msg)
    }
}

// Either a String or a rustls::Error
pub(crate) enum Either {
    String(String),
    Error(rustls::Error),
}

impl From<String> for Either {
    fn from(s: String) -> Either {
        Either::String(s)
    }
}

impl From<&str> for Either {
    fn from(s: &str) -> Either {
        Either::String(s.to_string())
    }
}

impl From<webpki::Error> for Either {
    fn from(e: webpki::Error) -> Either {
        Either::String(e.to_string())
    }
}

impl From<rustls::Error> for Either {
    fn from(e: rustls::Error) -> Either {
        Either::Error(e)
    }
}

// Turn a rustls_result into a rustls::Error on a best-effort basis. For
// variants that don't have a corresponding rustls::Error, or where we want to
// override rustls::Error's Display implementation, this returns a String.
// Otherwise, it returns a rustls::Error. This is used internally for determining
// whether a rustls_result is part of some top-level variant that maps to
// several rustls_results.
pub(crate) fn result_to_error(input: &rustls_result) -> Either {
    use rustls::internal::msgs::enums::AlertDescription as alert;
    use rustls_result::*;
    use sct::Error as sct;

    match input {
        // These variants are local to this glue layer.
        rustls_result::Ok =>  "OK".into(),
        Io =>  "I/O error".into(),
        NullParameter => "a parameter was NULL".into(),
        InvalidDnsNameError => "hostname was either malformed or an IP address (rustls does not support certificates for IP addresses)".into(),
        Panic => "a Rust component panicked".into(),
        CertificateParseError => "error parsing certificate".into(),
        PrivateKeyParseError => "error parsing private key".into(),
        InsufficientSize => "provided buffer is of insufficient size".into(),
        NotFound => "the item was not found".into(),
        InvalidParameter => "a parameter had an invalid value".into(),
        CertInvalidData => "invalid certificate data found".into(),
        UnexpectedEof =>  "unexpected EOF".into(),
        PlaintextEmpty =>  "no plaintext available; call rustls_connection_read_tls again".into(),

        // These variants correspond to a rustls::Error variant with a field,
        // where generating an arbitrary field would produce a confusing error
        // message. So we reproduce a simplified error string.
        InappropriateMessage => "received unexpected message".into(),
        InappropriateHandshakeMessage => "received unexpected handshake message".into(),
        CorruptMessagePayload => "received corrupt message".into(),

        CorruptMessage => Error::CorruptMessage.into(),
        NoCertificatesPresented => Error::NoCertificatesPresented.into(),
        DecryptError => Error::DecryptError.into(),
        FailedToGetCurrentTime => Error::FailedToGetCurrentTime.into(),
        FailedToGetRandomBytes => Error::FailedToGetRandomBytes.into(),
        HandshakeNotComplete => Error::HandshakeNotComplete.into(),
        PeerSentOversizedRecord => Error::PeerSentOversizedRecord.into(),
        NoApplicationProtocol => Error::NoApplicationProtocol.into(),
        PeerIncompatibleError => Error::PeerIncompatibleError("reason omitted".to_string()).into(),
        PeerMisbehavedError => Error::PeerMisbehavedError("reason omitted".to_string()).into(),
        BadMaxFragmentSize => Error::BadMaxFragmentSize.into(),
        UnsupportedNameType => Error::UnsupportedNameType.into(),
        EncryptError => Error::EncryptError.into(),
        CertInvalidEncoding => Error::InvalidCertificateEncoding.into(),
        CertInvalidSignatureType => Error::InvalidCertificateSignatureType.into(),
        CertInvalidSignature => Error::InvalidCertificateSignature.into(),

        General => Error::General("omitted".to_string()).into(),

        AlertCloseNotify => Error::AlertReceived(alert::CloseNotify).into(),
        AlertUnexpectedMessage => Error::AlertReceived(alert::UnexpectedMessage).into(),
        AlertBadRecordMac => Error::AlertReceived(alert::BadRecordMac).into(),
        AlertDecryptionFailed => Error::AlertReceived(alert::DecryptionFailed).into(),
        AlertRecordOverflow => Error::AlertReceived(alert::RecordOverflow).into(),
        AlertDecompressionFailure => Error::AlertReceived(alert::DecompressionFailure).into(),
        AlertHandshakeFailure => Error::AlertReceived(alert::HandshakeFailure).into(),
        AlertNoCertificate => Error::AlertReceived(alert::NoCertificate).into(),
        AlertBadCertificate => Error::AlertReceived(alert::BadCertificate).into(),
        AlertUnsupportedCertificate => Error::AlertReceived(alert::UnsupportedCertificate).into(),
        AlertCertificateRevoked => Error::AlertReceived(alert::CertificateRevoked).into(),
        AlertCertificateExpired => Error::AlertReceived(alert::CertificateExpired).into(),
        AlertCertificateUnknown => Error::AlertReceived(alert::CertificateUnknown).into(),
        AlertIllegalParameter => Error::AlertReceived(alert::IllegalParameter).into(),
        AlertUnknownCA => Error::AlertReceived(alert::UnknownCA).into(),
        AlertAccessDenied => Error::AlertReceived(alert::AccessDenied).into(),
        AlertDecodeError => Error::AlertReceived(alert::DecodeError).into(),
        AlertDecryptError => Error::AlertReceived(alert::DecryptError).into(),
        AlertExportRestriction => Error::AlertReceived(alert::ExportRestriction).into(),
        AlertProtocolVersion => Error::AlertReceived(alert::ProtocolVersion).into(),
        AlertInsufficientSecurity => Error::AlertReceived(alert::InsufficientSecurity).into(),
        AlertInternalError => Error::AlertReceived(alert::InternalError).into(),
        AlertInappropriateFallback => Error::AlertReceived(alert::InappropriateFallback).into(),
        AlertUserCanceled => Error::AlertReceived(alert::UserCanceled).into(),
        AlertNoRenegotiation => Error::AlertReceived(alert::NoRenegotiation).into(),
        AlertMissingExtension => Error::AlertReceived(alert::MissingExtension).into(),
        AlertUnsupportedExtension => Error::AlertReceived(alert::UnsupportedExtension).into(),
        AlertCertificateUnobtainable => Error::AlertReceived(alert::CertificateUnobtainable).into(),
        AlertUnrecognisedName => Error::AlertReceived(alert::UnrecognisedName).into(),
        AlertBadCertificateStatusResponse => {
            Error::AlertReceived(alert::BadCertificateStatusResponse).into()
        }
        AlertBadCertificateHashValue => Error::AlertReceived(alert::BadCertificateHashValue).into(),
        AlertUnknownPSKIdentity => Error::AlertReceived(alert::UnknownPSKIdentity).into(),
        AlertCertificateRequired => Error::AlertReceived(alert::CertificateRequired).into(),
        AlertNoApplicationProtocol => Error::AlertReceived(alert::NoApplicationProtocol).into(),
        AlertUnknown => Error::AlertReceived(alert::Unknown(0)).into(),

        CertSCTMalformed => Error::InvalidSct(sct::MalformedSct).into(),
        CertSCTInvalidSignature => Error::InvalidSct(sct::InvalidSignature).into(),
        CertSCTTimestampInFuture => Error::InvalidSct(sct::TimestampInFuture).into(),
        CertSCTUnsupportedVersion => Error::InvalidSct(sct::UnsupportedSctVersion).into(),
        CertSCTUnknownLog => Error::InvalidSct(sct::UnknownLog).into(),
    }
}
