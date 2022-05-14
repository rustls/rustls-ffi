use std::cmp::min;
use std::convert::TryFrom;
use std::fmt::Display;

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
            if buf.is_null() {
                return
            }
            if out_n.is_null() {
                return
            }
            let result: rustls_result = rustls_result::try_from(result).unwrap_or(rustls_result::InvalidParameter);
            let error_str = result.to_string();
            let out_len: usize = min(len - 1, error_str.len());
            unsafe {
                std::ptr::copy_nonoverlapping(error_str.as_ptr() as *mut c_char, buf, out_len);
                *out_n = out_len;
            }
        }
    }

    #[no_mangle]
    pub extern "C" fn rustls_result_is_cert_error(result: c_uint) -> bool {
        let result: rustls_result =
            rustls_result::try_from(result).unwrap_or(rustls_result::InvalidParameter);
        use rustls_result::*;
        matches!(
            result,
            CertInvalidEncoding
                | CertInvalidSignatureType
                | CertInvalidSignature
                | CertInvalidData
                | CertSCTMalformed
                | CertSCTInvalidSignature
                | CertSCTTimestampInFuture
                | CertSCTUnsupportedVersion
                | CertSCTUnknownLog
        )
    }
}

/// For cert-related rustls_results, turn them into a rustls::Error. For other
/// inputs, including Ok, return rustls::Error::General.
pub(crate) fn cert_result_to_error(result: rustls_result) -> rustls::Error {
    use rustls::Error::*;
    use rustls_result::*;
    match result {
        CertInvalidEncoding => InvalidCertificateEncoding,
        CertInvalidSignatureType => InvalidCertificateSignatureType,
        CertInvalidSignature => InvalidCertificateSignature,
        CertInvalidData => InvalidCertificateData("".into()),
        CertSCTMalformed => InvalidSct(sct::Error::MalformedSct),
        CertSCTInvalidSignature => InvalidSct(sct::Error::InvalidSignature),
        CertSCTTimestampInFuture => InvalidSct(sct::Error::TimestampInFuture),
        CertSCTUnsupportedVersion => InvalidSct(sct::Error::UnsupportedSctVersion),
        CertSCTUnknownLog => InvalidSct(sct::Error::UnknownLog),
        _ => rustls::Error::General("".into()),
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

#[test]
fn test_rustls_result_is_cert_error() {
    assert!(!rustls_result::rustls_result_is_cert_error(0));
    assert!(!rustls_result::rustls_result_is_cert_error(7000));
    assert!(rustls_result::rustls_result_is_cert_error(7117));
    assert!(rustls_result::rustls_result_is_cert_error(7118));
    assert!(rustls_result::rustls_result_is_cert_error(7119));
    assert!(rustls_result::rustls_result_is_cert_error(7120));
    assert!(rustls_result::rustls_result_is_cert_error(7319));
    assert!(rustls_result::rustls_result_is_cert_error(7320));
    assert!(rustls_result::rustls_result_is_cert_error(7321));
    assert!(rustls_result::rustls_result_is_cert_error(7322));
    assert!(rustls_result::rustls_result_is_cert_error(7323));
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
    AlreadyUsed = 7013,

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
        use rustls::internal::msgs::enums::AlertDescription as alert;
        use rustls_result::*;
        use sct::Error as sct;

        match self {
        // These variants are local to this glue layer.
        rustls_result::Ok =>  write!(f, "OK"),
        Io =>  write!(f, "I/O error"),
        NullParameter => write!(f, "a parameter was NULL"),
        InvalidDnsNameError => write!(f, "hostname was either malformed or an IP address (rustls does not support certificates for IP addresses)"),
        Panic => write!(f, "a Rust component panicked"),
        CertificateParseError => write!(f, "error parsing certificate"),
        PrivateKeyParseError => write!(f, "error parsing private key"),
        InsufficientSize => write!(f, "provided buffer is of insufficient size"),
        NotFound => write!(f, "the item was not found"),
        InvalidParameter => write!(f, "a parameter had an invalid value"),
        CertInvalidData => write!(f, "invalid certificate data found"),
        UnexpectedEof => write!(f,  "unexpected EOF"),
        PlaintextEmpty => write!(f,  "no plaintext available; call rustls_connection_read_tls again"),
        AlreadyUsed => write!(f, "tried to use a rustls struct after it had been converted to another struct"),

        // These variants correspond to a rustls::Error variant with a field,
        // where generating an arbitrary field would produce a confusing error
        // message. So we reproduce a simplified error string.
        InappropriateMessage => write!(f, "received unexpected message"),
        InappropriateHandshakeMessage => write!(f, "received unexpected handshake message"),
        CorruptMessagePayload => write!(f, "received corrupt message"),

        PeerIncompatibleError => write!(f, "peer is incompatible"),
        PeerMisbehavedError => write!(f, "peer misbehaved"),

        General => write!(f, "general error"),

        CorruptMessage => Error::CorruptMessage.fmt(f),
        NoCertificatesPresented => Error::NoCertificatesPresented.fmt(f),
        DecryptError => Error::DecryptError.fmt(f),
        FailedToGetCurrentTime => Error::FailedToGetCurrentTime.fmt(f),
        FailedToGetRandomBytes => Error::FailedToGetRandomBytes.fmt(f),
        HandshakeNotComplete => Error::HandshakeNotComplete.fmt(f),
        PeerSentOversizedRecord => Error::PeerSentOversizedRecord.fmt(f),
        NoApplicationProtocol => Error::NoApplicationProtocol.fmt(f),
        BadMaxFragmentSize => Error::BadMaxFragmentSize.fmt(f),
        UnsupportedNameType => Error::UnsupportedNameType.fmt(f),
        EncryptError => Error::EncryptError.fmt(f),
        CertInvalidEncoding => Error::InvalidCertificateEncoding.fmt(f),
        CertInvalidSignatureType => Error::InvalidCertificateSignatureType.fmt(f),
        CertInvalidSignature => Error::InvalidCertificateSignature.fmt(f),

        AlertCloseNotify => Error::AlertReceived(alert::CloseNotify).fmt(f),
        AlertUnexpectedMessage => Error::AlertReceived(alert::UnexpectedMessage).fmt(f),
        AlertBadRecordMac => Error::AlertReceived(alert::BadRecordMac).fmt(f),
        AlertDecryptionFailed => Error::AlertReceived(alert::DecryptionFailed).fmt(f),
        AlertRecordOverflow => Error::AlertReceived(alert::RecordOverflow).fmt(f),
        AlertDecompressionFailure => Error::AlertReceived(alert::DecompressionFailure).fmt(f),
        AlertHandshakeFailure => Error::AlertReceived(alert::HandshakeFailure).fmt(f),
        AlertNoCertificate => Error::AlertReceived(alert::NoCertificate).fmt(f),
        AlertBadCertificate => Error::AlertReceived(alert::BadCertificate).fmt(f),
        AlertUnsupportedCertificate => Error::AlertReceived(alert::UnsupportedCertificate).fmt(f),
        AlertCertificateRevoked => Error::AlertReceived(alert::CertificateRevoked).fmt(f),
        AlertCertificateExpired => Error::AlertReceived(alert::CertificateExpired).fmt(f),
        AlertCertificateUnknown => Error::AlertReceived(alert::CertificateUnknown).fmt(f),
        AlertIllegalParameter => Error::AlertReceived(alert::IllegalParameter).fmt(f),
        AlertUnknownCA => Error::AlertReceived(alert::UnknownCA).fmt(f),
        AlertAccessDenied => Error::AlertReceived(alert::AccessDenied).fmt(f),
        AlertDecodeError => Error::AlertReceived(alert::DecodeError).fmt(f),
        AlertDecryptError => Error::AlertReceived(alert::DecryptError).fmt(f),
        AlertExportRestriction => Error::AlertReceived(alert::ExportRestriction).fmt(f),
        AlertProtocolVersion => Error::AlertReceived(alert::ProtocolVersion).fmt(f),
        AlertInsufficientSecurity => Error::AlertReceived(alert::InsufficientSecurity).fmt(f),
        AlertInternalError => Error::AlertReceived(alert::InternalError).fmt(f),
        AlertInappropriateFallback => Error::AlertReceived(alert::InappropriateFallback).fmt(f),
        AlertUserCanceled => Error::AlertReceived(alert::UserCanceled).fmt(f),
        AlertNoRenegotiation => Error::AlertReceived(alert::NoRenegotiation).fmt(f),
        AlertMissingExtension => Error::AlertReceived(alert::MissingExtension).fmt(f),
        AlertUnsupportedExtension => Error::AlertReceived(alert::UnsupportedExtension).fmt(f),
        AlertCertificateUnobtainable => Error::AlertReceived(alert::CertificateUnobtainable).fmt(f),
        AlertUnrecognisedName => Error::AlertReceived(alert::UnrecognisedName).fmt(f),
        AlertBadCertificateStatusResponse => {
            Error::AlertReceived(alert::BadCertificateStatusResponse).fmt(f)
        }
        AlertBadCertificateHashValue => Error::AlertReceived(alert::BadCertificateHashValue).fmt(f),
        AlertUnknownPSKIdentity => Error::AlertReceived(alert::UnknownPSKIdentity).fmt(f),
        AlertCertificateRequired => Error::AlertReceived(alert::CertificateRequired).fmt(f),
        AlertNoApplicationProtocol => Error::AlertReceived(alert::NoApplicationProtocol).fmt(f),
        AlertUnknown => Error::AlertReceived(alert::Unknown(0)).fmt(f),

        CertSCTMalformed => Error::InvalidSct(sct::MalformedSct).fmt(f),
        CertSCTInvalidSignature => Error::InvalidSct(sct::InvalidSignature).fmt(f),
        CertSCTTimestampInFuture => Error::InvalidSct(sct::TimestampInFuture).fmt(f),
        CertSCTUnsupportedVersion => Error::InvalidSct(sct::UnsupportedSctVersion).fmt(f),
        CertSCTUnknownLog => Error::InvalidSct(sct::UnknownLog).fmt(f),
        }
    }
}
