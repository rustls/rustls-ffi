use std::{cmp::min, fmt::Display, slice};

use crate::ffi_panic_boundary;
use libc::{c_char, size_t};
use rustls::Error;

/// After a rustls_client_session method returns an error, you may call
/// this method to get a pointer to a buffer containing a detailed error
/// message. The contents of the error buffer will be out_n bytes long,
/// UTF-8 encoded, and not NUL-terminated.
#[no_mangle]
pub extern "C" fn rustls_error(
    result: rustls_result,
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
    match result_to_tlserror(&result) {
        Either::TLSError(Error::WebPkiError(_, _)) => true,
        Either::TLSError(Error::InvalidSct(_)) => true,
        _ => false,
    }
}

#[allow(dead_code)]
#[repr(C)]
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

    // From https://docs.rs/rustls/0.19.0/rustls/enum.TLSError.html
    CorruptMessage = 7100,
    NoCertificatesPresented = 7101,
    DecryptError = 7102,
    FailedToGetCurrentTime = 7103,
    FailedToGetRandomBytes = 7113, // Last added
    HandshakeNotComplete = 7104,
    PeerSentOversizedRecord = 7105,
    NoApplicationProtocol = 7106,

    // From TLSError, with fields that get dropped.
    PeerIncompatibleError = 7107,
    PeerMisbehavedError = 7108,
    InappropriateMessage = 7109,
    InappropriateHandshakeMessage = 7110,
    CorruptMessagePayload = 7111,
    General = 7112,

    // From TLSError, with fields that get flattened.
    // https://docs.rs/rustls/0.19.0/rustls/internal/msgs/enums/enum.AlertDescription.html
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

    // https://docs.rs/webpki/0.21.4/webpki/enum.Error.html
    CertBadDER = 7300,
    CertBadDERTime = 7301,
    CertCAUsedAsEndEntity = 7302,
    CertExpired = 7303,
    CertNotValidForName = 7304,
    CertNotValidYet = 7305,
    CertEndEntityUsedAsCA = 7306,
    CertExtensionValueInvalid = 7307,
    CertInvalidCertValidity = 7308,
    CertInvalidSignatureForPublicKey = 7309,
    CertMissingOrMalformedExtensions = 7324, // Last added
    CertNameConstraintViolation = 7310,
    CertPathLenConstraintViolated = 7311,
    CertSignatureAlgorithmMismatch = 7312,
    CertRequiredEKUNotFound = 7313,
    CertUnknownIssuer = 7314,
    CertUnsupportedCertVersion = 7315,
    CertUnsupportedCriticalExtension = 7316,
    CertUnsupportedSignatureAlgorithmForPublicKey = 7317,
    CertUnsupportedSignatureAlgorithm = 7318,

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
    use webpki::Error as webpki;

    match input {
        Error::CorruptMessage => CorruptMessage,
        Error::NoCertificatesPresented => NoCertificatesPresented,
        Error::DecryptError => DecryptError,
        Error::FailedToGetCurrentTime => FailedToGetCurrentTime,
        Error::HandshakeNotComplete => HandshakeNotComplete,
        Error::PeerSentOversizedRecord => PeerSentOversizedRecord,
        Error::NoApplicationProtocol => NoApplicationProtocol,

        Error::PeerIncompatibleError(_) => PeerIncompatibleError,
        Error::PeerMisbehavedError(_) => PeerMisbehavedError,
        Error::General(_) => General,
        Error::InappropriateMessage { .. } => InappropriateMessage,
        Error::InappropriateHandshakeMessage { .. } => InappropriateHandshakeMessage,
        Error::CorruptMessagePayload(_) => CorruptMessagePayload,

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
        Error::WebPkiError(e, op) => match e {
            webpki::BadDer => CertBadDER,
            webpki::BadDerTime => CertBadDERTime,
            webpki::CaUsedAsEndEntity => CertCAUsedAsEndEntity,
            webpki::CertExpired => CertExpired,
            webpki::CertNotValidForName => CertNotValidForName,
            webpki::CertNotValidYet => CertNotValidYet,
            webpki::EndEntityUsedAsCa => CertEndEntityUsedAsCA,
            webpki::ExtensionValueInvalid => CertExtensionValueInvalid,
            webpki::InvalidCertValidity => CertInvalidCertValidity,
            webpki::InvalidSignatureForPublicKey => CertInvalidSignatureForPublicKey,
            webpki::MissingOrMalformedExtensions => CertMissingOrMalformedExtensions,
            webpki::NameConstraintViolation => CertNameConstraintViolation,
            webpki::PathLenConstraintViolated => CertPathLenConstraintViolated,
            webpki::SignatureAlgorithmMismatch => CertSignatureAlgorithmMismatch,
            webpki::RequiredEkuNotFound => CertRequiredEKUNotFound,
            webpki::UnknownIssuer => CertUnknownIssuer,
            webpki::UnsupportedCertVersion => CertUnsupportedCertVersion,
            webpki::UnsupportedCriticalExtension => CertUnsupportedCriticalExtension,
            webpki::UnsupportedSignatureAlgorithmForPublicKey => {
                CertUnsupportedSignatureAlgorithmForPublicKey
            }
            webpki::UnsupportedSignatureAlgorithm => CertUnsupportedSignatureAlgorithm,
        },
        Error::InvalidSct(e) => match e {
            sct::MalformedSct => CertSCTMalformed,
            sct::InvalidSignature => CertSCTInvalidSignature,
            sct::TimestampInFuture => CertSCTTimestampInFuture,
            sct::UnsupportedSctVersion => CertSCTUnsupportedVersion,
            sct::UnknownLog => CertSCTUnknownLog,
        },
        Error::FailedToGetRandomBytes => FailedToGetRandomBytes,
    }
}

impl Display for rustls_result {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg: String = match result_to_tlserror(self) {
            Either::String(s) => s,
            Either::TLSError(e) => e.to_string(),
        };
        write!(f, "{}", msg)
    }
}

// Either a String or a TLSError
pub(crate) enum Either {
    String(String),
    TLSError(Error),
}

// Turn a rustls_result into a TLSError on a best-effort basis. For
// variants that don't have a corresponding TLSError, or where we want to
// override TLSError's Display implementation, this returns a String.
// Otherwise, it returns a TLSError. This is used internally for determining
// whether a rustls_result is part of some top-level variant that maps to
// several rustls_results.
pub(crate) fn result_to_tlserror(input: &rustls_result) -> Either {
    use rustls::internal::msgs::enums::AlertDescription as alert;
    use rustls_result::*;
    use sct::Error as sct;
    use webpki::Error as webpki;

    match input {
        // These variants are local to this glue layer.
        rustls_result::Ok => return Either::String("OK".to_string()),
        Io => return Either::String("I/O error".to_string()),
        NullParameter => return Either::String("a parameter was NULL".to_string()),
        InvalidDnsNameError => return Either::String(
            "hostname was either malformed or an IP address (rustls does not support certificates for IP addresses)".to_string()),
        Panic => return Either::String("a Rust component panicked".to_string()),
        CertificateParseError => return Either::String("error parsing certificate".to_string()),
        PrivateKeyParseError => return Either::String("error parsing private key".to_string()),
        InsufficientSize => return Either::String("provided buffer is of insufficient size".to_string()),
        NotFound => return Either::String("the item was not found".to_string()),
        InvalidParameter => return Either::String("a parameter had an invalid value".to_string()),

        // These variants correspond to a TLSError variant with a field,
        // where generating an arbitrary field would produce a confusing error
        // message. So we reproduce a simplified error string.
        InappropriateMessage => {
            return Either::String("received unexpected message".to_string());
        }
        InappropriateHandshakeMessage => {
            return Either::String("received unexpected handshake message".to_string());
        }
        CorruptMessagePayload => return Either::String("received corrupt message".to_string()),
        _ => {}
    };

    let e: Error = match input {
        rustls_result::Ok => unreachable!(),
        Io => unreachable!(),
        NullParameter => unreachable!(),
        InvalidDnsNameError => unreachable!(),
        Panic => unreachable!(),
        CertificateParseError => unreachable!(),
        PrivateKeyParseError => unreachable!(),
        InsufficientSize => unreachable!(),
        NotFound => unreachable!(),
        InvalidParameter => unreachable!(),

        InappropriateMessage => unreachable!(),
        InappropriateHandshakeMessage => unreachable!(),
        CorruptMessagePayload => unreachable!(),

        CorruptMessage => Error::CorruptMessage,
        NoCertificatesPresented => Error::NoCertificatesPresented,
        DecryptError => Error::DecryptError,
        FailedToGetCurrentTime => Error::FailedToGetCurrentTime,
        FailedToGetRandomBytes => Error::FailedToGetRandomBytes,
        HandshakeNotComplete => Error::HandshakeNotComplete,
        PeerSentOversizedRecord => Error::PeerSentOversizedRecord,
        NoApplicationProtocol => Error::NoApplicationProtocol,
        PeerIncompatibleError => Error::PeerIncompatibleError("reason omitted".to_string()),
        PeerMisbehavedError => Error::PeerMisbehavedError("reason omitted".to_string()),
        General => Error::General("omitted".to_string()),

        AlertCloseNotify => Error::AlertReceived(alert::CloseNotify),
        AlertUnexpectedMessage => Error::AlertReceived(alert::UnexpectedMessage),
        AlertBadRecordMac => Error::AlertReceived(alert::BadRecordMac),
        AlertDecryptionFailed => Error::AlertReceived(alert::DecryptionFailed),
        AlertRecordOverflow => Error::AlertReceived(alert::RecordOverflow),
        AlertDecompressionFailure => Error::AlertReceived(alert::DecompressionFailure),
        AlertHandshakeFailure => Error::AlertReceived(alert::HandshakeFailure),
        AlertNoCertificate => Error::AlertReceived(alert::NoCertificate),
        AlertBadCertificate => Error::AlertReceived(alert::BadCertificate),
        AlertUnsupportedCertificate => Error::AlertReceived(alert::UnsupportedCertificate),
        AlertCertificateRevoked => Error::AlertReceived(alert::CertificateRevoked),
        AlertCertificateExpired => Error::AlertReceived(alert::CertificateExpired),
        AlertCertificateUnknown => Error::AlertReceived(alert::CertificateUnknown),
        AlertIllegalParameter => Error::AlertReceived(alert::IllegalParameter),
        AlertUnknownCA => Error::AlertReceived(alert::UnknownCA),
        AlertAccessDenied => Error::AlertReceived(alert::AccessDenied),
        AlertDecodeError => Error::AlertReceived(alert::DecodeError),
        AlertDecryptError => Error::AlertReceived(alert::DecryptError),
        AlertExportRestriction => Error::AlertReceived(alert::ExportRestriction),
        AlertProtocolVersion => Error::AlertReceived(alert::ProtocolVersion),
        AlertInsufficientSecurity => Error::AlertReceived(alert::InsufficientSecurity),
        AlertInternalError => Error::AlertReceived(alert::InternalError),
        AlertInappropriateFallback => Error::AlertReceived(alert::InappropriateFallback),
        AlertUserCanceled => Error::AlertReceived(alert::UserCanceled),
        AlertNoRenegotiation => Error::AlertReceived(alert::NoRenegotiation),
        AlertMissingExtension => Error::AlertReceived(alert::MissingExtension),
        AlertUnsupportedExtension => Error::AlertReceived(alert::UnsupportedExtension),
        AlertCertificateUnobtainable => Error::AlertReceived(alert::CertificateUnobtainable),
        AlertUnrecognisedName => Error::AlertReceived(alert::UnrecognisedName),
        AlertBadCertificateStatusResponse => {
            Error::AlertReceived(alert::BadCertificateStatusResponse)
        }
        AlertBadCertificateHashValue => Error::AlertReceived(alert::BadCertificateHashValue),
        AlertUnknownPSKIdentity => Error::AlertReceived(alert::UnknownPSKIdentity),
        AlertCertificateRequired => Error::AlertReceived(alert::CertificateRequired),
        AlertNoApplicationProtocol => Error::AlertReceived(alert::NoApplicationProtocol),
        AlertUnknown => Error::AlertReceived(alert::Unknown(0)),

        CertBadDER => Error::WebPkiError(webpki::BadDer),
        CertBadDERTime => Error::WebPkiError(webpki::BadDERTime),
        CertCAUsedAsEndEntity => Error::WebPkiError(webpki::CAUsedAsEndEntity),
        CertExpired => Error::WebPkiError(webpki::CertExpired),
        CertNotValidForName => Error::WebPkiError(webpki::CertNotValidForName),
        CertNotValidYet => Error::WebPkiError(webpki::CertNotValidYet),
        CertEndEntityUsedAsCA => Error::WebPkiError(webpki::EndEntityUsedAsCA),
        CertExtensionValueInvalid => Error::WebPkiError(webpki::ExtensionValueInvalid),
        CertInvalidCertValidity => Error::WebPkiError(webpki::InvalidCertValidity),
        CertInvalidSignatureForPublicKey => {
            Error::WebPkiError(webpki::InvalidSignatureForPublicKey)
        }
        CertMissingOrMalformedExtensions => Error::WebPkiError(webpki::MissingOrMalformedExtensions),
        CertNameConstraintViolation => Error::WebPkiError(webpki::NameConstraintViolation),
        CertPathLenConstraintViolated => Error::WebPkiError(webpki::PathLenConstraintViolated),
        CertSignatureAlgorithmMismatch => Error::WebPkiError(webpki::SignatureAlgorithmMismatch),
        CertRequiredEKUNotFound => Error::WebPkiError(webpki::RequiredEKUNotFound),
        CertUnknownIssuer => Error::WebPkiError(webpki::UnknownIssuer),
        CertUnsupportedCertVersion => Error::WebPkiError(webpki::UnsupportedCertVersion),
        CertUnsupportedCriticalExtension => {
            Error::WebPkiError(webpki::UnsupportedCriticalExtension)
        }
        CertUnsupportedSignatureAlgorithmForPublicKey => {
            Error::WebPkiError(webpki::UnsupportedSignatureAlgorithmForPublicKey)
        }
        CertUnsupportedSignatureAlgorithm => {
            Error::WebPkiError(webpki::UnsupportedSignatureAlgorithm)
        }

        CertSCTMalformed => Error::InvalidSCT(sct::MalformedSCT),
        CertSCTInvalidSignature => Error::InvalidSCT(sct::InvalidSignature),
        CertSCTTimestampInFuture => Error::InvalidSCT(sct::TimestampInFuture),
        CertSCTUnsupportedVersion => Error::InvalidSCT(sct::UnsupportedSCTVersion),
        CertSCTUnknownLog => Error::InvalidSCT(sct::UnknownLog),
    };
    Either::TLSError(e)
}
