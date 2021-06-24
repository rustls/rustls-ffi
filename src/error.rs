use std::{cmp::min, fmt::Display, slice};

use crate::ffi_panic_boundary;
use libc::{c_char, size_t};
use rustls::Error;

/// A return value for a function that may return either success (0) or a
/// non-zero value representing an error.
#[repr(transparent)]
pub struct rustls_io_result(pub libc::c_int);

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
    match result_to_error(&result) {
        Either::Error(Error::WebPkiError(_, _)) => true,
        Either::Error(Error::InvalidSct(_)) => true,
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

    // From https://docs.rs/rustls/0.19.0/rustls/enum.TlsError.html
    CorruptMessage = 7100,
    NoCertificatesPresented = 7101,
    DecryptError = 7102,
    FailedToGetCurrentTime = 7103,
    FailedToGetRandomBytes = 7113,
    HandshakeNotComplete = 7104,
    PeerSentOversizedRecord = 7105,
    NoApplicationProtocol = 7106,
    BadMaxFragmentSize = 7114, // Last added

    // From Error, with fields that get dropped.
    PeerIncompatibleError = 7107,
    PeerMisbehavedError = 7108,
    InappropriateMessage = 7109,
    InappropriateHandshakeMessage = 7110,
    CorruptMessagePayload = 7111,
    General = 7112,

    // From Error, with fields that get flattened.
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
    CertBadEncoding = 7300,
    CertBadTimeEncoding = 7301,
    CertCAUsedAsEndEntity = 7302,
    CertExpired = 7303,
    CertNotValidForName = 7304,
    CertNotValidYet = 7305,
    CertEndEntityUsedAsCA = 7306,
    CertExtensionValueInvalid = 7307,
    CertInvalidCertValidity = 7308,
    CertInvalidSignatureForPublicKey = 7309,
    CertMissingOrMalformedExtensions = 7324,
    CertNameConstraintViolation = 7310,
    CertPathLenConstraintViolation = 7311,
    CertSignatureAlgorithmMismatch = 7312,
    CertRequiredEKUNotFound = 7313,
    CertUnknownIssuer = 7314,
    CertUnsupportedCertVersion = 7315,
    CertUnsupportedCriticalExtension = 7316,
    CertUnsupportedSignatureAlgorithmForPublicKey = 7317,
    CertUnsupportedSignatureAlgorithm = 7318,
    CertUnknownError = 7325, // Last added

    // https://docs.rs/sct/0.5.0/sct/enum.Error.html
    CertSCTMalformed = 7319,
    CertSCTInvalidSignature = 7320,
    CertSCTTimestampInFuture = 7321,
    CertSCTUnsupportedVersion = 7322,
    CertSCTUnknownLog = 7323,
}

pub(crate) fn map_error(input: rustls::Error) -> rustls_result {
    use rustls::internal::msgs::enums::AlertDescription as alert;
    use rustls::WebPkiError as webpki;
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

        Error::FailedToGetCurrentTime => FailedToGetCurrentTime,
        Error::FailedToGetRandomBytes => FailedToGetRandomBytes,
        Error::HandshakeNotComplete => HandshakeNotComplete,
        Error::PeerSentOversizedRecord => PeerSentOversizedRecord,
        Error::NoApplicationProtocol => NoApplicationProtocol,
        Error::BadMaxFragmentSize => BadMaxFragmentSize,

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
        Error::WebPkiError(e, _) => match e {
            webpki::BadEncoding => CertBadEncoding,
            webpki::BadTimeEncoding => CertBadTimeEncoding,
            webpki::CaUsedAsEndEntity => CertCAUsedAsEndEntity,
            webpki::CertExpired => CertExpired,
            webpki::CertNotValidForName => CertNotValidForName,
            webpki::CertNotValidYet => CertNotValidYet,
            webpki::EndEntityUsedAsCa => CertEndEntityUsedAsCA,
            webpki::ExtensionValueInvalid => CertExtensionValueInvalid,
            webpki::InvalidCertValidity => CertInvalidCertValidity,
            webpki::InvalidSignatureForPublicKey => CertInvalidSignatureForPublicKey,
            webpki::NameConstraintViolation => CertNameConstraintViolation,
            webpki::PathLenConstraintViolation => CertPathLenConstraintViolation,
            webpki::SignatureAlgorithmMismatch => CertSignatureAlgorithmMismatch,
            webpki::RequiredEkuNotFound => CertRequiredEKUNotFound,
            webpki::UnknownIssuer => CertUnknownIssuer,
            webpki::UnsupportedCertVersion => CertUnsupportedCertVersion,
            webpki::UnsupportedCriticalExtension => CertUnsupportedCriticalExtension,
            webpki::UnsupportedSignatureAlgorithmForPublicKey => {
                CertUnsupportedSignatureAlgorithmForPublicKey
            }
            webpki::UnsupportedSignatureAlgorithm => CertUnsupportedSignatureAlgorithm,
            _ => CertUnknownError,
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

impl Into<Either> for String {
    fn into(self) -> Either {
        Either::String(self)
    }
}

impl Into<Either> for &str {
    fn into(self) -> Either {
        Either::String(self.to_string())
    }
}

impl Into<Either> for webpki::Error {
    fn into(self) -> Either {
        Either::String(self.to_string())
    }
}

impl Into<Either> for rustls::Error {
    fn into(self) -> Either {
        Either::Error(self)
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
    use webpki::Error as webpki;

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

        CertBadEncoding => webpki::BadDer.into(),
        CertBadTimeEncoding => webpki::BadDerTime.into(),
        CertCAUsedAsEndEntity => webpki::CaUsedAsEndEntity.into(),
        CertExpired => webpki::CertExpired.into(),
        CertNotValidForName => webpki::CertNotValidForName.into(),
        CertNotValidYet => webpki::CertNotValidYet.into(),
        CertEndEntityUsedAsCA => webpki::EndEntityUsedAsCa.into(),
        CertExtensionValueInvalid => webpki::ExtensionValueInvalid.into(),
        CertInvalidCertValidity => webpki::InvalidCertValidity.into(),
        CertInvalidSignatureForPublicKey => webpki::InvalidSignatureForPublicKey.into(),
        CertMissingOrMalformedExtensions => webpki::MissingOrMalformedExtensions.into(),
        CertNameConstraintViolation => webpki::NameConstraintViolation.into(),
        CertPathLenConstraintViolated => webpki::PathLenConstraintViolated.into(),
        CertSignatureAlgorithmMismatch => webpki::SignatureAlgorithmMismatch.into(),
        CertRequiredEKUNotFound => webpki::RequiredEkuNotFound.into(),
        CertUnknownIssuer => webpki::UnknownIssuer.into(),
        CertUnsupportedCertVersion => webpki::UnsupportedCertVersion.into(),
        CertUnsupportedCriticalExtension => {
            webpki::UnsupportedCriticalExtension.into()
        }
        CertUnsupportedSignatureAlgorithmForPublicKey => {
            webpki::UnsupportedSignatureAlgorithmForPublicKey.into()
        }
        CertUnsupportedSignatureAlgorithm => {
            webpki::UnsupportedSignatureAlgorithm.into()
        }

        CertSCTMalformed => Error::InvalidSct(sct::MalformedSct).into(),
        CertSCTInvalidSignature => Error::InvalidSct(sct::InvalidSignature).into(),
        CertSCTTimestampInFuture => Error::InvalidSct(sct::TimestampInFuture).into(),
        CertSCTUnsupportedVersion => Error::InvalidSct(sct::UnsupportedSctVersion).into(),
        CertSCTUnknownLog => Error::InvalidSct(sct::UnknownLog).into(),
    }
}
