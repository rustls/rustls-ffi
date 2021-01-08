use std::{cmp::min, fmt::Display, slice};

use libc::{c_char, size_t};
use rustls::TLSError;

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

#[no_mangle]
pub extern "C" fn rustls_result_is_cert_error(result: rustls_result) -> bool {
    match result_to_tlserror(&result) {
        Either::TLSError(TLSError::WebPKIError(_)) => true,
        Either::TLSError(TLSError::InvalidSCT(_)) => true,
        _ => false,
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub enum rustls_result {
    Ok = 7000,
    Io,
    NullParameter,

    // From https://docs.rs/rustls/0.19.0/rustls/enum.TLSError.html
    CorruptMessage,
    NoCertificatesPresented,
    DecryptError,
    FailedToGetCurrentTime,
    HandshakeNotComplete,
    PeerSentOversizedRecord,
    NoApplicationProtocol,

    // From TLSError, with fields that get dropped.
    PeerIncompatibleError,
    PeerMisbehavedError,
    InappropriateMessage,
    InappropriateHandshakeMessage,
    CorruptMessagePayload,
    General,

    // From TLSError, with fields that get flattened.
    // https://docs.rs/rustls/0.19.0/rustls/internal/msgs/enums/enum.AlertDescription.html
    AlertCloseNotify,
    AlertUnexpectedMessage,
    AlertBadRecordMac,
    AlertDecryptionFailed,
    AlertRecordOverflow,
    AlertDecompressionFailure,
    AlertHandshakeFailure,
    AlertNoCertificate,
    AlertBadCertificate,
    AlertUnsupportedCertificate,
    AlertCertificateRevoked,
    AlertCertificateExpired,
    AlertCertificateUnknown,
    AlertIllegalParameter,
    AlertUnknownCA,
    AlertAccessDenied,
    AlertDecodeError,
    AlertDecryptError,
    AlertExportRestriction,
    AlertProtocolVersion,
    AlertInsufficientSecurity,
    AlertInternalError,
    AlertInappropriateFallback,
    AlertUserCanceled,
    AlertNoRenegotiation,
    AlertMissingExtension,
    AlertUnsupportedExtension,
    AlertCertificateUnobtainable,
    AlertUnrecognisedName,
    AlertBadCertificateStatusResponse,
    AlertBadCertificateHashValue,
    AlertUnknownPSKIdentity,
    AlertCertificateRequired,
    AlertNoApplicationProtocol,
    AlertUnknown,

    // https://docs.rs/webpki/0.21.4/webpki/enum.Error.html
    CertBadDER,
    CertBadDERTime,
    CertCAUsedAsEndEntity,
    CertExpired,
    CertNotValidForName,
    CertNotValidYet,
    CertEndEntityUsedAsCA,
    CertExtensionValueInvalid,
    CertInvalidCertValidity,
    CertInvalidSignatureForPublicKey,
    CertNameConstraintViolation,
    CertPathLenConstraintViolated,
    CertSignatureAlgorithmMismatch,
    CertRequiredEKUNotFound,
    CertUnknownIssuer,
    CertUnsupportedCertVersion,
    CertUnsupportedCriticalExtension,
    CertUnsupportedSignatureAlgorithmForPublicKey,
    CertUnsupportedSignatureAlgorithm,

    // https://docs.rs/sct/0.5.0/sct/enum.Error.html
    CertSCTMalformed,
    CertSCTInvalidSignature,
    CertSCTTimestampInFuture,
    CertSCTUnsupportedVersion,
    CertSCTUnknownLog,
}

pub(crate) fn map_error(input: rustls::TLSError) -> rustls_result {
    use rustls::internal::msgs::enums::AlertDescription as alert;
    use rustls_result::*;
    use sct::Error as sct;
    use webpki::Error as webpki;

    match input {
        TLSError::CorruptMessage => CorruptMessage,
        TLSError::NoCertificatesPresented => NoCertificatesPresented,
        TLSError::DecryptError => DecryptError,
        TLSError::FailedToGetCurrentTime => FailedToGetCurrentTime,
        TLSError::HandshakeNotComplete => HandshakeNotComplete,
        TLSError::PeerSentOversizedRecord => PeerSentOversizedRecord,
        TLSError::NoApplicationProtocol => NoApplicationProtocol,

        TLSError::PeerIncompatibleError(_) => PeerIncompatibleError,
        TLSError::PeerMisbehavedError(_) => PeerMisbehavedError,
        TLSError::General(_) => General,
        TLSError::InappropriateMessage { .. } => InappropriateMessage,
        TLSError::InappropriateHandshakeMessage { .. } => InappropriateHandshakeMessage,
        TLSError::CorruptMessagePayload(_) => CorruptMessagePayload,

        TLSError::AlertReceived(e) => match e {
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
        TLSError::WebPKIError(e) => match e {
            webpki::BadDER => CertBadDER,
            webpki::BadDERTime => CertBadDERTime,
            webpki::CAUsedAsEndEntity => CertCAUsedAsEndEntity,
            webpki::CertExpired => CertExpired,
            webpki::CertNotValidForName => CertNotValidForName,
            webpki::CertNotValidYet => CertNotValidYet,
            webpki::EndEntityUsedAsCA => CertEndEntityUsedAsCA,
            webpki::ExtensionValueInvalid => CertExtensionValueInvalid,
            webpki::InvalidCertValidity => CertInvalidCertValidity,
            webpki::InvalidSignatureForPublicKey => CertInvalidSignatureForPublicKey,
            webpki::NameConstraintViolation => CertNameConstraintViolation,
            webpki::PathLenConstraintViolated => CertPathLenConstraintViolated,
            webpki::SignatureAlgorithmMismatch => CertSignatureAlgorithmMismatch,
            webpki::RequiredEKUNotFound => CertRequiredEKUNotFound,
            webpki::UnknownIssuer => CertUnknownIssuer,
            webpki::UnsupportedCertVersion => CertUnsupportedCertVersion,
            webpki::UnsupportedCriticalExtension => CertUnsupportedCriticalExtension,
            webpki::UnsupportedSignatureAlgorithmForPublicKey => {
                CertUnsupportedSignatureAlgorithmForPublicKey
            }
            webpki::UnsupportedSignatureAlgorithm => CertUnsupportedSignatureAlgorithm,
        },
        TLSError::InvalidSCT(e) => match e {
            sct::MalformedSCT => CertSCTMalformed,
            sct::InvalidSignature => CertSCTInvalidSignature,
            sct::TimestampInFuture => CertSCTTimestampInFuture,
            sct::UnsupportedSCTVersion => CertSCTUnsupportedVersion,
            sct::UnknownLog => CertSCTUnknownLog,
        },
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
enum Either {
    String(String),
    TLSError(TLSError),
}

// Turn a rustls_result into a TLSError on a best-effort basis. For
// variants that don't have a corresponding TLSError, or where we want to
// override TLSError's Display implementation, this returns a String.
// Otherwise, it returns a TLSError. This is used internally for determining
// whether a rustls_result is part of some top-level variant that maps to
// several rustls_results.
fn result_to_tlserror(input: &rustls_result) -> Either {
    use rustls::internal::msgs::enums::AlertDescription as alert;
    use rustls_result::*;
    use sct::Error as sct;
    use webpki::Error as webpki;

    match input {
        // These variants are local to this glue layer.
        rustls_result::Ok => return Either::String("OK".to_string()),
        Io => return Either::String("I/O error".to_string()),
        NullParameter => return Either::String("a parameter was NULL".to_string()),

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

    let e: TLSError = match input {
        rustls_result::Ok => unreachable!(),
        Io => unreachable!(),
        NullParameter => unreachable!(),

        InappropriateMessage => unreachable!(),
        InappropriateHandshakeMessage => unreachable!(),
        CorruptMessagePayload => unreachable!(),

        CorruptMessage => TLSError::CorruptMessage,
        NoCertificatesPresented => TLSError::NoCertificatesPresented,
        DecryptError => TLSError::DecryptError,
        FailedToGetCurrentTime => TLSError::FailedToGetCurrentTime,
        HandshakeNotComplete => TLSError::HandshakeNotComplete,
        PeerSentOversizedRecord => TLSError::PeerSentOversizedRecord,
        NoApplicationProtocol => TLSError::NoApplicationProtocol,
        PeerIncompatibleError => TLSError::PeerIncompatibleError("reason omitted".to_string()),
        PeerMisbehavedError => TLSError::PeerMisbehavedError("reason omitted".to_string()),
        General => TLSError::General("omitted".to_string()),

        AlertCloseNotify => TLSError::AlertReceived(alert::CloseNotify),
        AlertUnexpectedMessage => TLSError::AlertReceived(alert::UnexpectedMessage),
        AlertBadRecordMac => TLSError::AlertReceived(alert::BadRecordMac),
        AlertDecryptionFailed => TLSError::AlertReceived(alert::DecryptionFailed),
        AlertRecordOverflow => TLSError::AlertReceived(alert::RecordOverflow),
        AlertDecompressionFailure => TLSError::AlertReceived(alert::DecompressionFailure),
        AlertHandshakeFailure => TLSError::AlertReceived(alert::HandshakeFailure),
        AlertNoCertificate => TLSError::AlertReceived(alert::NoCertificate),
        AlertBadCertificate => TLSError::AlertReceived(alert::BadCertificate),
        AlertUnsupportedCertificate => TLSError::AlertReceived(alert::UnsupportedCertificate),
        AlertCertificateRevoked => TLSError::AlertReceived(alert::CertificateRevoked),
        AlertCertificateExpired => TLSError::AlertReceived(alert::CertificateExpired),
        AlertCertificateUnknown => TLSError::AlertReceived(alert::CertificateUnknown),
        AlertIllegalParameter => TLSError::AlertReceived(alert::IllegalParameter),
        AlertUnknownCA => TLSError::AlertReceived(alert::UnknownCA),
        AlertAccessDenied => TLSError::AlertReceived(alert::AccessDenied),
        AlertDecodeError => TLSError::AlertReceived(alert::DecodeError),
        AlertDecryptError => TLSError::AlertReceived(alert::DecryptError),
        AlertExportRestriction => TLSError::AlertReceived(alert::ExportRestriction),
        AlertProtocolVersion => TLSError::AlertReceived(alert::ProtocolVersion),
        AlertInsufficientSecurity => TLSError::AlertReceived(alert::InsufficientSecurity),
        AlertInternalError => TLSError::AlertReceived(alert::InternalError),
        AlertInappropriateFallback => TLSError::AlertReceived(alert::InappropriateFallback),
        AlertUserCanceled => TLSError::AlertReceived(alert::UserCanceled),
        AlertNoRenegotiation => TLSError::AlertReceived(alert::NoRenegotiation),
        AlertMissingExtension => TLSError::AlertReceived(alert::MissingExtension),
        AlertUnsupportedExtension => TLSError::AlertReceived(alert::UnsupportedExtension),
        AlertCertificateUnobtainable => TLSError::AlertReceived(alert::CertificateUnobtainable),
        AlertUnrecognisedName => TLSError::AlertReceived(alert::UnrecognisedName),
        AlertBadCertificateStatusResponse => {
            TLSError::AlertReceived(alert::BadCertificateStatusResponse)
        }
        AlertBadCertificateHashValue => TLSError::AlertReceived(alert::BadCertificateHashValue),
        AlertUnknownPSKIdentity => TLSError::AlertReceived(alert::UnknownPSKIdentity),
        AlertCertificateRequired => TLSError::AlertReceived(alert::CertificateRequired),
        AlertNoApplicationProtocol => TLSError::AlertReceived(alert::NoApplicationProtocol),
        AlertUnknown => TLSError::AlertReceived(alert::Unknown(0)),

        CertBadDER => TLSError::WebPKIError(webpki::BadDER),
        CertBadDERTime => TLSError::WebPKIError(webpki::BadDERTime),
        CertCAUsedAsEndEntity => TLSError::WebPKIError(webpki::CAUsedAsEndEntity),
        CertExpired => TLSError::WebPKIError(webpki::CertExpired),
        CertNotValidForName => TLSError::WebPKIError(webpki::CertNotValidForName),
        CertNotValidYet => TLSError::WebPKIError(webpki::CertNotValidYet),
        CertEndEntityUsedAsCA => TLSError::WebPKIError(webpki::EndEntityUsedAsCA),
        CertExtensionValueInvalid => TLSError::WebPKIError(webpki::ExtensionValueInvalid),
        CertInvalidCertValidity => TLSError::WebPKIError(webpki::InvalidCertValidity),
        CertInvalidSignatureForPublicKey => {
            TLSError::WebPKIError(webpki::InvalidSignatureForPublicKey)
        }
        CertNameConstraintViolation => TLSError::WebPKIError(webpki::NameConstraintViolation),
        CertPathLenConstraintViolated => TLSError::WebPKIError(webpki::PathLenConstraintViolated),
        CertSignatureAlgorithmMismatch => TLSError::WebPKIError(webpki::SignatureAlgorithmMismatch),
        CertRequiredEKUNotFound => TLSError::WebPKIError(webpki::RequiredEKUNotFound),
        CertUnknownIssuer => TLSError::WebPKIError(webpki::UnknownIssuer),
        CertUnsupportedCertVersion => TLSError::WebPKIError(webpki::UnsupportedCertVersion),
        CertUnsupportedCriticalExtension => {
            TLSError::WebPKIError(webpki::UnsupportedCriticalExtension)
        }
        CertUnsupportedSignatureAlgorithmForPublicKey => {
            TLSError::WebPKIError(webpki::UnsupportedSignatureAlgorithmForPublicKey)
        }
        CertUnsupportedSignatureAlgorithm => {
            TLSError::WebPKIError(webpki::UnsupportedSignatureAlgorithm)
        }

        CertSCTMalformed => TLSError::InvalidSCT(sct::MalformedSCT),
        CertSCTInvalidSignature => TLSError::InvalidSCT(sct::InvalidSignature),
        CertSCTTimestampInFuture => TLSError::InvalidSCT(sct::TimestampInFuture),
        CertSCTUnsupportedVersion => TLSError::InvalidSCT(sct::UnsupportedSCTVersion),
        CertSCTUnknownLog => TLSError::InvalidSCT(sct::UnknownLog),
    };
    Either::TLSError(e)
}
