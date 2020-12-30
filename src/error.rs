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
        write!(f, "{}", result_to_string(self))
    }
}

fn result_to_string(input: &rustls_result) -> String {
    use rustls::internal::msgs::enums::AlertDescription as alert;
    use rustls_result::*;
    use sct::Error as sct;
    use webpki::Error as webpki;

    let msg = match input {
        // These variants are local to this glue layer.
        rustls_result::Ok => "OK".to_string(),
        Io => "I/O error".to_string(),
        NullParameter => "a parameter was NULL".to_string(),

        // These variants correspond to a TLSError variant with a field,
        // where generating an arbitrary field would produce a confusing error
        // message. So we reproduce a simplified error string.
        InappropriateMessage => "received unexpected message".to_string(),
        InappropriateHandshakeMessage => "received unexpected handshake message".to_string(),
        CorruptMessagePayload => "received corrupt message".to_string(),

        CorruptMessage => TLSError::CorruptMessage.to_string(),
        NoCertificatesPresented => TLSError::NoCertificatesPresented.to_string(),
        DecryptError => TLSError::DecryptError.to_string(),
        FailedToGetCurrentTime => TLSError::FailedToGetCurrentTime.to_string(),
        HandshakeNotComplete => TLSError::HandshakeNotComplete.to_string(),
        PeerSentOversizedRecord => TLSError::PeerSentOversizedRecord.to_string(),
        NoApplicationProtocol => TLSError::NoApplicationProtocol.to_string(),
        PeerIncompatibleError => {
            TLSError::PeerIncompatibleError("reason omitted".to_string()).to_string()
        }
        PeerMisbehavedError => {
            TLSError::PeerMisbehavedError("reason omitted".to_string()).to_string()
        }
        General => TLSError::General("omitted".to_string()).to_string(),

        AlertCloseNotify => TLSError::AlertReceived(alert::CloseNotify).to_string(),
        AlertUnexpectedMessage => TLSError::AlertReceived(alert::UnexpectedMessage).to_string(),
        AlertBadRecordMac => TLSError::AlertReceived(alert::BadRecordMac).to_string(),
        AlertDecryptionFailed => TLSError::AlertReceived(alert::DecryptionFailed).to_string(),
        AlertRecordOverflow => TLSError::AlertReceived(alert::RecordOverflow).to_string(),
        AlertDecompressionFailure => {
            TLSError::AlertReceived(alert::DecompressionFailure).to_string()
        }
        AlertHandshakeFailure => TLSError::AlertReceived(alert::HandshakeFailure).to_string(),
        AlertNoCertificate => TLSError::AlertReceived(alert::NoCertificate).to_string(),
        AlertBadCertificate => TLSError::AlertReceived(alert::BadCertificate).to_string(),
        AlertUnsupportedCertificate => {
            TLSError::AlertReceived(alert::UnsupportedCertificate).to_string()
        }
        AlertCertificateRevoked => TLSError::AlertReceived(alert::CertificateRevoked).to_string(),
        AlertCertificateExpired => TLSError::AlertReceived(alert::CertificateExpired).to_string(),
        AlertCertificateUnknown => TLSError::AlertReceived(alert::CertificateUnknown).to_string(),
        AlertIllegalParameter => TLSError::AlertReceived(alert::IllegalParameter).to_string(),
        AlertUnknownCA => TLSError::AlertReceived(alert::UnknownCA).to_string(),
        AlertAccessDenied => TLSError::AlertReceived(alert::AccessDenied).to_string(),
        AlertDecodeError => TLSError::AlertReceived(alert::DecodeError).to_string(),
        AlertDecryptError => TLSError::AlertReceived(alert::DecryptError).to_string(),
        AlertExportRestriction => TLSError::AlertReceived(alert::ExportRestriction).to_string(),
        AlertProtocolVersion => TLSError::AlertReceived(alert::ProtocolVersion).to_string(),
        AlertInsufficientSecurity => {
            TLSError::AlertReceived(alert::InsufficientSecurity).to_string()
        }
        AlertInternalError => TLSError::AlertReceived(alert::InternalError).to_string(),
        AlertInappropriateFallback => {
            TLSError::AlertReceived(alert::InappropriateFallback).to_string()
        }
        AlertUserCanceled => TLSError::AlertReceived(alert::UserCanceled).to_string(),
        AlertNoRenegotiation => TLSError::AlertReceived(alert::NoRenegotiation).to_string(),
        AlertMissingExtension => TLSError::AlertReceived(alert::MissingExtension).to_string(),
        AlertUnsupportedExtension => {
            TLSError::AlertReceived(alert::UnsupportedExtension).to_string()
        }
        AlertCertificateUnobtainable => {
            TLSError::AlertReceived(alert::CertificateUnobtainable).to_string()
        }
        AlertUnrecognisedName => TLSError::AlertReceived(alert::UnrecognisedName).to_string(),
        AlertBadCertificateStatusResponse => {
            TLSError::AlertReceived(alert::BadCertificateStatusResponse).to_string()
        }
        AlertBadCertificateHashValue => {
            TLSError::AlertReceived(alert::BadCertificateHashValue).to_string()
        }
        AlertUnknownPSKIdentity => TLSError::AlertReceived(alert::UnknownPSKIdentity).to_string(),
        AlertCertificateRequired => TLSError::AlertReceived(alert::CertificateRequired).to_string(),
        AlertNoApplicationProtocol => {
            TLSError::AlertReceived(alert::NoApplicationProtocol).to_string()
        }
        AlertUnknown => TLSError::AlertReceived(alert::Unknown(0)).to_string(),

        CertBadDER => TLSError::WebPKIError(webpki::BadDER).to_string(),
        CertBadDERTime => TLSError::WebPKIError(webpki::BadDERTime).to_string(),
        CertCAUsedAsEndEntity => TLSError::WebPKIError(webpki::CAUsedAsEndEntity).to_string(),
        CertExpired => TLSError::WebPKIError(webpki::CertExpired).to_string(),
        CertNotValidForName => TLSError::WebPKIError(webpki::CertNotValidForName).to_string(),
        CertNotValidYet => TLSError::WebPKIError(webpki::CertNotValidYet).to_string(),
        CertEndEntityUsedAsCA => TLSError::WebPKIError(webpki::EndEntityUsedAsCA).to_string(),
        CertExtensionValueInvalid => {
            TLSError::WebPKIError(webpki::ExtensionValueInvalid).to_string()
        }
        CertInvalidCertValidity => TLSError::WebPKIError(webpki::InvalidCertValidity).to_string(),
        CertInvalidSignatureForPublicKey => {
            TLSError::WebPKIError(webpki::InvalidSignatureForPublicKey).to_string()
        }
        CertNameConstraintViolation => {
            TLSError::WebPKIError(webpki::NameConstraintViolation).to_string()
        }
        CertPathLenConstraintViolated => {
            TLSError::WebPKIError(webpki::PathLenConstraintViolated).to_string()
        }
        CertSignatureAlgorithmMismatch => {
            TLSError::WebPKIError(webpki::SignatureAlgorithmMismatch).to_string()
        }
        CertRequiredEKUNotFound => TLSError::WebPKIError(webpki::RequiredEKUNotFound).to_string(),
        CertUnknownIssuer => TLSError::WebPKIError(webpki::UnknownIssuer).to_string(),
        CertUnsupportedCertVersion => {
            TLSError::WebPKIError(webpki::UnsupportedCertVersion).to_string()
        }
        CertUnsupportedCriticalExtension => {
            TLSError::WebPKIError(webpki::UnsupportedCriticalExtension).to_string()
        }
        CertUnsupportedSignatureAlgorithmForPublicKey => {
            TLSError::WebPKIError(webpki::UnsupportedSignatureAlgorithmForPublicKey).to_string()
        }
        CertUnsupportedSignatureAlgorithm => {
            TLSError::WebPKIError(webpki::UnsupportedSignatureAlgorithm).to_string()
        }

        CertSCTMalformed => TLSError::InvalidSCT(sct::MalformedSCT).to_string(),
        CertSCTInvalidSignature => TLSError::InvalidSCT(sct::InvalidSignature).to_string(),
        CertSCTTimestampInFuture => TLSError::InvalidSCT(sct::TimestampInFuture).to_string(),
        CertSCTUnsupportedVersion => TLSError::InvalidSCT(sct::UnsupportedSCTVersion).to_string(),
        CertSCTUnknownLog => TLSError::InvalidSCT(sct::UnknownLog).to_string(),
    };
    format!("rustls: {}", msg)
}
