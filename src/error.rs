use std::cmp::min;
use std::fmt::Display;
use std::sync::Arc;

use crate::ffi_panic_boundary;
use libc::{c_char, c_uint, size_t};
use rustls::server::VerifierBuilderError;
use rustls::{CertRevocationListError, CertificateError, Error, InvalidMessage};

/// A return value for a function that may return either success (0) or a
/// non-zero value representing an error.
///
/// The values should match socket error numbers for your operating system --
/// for example, the integers for `ETIMEDOUT`, `EAGAIN`, or similar.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct rustls_io_result(pub libc::c_int);

macro_rules! u32_enum_builder {
    (
    $(#[$comment:meta])*
        EnumName: $enum_name: ident;
        EnumDefault: $enum_default: ident;
        EnumVal { $( $enum_var: ident => $enum_val: expr ),* }
    ) => {
        $(#[$comment])*
        #[allow(dead_code)]
        #[repr(u32)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $enum_name {
            $( $enum_var = $enum_val),*
        }
        impl From<u32> for $enum_name {
            fn from(x: u32) -> Self {
                match x {
                    $($enum_val => $enum_name::$enum_var),*
                    , _ => $enum_name::$enum_default,
                }
            }
        }
    };
}

u32_enum_builder! {
    EnumName: rustls_result;
    EnumDefault: InvalidParameter;
    EnumVal{
        Ok => 7000,
        Io => 7001,
        NullParameter => 7002,
        InvalidDnsNameError => 7003,
        Panic => 7004,
        CertificateParseError => 7005,
        PrivateKeyParseError => 7006,
        InsufficientSize => 7007,
        NotFound => 7008,
        InvalidParameter => 7009,
        UnexpectedEof => 7010,
        PlaintextEmpty => 7011,
        AcceptorNotReady => 7012,
        AlreadyUsed => 7013,
        CertificateRevocationListParseError => 7014,
        NoServerCertVerifier => 7015,
        NoDefaultCryptoProvider => 7016,
        GetRandomFailed => 7017,

        // From https://docs.rs/rustls/latest/rustls/enum.Error.html
        NoCertificatesPresented => 7101,
        DecryptError => 7102,
        FailedToGetCurrentTime => 7103,
        FailedToGetRandomBytes => 7113,
        HandshakeNotComplete => 7104,
        PeerSentOversizedRecord => 7105,
        NoApplicationProtocol => 7106,
        BadMaxFragmentSize => 7114,
        UnsupportedNameType => 7115,
        EncryptError => 7116,

        // Reserved from previous use pre rustls-ffi <0.21.0
        //  CorruptMessage => 7100,
        //  CorruptMessagePayload => 7111,
        //  CertInvalidEncoding => 7117,
        //  CertInvalidSignatureType => 7118,
        //  CertInvalidSignature => 7119,
        //  CertInvalidData => 7120,

        // From InvalidCertificate, with fields that get flattened.
        // https://docs.rs/rustls/0.21.0/rustls/enum.Error.html#variant.InvalidCertificate
        CertEncodingBad => 7121,
        CertExpired => 7122,
        CertNotYetValid => 7123,
        CertRevoked => 7124,
        CertUnhandledCriticalExtension => 7125,
        CertUnknownIssuer => 7126,
        CertBadSignature => 7127,
        CertNotValidForName => 7128,
        CertInvalidPurpose => 7129,
        CertApplicationVerificationFailure => 7130,
        CertOtherError => 7131,
        CertUnknownRevocationStatus => 7154, // Last added.

        // From InvalidMessage, with fields that get flattened.
        // https://docs.rs/rustls/0.21.0/rustls/enum.Error.html#variant.InvalidMessage
        MessageHandshakePayloadTooLarge => 7133,
        MessageInvalidCcs => 7134,
        MessageInvalidContentType => 7135,
        MessageInvalidCertStatusType => 7136,
        MessageInvalidCertRequest => 7137,
        MessageInvalidDhParams => 7138,
        MessageInvalidEmptyPayload => 7139,
        MessageInvalidKeyUpdate => 7140,
        MessageInvalidServerName => 7141,
        MessageTooLarge => 7142,
        MessageTooShort => 7143,
        MessageMissingData => 7144,
        MessageMissingKeyExchange => 7145,
        MessageNoSignatureSchemes => 7146,
        MessageTrailingData => 7147,
        MessageUnexpectedMessage => 7148,
        MessageUnknownProtocolVersion => 7149,
        MessageUnsupportedCompression => 7150,
        MessageUnsupportedCurveType => 7151,
        MessageUnsupportedKeyExchangeAlgorithm => 7152,
        MessageInvalidOther => 7153,

        // From Error, with fields that get dropped.
        PeerIncompatibleError => 7107,
        PeerMisbehavedError => 7108,
        InappropriateMessage => 7109,
        InappropriateHandshakeMessage => 7110,
        General => 7112,

        // From Error, with fields that get flattened.
        // https://docs.rs/rustls/latest/rustls/internal/msgs/enums/enum.AlertDescription.html
        AlertCloseNotify => 7200,
        AlertUnexpectedMessage => 7201,
        AlertBadRecordMac => 7202,
        AlertDecryptionFailed => 7203,
        AlertRecordOverflow => 7204,
        AlertDecompressionFailure => 7205,
        AlertHandshakeFailure => 7206,
        AlertNoCertificate => 7207,
        AlertBadCertificate => 7208,
        AlertUnsupportedCertificate => 7209,
        AlertCertificateRevoked => 7210,
        AlertCertificateExpired => 7211,
        AlertCertificateUnknown => 7212,
        AlertIllegalParameter => 7213,
        AlertUnknownCA => 7214,
        AlertAccessDenied => 7215,
        AlertDecodeError => 7216,
        AlertDecryptError => 7217,
        AlertExportRestriction => 7218,
        AlertProtocolVersion => 7219,
        AlertInsufficientSecurity => 7220,
        AlertInternalError => 7221,
        AlertInappropriateFallback => 7222,
        AlertUserCanceled => 7223,
        AlertNoRenegotiation => 7224,
        AlertMissingExtension => 7225,
        AlertUnsupportedExtension => 7226,
        AlertCertificateUnobtainable => 7227,
        AlertUnrecognisedName => 7228,
        AlertBadCertificateStatusResponse => 7229,
        AlertBadCertificateHashValue => 7230,
        AlertUnknownPSKIdentity => 7231,
        AlertCertificateRequired => 7232,
        AlertNoApplicationProtocol => 7233,
        AlertUnknown => 7234,

        // Reserved from previous use pre rustls-ffi <0.22.0
        // CertSCTMalformed => 7319,
        // CertSCTInvalidSignature => 7320,
        // CertSCTTimestampInFuture => 7321,
        // CertSCTUnsupportedVersion => 7322,
        // CertSCTUnknownLog => 7323,

        // From InvalidCertRevocationList, with fields that get flattened.
        // https://docs.rs/rustls/0.21.6/rustls/enum.Error.html#variant.InvalidCertRevocationList
        CertRevocationListBadSignature => 7400,
        CertRevocationListInvalidCrlNumber => 7401,
        CertRevocationListInvalidRevokedCertSerialNumber => 7402,
        CertRevocationListIssuerInvalidForCrl => 7403,
        CertRevocationListOtherError => 7404,
        CertRevocationListParseError => 7405,
        CertRevocationListUnsupportedCrlVersion => 7406,
        CertRevocationListUnsupportedCriticalExtension => 7407,
        CertRevocationListUnsupportedDeltaCrl => 7408,
        CertRevocationListUnsupportedIndirectCrl => 7409,
        CertRevocationListUnsupportedRevocationReason => 7410,

        // From ClientCertVerifierBuilderError, with fields that get flattened.
        ClientCertVerifierBuilderNoRootAnchors => 7500
    }
}

impl rustls_result {
    /// After a rustls function returns an error, you may call
    /// this to get a pointer to a buffer containing a detailed error
    /// message.
    ///
    /// The contents of the error buffer will be out_n bytes long,
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
                return;
            }
            if out_n.is_null() {
                return;
            }
            let error_str = rustls_result::from(result).to_string();
            let out_len = min(len - 1, error_str.len());
            unsafe {
                std::ptr::copy_nonoverlapping(error_str.as_ptr() as *mut c_char, buf, out_len);
                *out_n = out_len;
            }
        }
    }

    #[no_mangle]
    pub extern "C" fn rustls_result_is_cert_error(result: c_uint) -> bool {
        use rustls_result::*;
        matches!(
            rustls_result::from(result),
            CertEncodingBad
                | CertExpired
                | CertNotYetValid
                | CertRevoked
                | CertUnhandledCriticalExtension
                | CertUnknownIssuer
                | CertUnknownRevocationStatus
                | CertBadSignature
                | CertNotValidForName
                | CertInvalidPurpose
                | CertApplicationVerificationFailure
                | CertOtherError
        )
    }
}

/// For cert-related rustls_results, turn them into a rustls::Error.
///
/// For other inputs, including Ok, return rustls::Error::General.
pub(crate) fn cert_result_to_error(result: rustls_result) -> Error {
    use rustls::Error::*;
    use rustls::OtherError;
    use rustls_result::*;
    match result {
        CertEncodingBad => InvalidCertificate(CertificateError::BadEncoding),
        CertExpired => InvalidCertificate(CertificateError::Expired),
        CertNotYetValid => InvalidCertificate(CertificateError::NotValidYet),
        CertRevoked => InvalidCertificate(CertificateError::Revoked),
        CertUnhandledCriticalExtension => {
            InvalidCertificate(CertificateError::UnhandledCriticalExtension)
        }
        CertUnknownIssuer => InvalidCertificate(CertificateError::UnknownIssuer),
        CertBadSignature => InvalidCertificate(CertificateError::BadSignature),
        CertNotValidForName => InvalidCertificate(CertificateError::NotValidForName),
        CertInvalidPurpose => InvalidCertificate(CertificateError::InvalidPurpose),
        CertApplicationVerificationFailure => {
            InvalidCertificate(CertificateError::ApplicationVerificationFailure)
        }
        CertOtherError => InvalidCertificate(CertificateError::Other(OtherError(Arc::from(
            Box::from(""),
        )))),
        _ => rustls::Error::General("".into()),
    }
}

#[test]
fn test_rustls_error() {
    let mut buf = [0 as c_char; 512];
    let mut n = 0;
    rustls_result::rustls_error(0, &mut buf as *mut _, buf.len(), &mut n);
    let output = String::from_utf8(buf[0..n].iter().map(|b| *b as u8).collect()).unwrap();
    assert_eq!(&output, "a parameter had an invalid value");

    rustls_result::rustls_error(7000, &mut buf as *mut _, buf.len(), &mut n);
    let output = String::from_utf8(buf[0..n].iter().map(|b| *b as u8).collect()).unwrap();
    assert_eq!(&output, "OK");

    rustls_result::rustls_error(7101, &mut buf as *mut _, buf.len(), &mut n);
    let output = String::from_utf8(buf[0..n].iter().map(|b| *b as u8).collect()).unwrap();
    assert_eq!(&output, "peer sent no certificates");
}

#[test]
fn test_rustls_result_is_cert_error() {
    assert!(!rustls_result::rustls_result_is_cert_error(0));
    assert!(!rustls_result::rustls_result_is_cert_error(7000));

    // Test CertificateError range.
    for id in 7121..=7131 {
        assert!(rustls_result::rustls_result_is_cert_error(id));
    }
}

pub(crate) fn map_error(input: Error) -> rustls_result {
    use rustls::AlertDescription as alert;
    use rustls_result::*;

    match input {
        Error::InappropriateMessage { .. } => InappropriateMessage,
        Error::InappropriateHandshakeMessage { .. } => InappropriateHandshakeMessage,

        Error::NoCertificatesPresented => NoCertificatesPresented,
        Error::DecryptError => DecryptError,
        Error::PeerIncompatible(_) => PeerIncompatibleError,
        Error::PeerMisbehaved(_) => PeerMisbehavedError,
        Error::UnsupportedNameType => UnsupportedNameType,
        Error::EncryptError => EncryptError,

        Error::InvalidMessage(e) => match e {
            InvalidMessage::HandshakePayloadTooLarge => MessageHandshakePayloadTooLarge,
            InvalidMessage::InvalidCcs => MessageInvalidCcs,
            InvalidMessage::InvalidContentType => MessageInvalidContentType,
            InvalidMessage::InvalidCertificateStatusType => MessageInvalidCertStatusType,
            InvalidMessage::InvalidCertRequest => MessageInvalidCertRequest,
            InvalidMessage::InvalidDhParams => MessageInvalidDhParams,
            InvalidMessage::InvalidEmptyPayload => MessageInvalidEmptyPayload,
            InvalidMessage::InvalidKeyUpdate => MessageInvalidKeyUpdate,
            InvalidMessage::InvalidServerName => MessageInvalidServerName,
            InvalidMessage::MessageTooLarge => MessageTooLarge,
            InvalidMessage::MessageTooShort => MessageTooShort,
            InvalidMessage::MissingData(_) => MessageMissingData,
            InvalidMessage::MissingKeyExchange => MessageMissingKeyExchange,
            InvalidMessage::NoSignatureSchemes => MessageNoSignatureSchemes,
            InvalidMessage::TrailingData(_) => MessageTrailingData,
            InvalidMessage::UnexpectedMessage(_) => MessageUnexpectedMessage,
            InvalidMessage::UnknownProtocolVersion => MessageUnknownProtocolVersion,
            InvalidMessage::UnsupportedCompression => MessageUnsupportedCompression,
            InvalidMessage::UnsupportedCurveType => MessageUnsupportedCurveType,
            InvalidMessage::UnsupportedKeyExchangeAlgorithm(_) => MessageUnsupportedCompression,
            _ => MessageInvalidOther,
        },

        Error::FailedToGetCurrentTime => FailedToGetCurrentTime,
        Error::FailedToGetRandomBytes => FailedToGetRandomBytes,
        Error::HandshakeNotComplete => HandshakeNotComplete,
        Error::PeerSentOversizedRecord => PeerSentOversizedRecord,
        Error::NoApplicationProtocol => NoApplicationProtocol,
        Error::BadMaxFragmentSize => BadMaxFragmentSize,

        Error::InvalidCertificate(e) => match e {
            CertificateError::BadEncoding => CertEncodingBad,
            CertificateError::Expired => CertExpired,
            CertificateError::NotValidYet => CertNotYetValid,
            CertificateError::Revoked => CertRevoked,
            CertificateError::UnhandledCriticalExtension => CertUnhandledCriticalExtension,
            CertificateError::UnknownIssuer => CertUnknownIssuer,
            CertificateError::UnknownRevocationStatus => CertUnknownRevocationStatus,
            CertificateError::BadSignature => CertBadSignature,
            CertificateError::NotValidForName => CertNotValidForName,
            CertificateError::InvalidPurpose => CertInvalidPurpose,
            CertificateError::ApplicationVerificationFailure => CertApplicationVerificationFailure,
            _ => CertOtherError,
        },

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
            _ => AlertUnknown,
        },

        Error::InvalidCertRevocationList(e) => map_crl_error(e),

        _ => General,
    }
}

pub(crate) fn map_crl_error(err: CertRevocationListError) -> rustls_result {
    use rustls_result::*;

    match err {
        CertRevocationListError::BadSignature => CertRevocationListBadSignature,
        CertRevocationListError::InvalidCrlNumber => CertRevocationListInvalidCrlNumber,
        CertRevocationListError::InvalidRevokedCertSerialNumber => {
            CertRevocationListInvalidRevokedCertSerialNumber
        }
        CertRevocationListError::IssuerInvalidForCrl => CertRevocationListIssuerInvalidForCrl,
        CertRevocationListError::Other(_) => CertRevocationListOtherError,
        CertRevocationListError::ParseError => CertRevocationListParseError,
        CertRevocationListError::UnsupportedCrlVersion => CertRevocationListUnsupportedCrlVersion,
        CertRevocationListError::UnsupportedCriticalExtension => {
            CertRevocationListUnsupportedCriticalExtension
        }
        CertRevocationListError::UnsupportedDeltaCrl => CertRevocationListUnsupportedDeltaCrl,
        CertRevocationListError::UnsupportedIndirectCrl => CertRevocationListUnsupportedIndirectCrl,
        CertRevocationListError::UnsupportedRevocationReason => {
            CertRevocationListUnsupportedRevocationReason
        }
        _ => CertRevocationListOtherError,
    }
}

pub(crate) fn map_verifier_builder_error(err: VerifierBuilderError) -> rustls_result {
    match err {
        VerifierBuilderError::NoRootAnchors => {
            rustls_result::ClientCertVerifierBuilderNoRootAnchors
        }
        VerifierBuilderError::InvalidCrl(crl_err) => map_crl_error(crl_err),
        _ => rustls_result::General,
    }
}

impl Display for rustls_result {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use rustls::AlertDescription as alert;
        use rustls_result::*;

        match self {
            // These variants are local to this glue layer.
            rustls_result::Ok => write!(f, "OK"),
            Io => write!(f, "I/O error"),
            NullParameter => write!(f, "a parameter was NULL"),
            InvalidDnsNameError => write!(
                f,
                "server name was malformed (not a valid hostname or IP address)"
            ),
            Panic => write!(f, "a Rust component panicked"),
            CertificateParseError => write!(f, "error parsing certificate"),
            PrivateKeyParseError => write!(f, "error parsing private key"),
            InsufficientSize => write!(f, "provided buffer is of insufficient size"),
            NotFound => write!(f, "the item was not found"),
            InvalidParameter => write!(f, "a parameter had an invalid value"),
            UnexpectedEof => write!(
                f,
                "peer closed TCP connection without first closing TLS connection"
            ),
            PlaintextEmpty => write!(
                f,
                "no plaintext available; call rustls_connection_read_tls again"
            ),
            AcceptorNotReady => write!(
                f,
                "rustls_acceptor not ready yet; read more TLS bytes into it"
            ),
            AlreadyUsed => write!(
                f,
                "tried to use a rustls struct after it had been converted to another struct"
            ),
            CertificateRevocationListParseError => {
                write!(f, "error parsing certificate revocation list (CRL)",)
            }
            NoServerCertVerifier => {
                write!(
                    f,
                    "no server certificate verifier was configured on the client config builder"
                )
            }
            NoDefaultCryptoProvider => {
                write!(
                    f,
                    "no default process-wide crypto provider has been installed"
                )
            }
            GetRandomFailed => {
                write!(f, "failed to get random bytes from the crypto provider")
            }

            CertEncodingBad => Error::InvalidCertificate(CertificateError::BadEncoding).fmt(f),
            CertExpired => Error::InvalidCertificate(CertificateError::Expired).fmt(f),
            CertNotYetValid => Error::InvalidCertificate(CertificateError::NotValidYet).fmt(f),
            CertRevoked => Error::InvalidCertificate(CertificateError::Revoked).fmt(f),
            CertUnhandledCriticalExtension => {
                Error::InvalidCertificate(CertificateError::UnhandledCriticalExtension).fmt(f)
            }
            CertUnknownIssuer => Error::InvalidCertificate(CertificateError::UnknownIssuer).fmt(f),
            CertBadSignature => Error::InvalidCertificate(CertificateError::BadSignature).fmt(f),
            CertNotValidForName => {
                Error::InvalidCertificate(CertificateError::NotValidForName).fmt(f)
            }
            CertInvalidPurpose => {
                Error::InvalidCertificate(CertificateError::InvalidPurpose).fmt(f)
            }
            CertApplicationVerificationFailure => {
                Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure).fmt(f)
            }
            CertUnknownRevocationStatus => {
                Error::InvalidCertificate(CertificateError::UnknownRevocationStatus).fmt(f)
            }
            CertOtherError => write!(f, "unknown certificate error"),

            // These variants correspond to a rustls::Error variant with a field,
            // where generating an arbitrary field would produce a confusing error
            // message. So we reproduce a simplified error string.
            InappropriateMessage => write!(f, "received unexpected message"),
            InappropriateHandshakeMessage => write!(f, "received unexpected handshake message"),

            MessageHandshakePayloadTooLarge => {
                Error::InvalidMessage(InvalidMessage::HandshakePayloadTooLarge).fmt(f)
            }
            MessageInvalidContentType => {
                Error::InvalidMessage(InvalidMessage::InvalidContentType).fmt(f)
            }
            MessageInvalidServerName => {
                Error::InvalidMessage(InvalidMessage::InvalidServerName).fmt(f)
            }
            MessageTooLarge => Error::InvalidMessage(InvalidMessage::MessageTooLarge).fmt(f),
            MessageTooShort => Error::InvalidMessage(InvalidMessage::MessageTooShort).fmt(f),
            MessageUnknownProtocolVersion => {
                Error::InvalidMessage(InvalidMessage::UnknownProtocolVersion).fmt(f)
            }
            MessageUnsupportedCompression => {
                Error::InvalidMessage(InvalidMessage::UnsupportedCompression).fmt(f)
            }
            MessageInvalidEmptyPayload => {
                Error::InvalidMessage(InvalidMessage::InvalidEmptyPayload).fmt(f)
            }
            MessageInvalidCertStatusType => {
                Error::InvalidMessage(InvalidMessage::InvalidCertificateStatusType).fmt(f)
            }
            MessageInvalidKeyUpdate => {
                Error::InvalidMessage(InvalidMessage::InvalidKeyUpdate).fmt(f)
            }
            MessageUnsupportedCurveType => {
                Error::InvalidMessage(InvalidMessage::UnsupportedCurveType).fmt(f)
            }

            // These variants correspond to a InvalidMessage variant with a field where generating an
            // arbitrary field would produce a confusing error message. So we reproduce a simplified
            // error string.
            MessageMissingData => write!(f, "missing data for the named handshake payload value"),
            MessageTrailingData => write!(
                f,
                "trailing data found for the named handshake payload value"
            ),
            MessageUnexpectedMessage => write!(f, "peer sent unexpected message type"),
            MessageUnsupportedKeyExchangeAlgorithm => {
                write!(f, "peer sent an unsupported key exchange algorithm")
            }

            // These variants correspond to an InvalidMessage variant where the Debug fmt may not
            // express enough information, so we provide a friendlier error string.
            MessageMissingKeyExchange => {
                write!(f, "peer did not advertise supported key exchange groups")
            }
            MessageNoSignatureSchemes => write!(f, "peer sent an empty list of signature schemes"),
            MessageInvalidDhParams => write!(
                f,
                "peer's Diffie-Hellman (DH) parameters could not be decoded"
            ),
            MessageInvalidCertRequest => write!(f, "invalid certificate request context"),
            MessageInvalidCcs => write!(f, "invalid change cipher spec (CCS) payload"),
            MessageInvalidOther => write!(f, "invalid message"),

            PeerIncompatibleError => write!(f, "peer is incompatible"),
            PeerMisbehavedError => write!(f, "peer misbehaved"),

            General => write!(f, "general error"),

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

            AlertCloseNotify => Error::AlertReceived(alert::CloseNotify).fmt(f),
            AlertUnexpectedMessage => Error::AlertReceived(alert::UnexpectedMessage).fmt(f),
            AlertBadRecordMac => Error::AlertReceived(alert::BadRecordMac).fmt(f),
            AlertDecryptionFailed => Error::AlertReceived(alert::DecryptionFailed).fmt(f),
            AlertRecordOverflow => Error::AlertReceived(alert::RecordOverflow).fmt(f),
            AlertDecompressionFailure => Error::AlertReceived(alert::DecompressionFailure).fmt(f),
            AlertHandshakeFailure => Error::AlertReceived(alert::HandshakeFailure).fmt(f),
            AlertNoCertificate => Error::AlertReceived(alert::NoCertificate).fmt(f),
            AlertBadCertificate => Error::AlertReceived(alert::BadCertificate).fmt(f),
            AlertUnsupportedCertificate => {
                Error::AlertReceived(alert::UnsupportedCertificate).fmt(f)
            }
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
            AlertCertificateUnobtainable => {
                Error::AlertReceived(alert::CertificateUnobtainable).fmt(f)
            }
            AlertUnrecognisedName => Error::AlertReceived(alert::UnrecognisedName).fmt(f),
            AlertBadCertificateStatusResponse => {
                Error::AlertReceived(alert::BadCertificateStatusResponse).fmt(f)
            }
            AlertBadCertificateHashValue => {
                Error::AlertReceived(alert::BadCertificateHashValue).fmt(f)
            }
            AlertUnknownPSKIdentity => Error::AlertReceived(alert::UnknownPSKIdentity).fmt(f),
            AlertCertificateRequired => Error::AlertReceived(alert::CertificateRequired).fmt(f),
            AlertNoApplicationProtocol => Error::AlertReceived(alert::NoApplicationProtocol).fmt(f),
            AlertUnknown => Error::AlertReceived(alert::Unknown(0)).fmt(f),

            CertRevocationListBadSignature => {
                Error::InvalidCertRevocationList(CertRevocationListError::BadSignature).fmt(f)
            }
            CertRevocationListInvalidCrlNumber => {
                Error::InvalidCertRevocationList(CertRevocationListError::InvalidCrlNumber).fmt(f)
            }
            CertRevocationListInvalidRevokedCertSerialNumber => Error::InvalidCertRevocationList(
                CertRevocationListError::InvalidRevokedCertSerialNumber,
            )
            .fmt(f),
            CertRevocationListIssuerInvalidForCrl => {
                Error::InvalidCertRevocationList(CertRevocationListError::IssuerInvalidForCrl)
                    .fmt(f)
            }
            CertRevocationListOtherError => {
                write!(f, "unknown certificate revocation list (CRL) error")
            }
            CertRevocationListParseError => {
                Error::InvalidCertRevocationList(CertRevocationListError::ParseError).fmt(f)
            }
            CertRevocationListUnsupportedCrlVersion => {
                Error::InvalidCertRevocationList(CertRevocationListError::UnsupportedCrlVersion)
                    .fmt(f)
            }
            CertRevocationListUnsupportedCriticalExtension => Error::InvalidCertRevocationList(
                CertRevocationListError::UnsupportedCriticalExtension,
            )
            .fmt(f),
            CertRevocationListUnsupportedDeltaCrl => {
                Error::InvalidCertRevocationList(CertRevocationListError::UnsupportedDeltaCrl)
                    .fmt(f)
            }
            CertRevocationListUnsupportedIndirectCrl => {
                Error::InvalidCertRevocationList(CertRevocationListError::UnsupportedIndirectCrl)
                    .fmt(f)
            }
            CertRevocationListUnsupportedRevocationReason => Error::InvalidCertRevocationList(
                CertRevocationListError::UnsupportedRevocationReason,
            )
            .fmt(f),

            ClientCertVerifierBuilderNoRootAnchors => write!(f, "no root trust anchors provided"),
        }
    }
}
