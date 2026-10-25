#ifndef RUSTLS_H
#define RUSTLS_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define RUSTLS_VERSION_MAJOR 0
#define RUSTLS_VERSION_MINOR 15
#define RUSTLS_VERSION_PATCH 6

/**
 * This gives each version part 8 bits, and leaves the 8 least significant bits
 * empty for future additions, for example pre-release versions.
 */
#define RUSTLS_VERSION_NUMBER ((RUSTLS_VERSION_MAJOR << 24)   \
                               |(RUSTLS_VERSION_MINOR << 16)  \
                               |(RUSTLS_VERSION_PATCH << 8))

#if defined(__clang__) || defined(__GNUC__)
# define DEPRECATED_FUNC(why) __attribute__((deprecated(why)))
#elif defined(_MSC_VER)
# define DEPRECATED_FUNC(why) __declspec(deprecated(why))
#else
# define DEPRECATED_FUNC(why)
#endif


/**
 * Numeric error codes returned from rustls-ffi API functions.
 */
enum rustls_result
#if __STDC_VERSION__ >= 202311L
  : uint32_t
#endif // __STDC_VERSION__ >= 202311L
 {
  RUSTLS_RESULT_OK = 7000,
  RUSTLS_RESULT_IO = 7001,
  RUSTLS_RESULT_NULL_PARAMETER = 7002,
  RUSTLS_RESULT_INVALID_DNS_NAME_ERROR = 7003,
  RUSTLS_RESULT_PANIC = 7004,
  RUSTLS_RESULT_CERTIFICATE_PARSE_ERROR = 7005,
  RUSTLS_RESULT_PRIVATE_KEY_PARSE_ERROR = 7006,
  RUSTLS_RESULT_INSUFFICIENT_SIZE = 7007,
  RUSTLS_RESULT_NOT_FOUND = 7008,
  RUSTLS_RESULT_INVALID_PARAMETER = 7009,
  RUSTLS_RESULT_UNEXPECTED_EOF = 7010,
  RUSTLS_RESULT_PLAINTEXT_EMPTY = 7011,
  RUSTLS_RESULT_ACCEPTOR_NOT_READY = 7012,
  RUSTLS_RESULT_ALREADY_USED = 7013,
  RUSTLS_RESULT_CERTIFICATE_REVOCATION_LIST_PARSE_ERROR = 7014,
  RUSTLS_RESULT_NO_SERVER_CERT_VERIFIER = 7015,
  RUSTLS_RESULT_NO_DEFAULT_CRYPTO_PROVIDER = 7016,
  RUSTLS_RESULT_GET_RANDOM_FAILED = 7017,
  RUSTLS_RESULT_NO_CERT_RESOLVER = 7018,
  RUSTLS_RESULT_HPKE_ERROR = 7019,
  RUSTLS_RESULT_BUILDER_INCOMPATIBLE_TLS_VERSIONS = 7020,
  RUSTLS_RESULT_NO_CERTIFICATES_PRESENTED = 7101,
  RUSTLS_RESULT_DECRYPT_ERROR = 7102,
  RUSTLS_RESULT_FAILED_TO_GET_CURRENT_TIME = 7103,
  RUSTLS_RESULT_FAILED_TO_GET_RANDOM_BYTES = 7113,
  RUSTLS_RESULT_HANDSHAKE_NOT_COMPLETE = 7104,
  RUSTLS_RESULT_PEER_SENT_OVERSIZED_RECORD = 7105,
  RUSTLS_RESULT_NO_APPLICATION_PROTOCOL = 7106,
  RUSTLS_RESULT_BAD_MAX_FRAGMENT_SIZE = 7114,
  RUSTLS_RESULT_UNSUPPORTED_NAME_TYPE = 7115,
  RUSTLS_RESULT_ENCRYPT_ERROR = 7116,
  RUSTLS_RESULT_CERT_ENCODING_BAD = 7121,
  RUSTLS_RESULT_CERT_EXPIRED = 7122,
  RUSTLS_RESULT_CERT_NOT_YET_VALID = 7123,
  RUSTLS_RESULT_CERT_REVOKED = 7124,
  RUSTLS_RESULT_CERT_UNHANDLED_CRITICAL_EXTENSION = 7125,
  RUSTLS_RESULT_CERT_UNKNOWN_ISSUER = 7126,
  RUSTLS_RESULT_CERT_BAD_SIGNATURE = 7127,
  RUSTLS_RESULT_CERT_NOT_VALID_FOR_NAME = 7128,
  RUSTLS_RESULT_CERT_INVALID_PURPOSE = 7129,
  RUSTLS_RESULT_CERT_APPLICATION_VERIFICATION_FAILURE = 7130,
  RUSTLS_RESULT_CERT_OTHER_ERROR = 7131,
  RUSTLS_RESULT_CERT_UNKNOWN_REVOCATION_STATUS = 7154,
  RUSTLS_RESULT_CERT_EXPIRED_REVOCATION_LIST = 7156,
  RUSTLS_RESULT_CERT_UNSUPPORTED_SIGNATURE_ALGORITHM = 7157,
  RUSTLS_RESULT_MESSAGE_HANDSHAKE_PAYLOAD_TOO_LARGE = 7133,
  RUSTLS_RESULT_MESSAGE_INVALID_CCS = 7134,
  RUSTLS_RESULT_MESSAGE_INVALID_CONTENT_TYPE = 7135,
  RUSTLS_RESULT_MESSAGE_INVALID_CERT_STATUS_TYPE = 7136,
  RUSTLS_RESULT_MESSAGE_INVALID_CERT_REQUEST = 7137,
  RUSTLS_RESULT_MESSAGE_INVALID_DH_PARAMS = 7138,
  RUSTLS_RESULT_MESSAGE_INVALID_EMPTY_PAYLOAD = 7139,
  RUSTLS_RESULT_MESSAGE_INVALID_KEY_UPDATE = 7140,
  RUSTLS_RESULT_MESSAGE_INVALID_SERVER_NAME = 7141,
  RUSTLS_RESULT_MESSAGE_TOO_LARGE = 7142,
  RUSTLS_RESULT_MESSAGE_TOO_SHORT = 7143,
  RUSTLS_RESULT_MESSAGE_MISSING_DATA = 7144,
  RUSTLS_RESULT_MESSAGE_MISSING_KEY_EXCHANGE = 7145,
  RUSTLS_RESULT_MESSAGE_NO_SIGNATURE_SCHEMES = 7146,
  RUSTLS_RESULT_MESSAGE_TRAILING_DATA = 7147,
  RUSTLS_RESULT_MESSAGE_UNEXPECTED_MESSAGE = 7148,
  RUSTLS_RESULT_MESSAGE_UNKNOWN_PROTOCOL_VERSION = 7149,
  RUSTLS_RESULT_MESSAGE_UNSUPPORTED_COMPRESSION = 7150,
  RUSTLS_RESULT_MESSAGE_UNSUPPORTED_CURVE_TYPE = 7151,
  RUSTLS_RESULT_MESSAGE_UNSUPPORTED_KEY_EXCHANGE_ALGORITHM = 7152,
  RUSTLS_RESULT_MESSAGE_INVALID_OTHER = 7153,
  RUSTLS_RESULT_MESSAGE_CERTIFICATE_PAYLOAD_TOO_LARGE = 7155,
  RUSTLS_RESULT_PEER_INCOMPATIBLE_ERROR = 7107,
  RUSTLS_RESULT_PEER_MISBEHAVED_ERROR = 7108,
  RUSTLS_RESULT_INAPPROPRIATE_MESSAGE = 7109,
  RUSTLS_RESULT_INAPPROPRIATE_HANDSHAKE_MESSAGE = 7110,
  RUSTLS_RESULT_GENERAL = 7112,
  RUSTLS_RESULT_ALERT_CLOSE_NOTIFY = 7200,
  RUSTLS_RESULT_ALERT_UNEXPECTED_MESSAGE = 7201,
  RUSTLS_RESULT_ALERT_BAD_RECORD_MAC = 7202,
  RUSTLS_RESULT_ALERT_DECRYPTION_FAILED = 7203,
  RUSTLS_RESULT_ALERT_RECORD_OVERFLOW = 7204,
  RUSTLS_RESULT_ALERT_DECOMPRESSION_FAILURE = 7205,
  RUSTLS_RESULT_ALERT_HANDSHAKE_FAILURE = 7206,
  RUSTLS_RESULT_ALERT_NO_CERTIFICATE = 7207,
  RUSTLS_RESULT_ALERT_BAD_CERTIFICATE = 7208,
  RUSTLS_RESULT_ALERT_UNSUPPORTED_CERTIFICATE = 7209,
  RUSTLS_RESULT_ALERT_CERTIFICATE_REVOKED = 7210,
  RUSTLS_RESULT_ALERT_CERTIFICATE_EXPIRED = 7211,
  RUSTLS_RESULT_ALERT_CERTIFICATE_UNKNOWN = 7212,
  RUSTLS_RESULT_ALERT_ILLEGAL_PARAMETER = 7213,
  RUSTLS_RESULT_ALERT_UNKNOWN_CA = 7214,
  RUSTLS_RESULT_ALERT_ACCESS_DENIED = 7215,
  RUSTLS_RESULT_ALERT_DECODE_ERROR = 7216,
  RUSTLS_RESULT_ALERT_DECRYPT_ERROR = 7217,
  RUSTLS_RESULT_ALERT_EXPORT_RESTRICTION = 7218,
  RUSTLS_RESULT_ALERT_PROTOCOL_VERSION = 7219,
  RUSTLS_RESULT_ALERT_INSUFFICIENT_SECURITY = 7220,
  RUSTLS_RESULT_ALERT_INTERNAL_ERROR = 7221,
  RUSTLS_RESULT_ALERT_INAPPROPRIATE_FALLBACK = 7222,
  RUSTLS_RESULT_ALERT_USER_CANCELED = 7223,
  RUSTLS_RESULT_ALERT_NO_RENEGOTIATION = 7224,
  RUSTLS_RESULT_ALERT_MISSING_EXTENSION = 7225,
  RUSTLS_RESULT_ALERT_UNSUPPORTED_EXTENSION = 7226,
  RUSTLS_RESULT_ALERT_CERTIFICATE_UNOBTAINABLE = 7227,
  RUSTLS_RESULT_ALERT_UNRECOGNISED_NAME = 7228,
  RUSTLS_RESULT_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE = 7229,
  RUSTLS_RESULT_ALERT_BAD_CERTIFICATE_HASH_VALUE = 7230,
  RUSTLS_RESULT_ALERT_UNKNOWN_PSK_IDENTITY = 7231,
  RUSTLS_RESULT_ALERT_CERTIFICATE_REQUIRED = 7232,
  RUSTLS_RESULT_ALERT_NO_APPLICATION_PROTOCOL = 7233,
  RUSTLS_RESULT_ALERT_UNKNOWN = 7234,
  RUSTLS_RESULT_CERT_REVOCATION_LIST_BAD_SIGNATURE = 7400,
  RUSTLS_RESULT_CERT_REVOCATION_LIST_INVALID_CRL_NUMBER = 7401,
  RUSTLS_RESULT_CERT_REVOCATION_LIST_INVALID_REVOKED_CERT_SERIAL_NUMBER = 7402,
  RUSTLS_RESULT_CERT_REVOCATION_LIST_ISSUER_INVALID_FOR_CRL = 7403,
  RUSTLS_RESULT_CERT_REVOCATION_LIST_OTHER_ERROR = 7404,
  RUSTLS_RESULT_CERT_REVOCATION_LIST_PARSE_ERROR = 7405,
  RUSTLS_RESULT_CERT_REVOCATION_LIST_UNSUPPORTED_CRL_VERSION = 7406,
  RUSTLS_RESULT_CERT_REVOCATION_LIST_UNSUPPORTED_CRITICAL_EXTENSION = 7407,
  RUSTLS_RESULT_CERT_REVOCATION_LIST_UNSUPPORTED_DELTA_CRL = 7408,
  RUSTLS_RESULT_CERT_REVOCATION_LIST_UNSUPPORTED_INDIRECT_CRL = 7409,
  RUSTLS_RESULT_CERT_REVOCATION_LIST_UNSUPPORTED_REVOCATION_REASON = 7410,
  RUSTLS_RESULT_CERT_REVOCATION_LIST_UNSUPPORTED_SIGNATURE_ALGORITHM = 7411,
  RUSTLS_RESULT_CLIENT_CERT_VERIFIER_BUILDER_NO_ROOT_ANCHORS = 7500,
  RUSTLS_RESULT_INCONSISTENT_KEYS_KEYS_MISMATCH = 7600,
  RUSTLS_RESULT_INCONSISTENT_KEYS_UNKNOWN = 7601,
  RUSTLS_RESULT_INVALID_ENCRYPTED_CLIENT_HELLO_INVALID_CONFIG_LIST = 7700,
  RUSTLS_RESULT_INVALID_ENCRYPTED_CLIENT_HELLO_NO_COMPATIBLE_CONFIG = 7701,
  RUSTLS_RESULT_INVALID_ENCRYPTED_CLIENT_HELLO_SNI_REQUIRED = 7702,
};
#if __STDC_VERSION__ >= 202311L
typedef enum rustls_result rustls_result;
#else
typedef uint32_t rustls_result;
#endif // __STDC_VERSION__ >= 202311L

/**
 * Definitions of known TLS protocol versions.
 */
typedef enum rustls_tls_version {
  RUSTLS_TLS_VERSION_UNKNOWN = 0,
  RUSTLS_TLS_VERSION_SSLV2 = 512,
  RUSTLS_TLS_VERSION_SSLV3 = 768,
  RUSTLS_TLS_VERSION_TLSV1_0 = 769,
  RUSTLS_TLS_VERSION_TLSV1_1 = 770,
  RUSTLS_TLS_VERSION_TLSV1_2 = 771,
  RUSTLS_TLS_VERSION_TLSV1_3 = 772,
} rustls_tls_version;

/**
 * Describes which sort of handshake happened.
 */
typedef enum rustls_handshake_kind {
  /**
   * The type of handshake could not be determined.
   *
   * This variant should not be used.
   */
  RUSTLS_HANDSHAKE_KIND_UNKNOWN = 0,
  /**
   * A full TLS handshake.
   *
   * This is the typical TLS connection initiation process when resumption is
   * unavailable and the initial ClientHello is accepted by the server.
   */
  RUSTLS_HANDSHAKE_KIND_FULL = 1,
  /**
   * A full TLS handshake, with an extra round-trip for a hello retry request.
   *
   * The server can respond with a hello retry request (HRR) if the initial ClientHello
   * is unacceptable for several reasons, the most likely being that the client offered
   * no supported key shares.
   */
  RUSTLS_HANDSHAKE_KIND_FULL_WITH_HELLO_RETRY_REQUEST = 2,
  /**
   * A resumed TLS handshake.
   *
   * Resumed handshakes involve fewer round trips and less cryptography than
   * full ones, but can only happen when the peers have previously done a full
   * handshake together, and then remember data about it.
   */
  RUSTLS_HANDSHAKE_KIND_RESUMED = 3,
} rustls_handshake_kind;

/**
 * A parsed ClientHello produced by a `rustls_acceptor`.
 *
 * It is used to check server name indication (SNI), ALPN protocols,
 * signature schemes, and cipher suites. It can be combined with a
 * `rustls_server_config` to build a `rustls_connection`.
 */
typedef struct rustls_accepted rustls_accepted;

/**
 * Represents a TLS alert resulting from accepting a client.
 */
typedef struct rustls_accepted_alert rustls_accepted_alert;

/**
 * A buffer and parser for ClientHello bytes.
 *
 * This allows reading ClientHello before choosing a `rustls_server_config`.
 *
 * It's useful when the server config will be based on parameters in the
 * ClientHello: server name indication (SNI), ALPN protocols, signature
 * schemes, and cipher suites.
 *
 * In particular, if a server wants to do some potentially expensive work
 * to load a certificate for a given hostname, `rustls_acceptor` allows doing
 * that asynchronously, as opposed to `rustls_server_config_builder_set_hello_callback()`,
 * which doesn't work well for asynchronous I/O.
 *
 * The general flow is:
 *
 * - `rustls_acceptor_new()`
 * - Loop:
 *   - Read bytes from the network with `rustls_acceptor_read_tls()`.
 *   - If successful, parse those bytes with `rustls_acceptor_accept()`.
 *   - If that returns `RUSTLS_RESULT_ACCEPTOR_NOT_READY`, continue.
 *   - Otherwise, break.
 * - If `rustls_acceptor_accept()` returned `RUSTLS_RESULT_OK`:
 *   - Examine the resulting `rustls_accepted`.
 *   - Create or select a `rustls_server_config`.
 *   - Call `rustls_accepted_into_connection()`.
 * - Otherwise, there was a problem with the ClientHello data and the
 *   connection should be rejected.
 */
typedef struct rustls_acceptor rustls_acceptor;

/**
 * An X.509 certificate, as used in rustls.
 * Corresponds to `CertificateDer` in the Rust pki-types API.
 *
 * See also the rustls-pki-types documentation for [`CertificateDer`].
 *
 * [`CertificateDer`]: https://docs.rs/rustls-pki-types/latest/rustls_pki_types/struct.CertificateDer.html
 */
typedef struct rustls_certificate rustls_certificate;

/**
 * The complete chain of certificates to send during a TLS handshake,
 * plus a private key that matches the end-entity (leaf) certificate.
 *
 * Corresponds to `CertifiedKey` in the Rust API.
 *
 * See also the rustls documentation for [`CertifiedKey`].
 *
 * [`CertifiedKey`]: https://docs.rs/rustls/latest/rustls/sign/struct.CertifiedKey.html
 */
typedef struct rustls_certified_key rustls_certified_key;

/**
 * A built client certificate verifier that can be provided to a `rustls_server_config_builder`
 * with `rustls_server_config_builder_set_client_verifier`.
 */
typedef struct rustls_client_cert_verifier rustls_client_cert_verifier;

/**
 * A client config that is done being constructed and is now read-only.
 *
 * Under the hood, this object corresponds to an `Arc<ClientConfig>`.
 *
 * See also the rustls documentation for [`ClientConfig`].
 *
 * [`ClientConfig`]: https://docs.rs/rustls/latest/rustls/struct.ClientConfig.html
 */
typedef struct rustls_client_config rustls_client_config;

/**
 * A client config being constructed.
 *
 * A builder can be modified by, e.g. `rustls_client_config_builder_set_server_verifier`.
 * Once you're done configuring settings, call `rustls_client_config_builder_build`
 * to turn it into a `rustls_client_config`.
 *
 * Alternatively, if an error occurs or, you don't wish to build a config,
 * call `rustls_client_config_builder_free` to free the builder directly.
 *
 * This object is not safe for concurrent mutation. Under the hood,
 * it corresponds to a `Box<ClientConfig>`.
 *
 * See also the rustls documentation for [`ConfigBuilder`].
 *
 * [`ConfigBuilder`]: https://docs.rs/rustls/latest/rustls/struct.ConfigBuilder.html
 */
typedef struct rustls_client_config_builder rustls_client_config_builder;

/**
 * A C representation of a Rustls `Connection`.
 */
typedef struct rustls_connection rustls_connection;

/**
 * A C representation of a Rustls
 * [`CryptoProvider`](https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html).
 */
typedef struct rustls_crypto_provider rustls_crypto_provider;

/**
 * A `rustls_crypto_provider` builder.
 */
typedef struct rustls_crypto_provider_builder rustls_crypto_provider_builder;

/**
 * A collection of supported Hybrid Public Key Encryption (HPKE) suites.
 *
 * `rustls_hpke` can be provided to `rustls_client_config_builder_enable_ech` and
 * `rustls_client_config_builder_enable_ech_grease()` to customize a
 * `rustls_client_config_builder` to use Encrypted Client Hello (ECH).
 */
typedef struct rustls_hpke rustls_hpke;

/**
 * An alias for `struct iovec` from uio.h (on Unix) or `WSABUF` on Windows.
 *
 * On Unix, cast `const rustls_iovec *` to `const struct iovec *`. On Windows,
 * cast it to `const WSABUF *`; `LPWSABUF` is an alias for the non-const pointer
 * `WSABUF *`.
 *
 * See [`std::io::IoSlice`] for details on interoperability with platform-specific
 * vectored IO.
 *
 * [`std::io::IoSlice`]: https://doc.rust-lang.org/std/io/struct.IoSlice.html
 */
typedef struct rustls_iovec rustls_iovec;

/**
 * A root certificate store.
 *
 * See also the rustls documentation for [`RootCertStore`].
 *
 * [`RootCertStore`]: https://docs.rs/rustls/latest/rustls/struct.RootCertStore.html
 */
typedef struct rustls_root_cert_store rustls_root_cert_store;

/**
 * A `rustls_root_cert_store` being constructed.
 *
 * A builder can be modified by adding trust anchor root certificates with
 * `rustls_root_cert_store_builder_add_pem`. Once you're done adding root certificates,
 * call `rustls_root_cert_store_builder_build` to turn it into a `rustls_root_cert_store`.
 * This object is not safe for concurrent mutation.
 */
typedef struct rustls_root_cert_store_builder rustls_root_cert_store_builder;

/**
 * A built server certificate verifier that can be provided to a `rustls_client_config_builder`
 * with `rustls_client_config_builder_set_server_verifier`.
 */
typedef struct rustls_server_cert_verifier rustls_server_cert_verifier;

/**
 * A server config that is done being constructed and is now read-only.
 *
 * Under the hood, this object corresponds to an `Arc<ServerConfig>`.
 *
 * See also the rustls documentation for [`ServerConfig`].
 *
 * [`ServerConfig`]: https://docs.rs/rustls/latest/rustls/struct.ServerConfig.html
 */
typedef struct rustls_server_config rustls_server_config;

/**
 * A server config being constructed.
 *
 * A builder can be modified by, e.g. `rustls_server_config_builder_set_certified_keys`.
 * Once you're done configuring settings, call `rustls_server_config_builder_build`
 * to turn it into a `rustls_server_config`.
 *
 * Alternatively, if an error occurs or, you don't wish to build a config,
 * call `rustls_server_config_builder_free` to free the builder directly.
 *
 * This object is not safe for concurrent mutation.
 *
 * See also the rustls documentation for [`ConfigBuilder`].
 *
 * [`ConfigBuilder`]: https://docs.rs/rustls/latest/rustls/struct.ConfigBuilder.html
 */
typedef struct rustls_server_config_builder rustls_server_config_builder;

/**
 * A signing key that can be used to construct a certified key.
 */
typedef struct rustls_signing_key rustls_signing_key;

/**
 * A read-only view of a slice of Rust byte slices.
 *
 * This is used to pass data from rustls-ffi to callback functions provided
 * by the user of the API. Because Vec and slice are not `#[repr(C)]`, we
 * provide access via a pointer to an opaque struct and an accessor method
 * that acts on that struct to get entries of type `rustls_slice_bytes`.
 * Internally, the pointee is a `&[&[u8]]`.
 *
 * The memory exposed is available as specified by the function
 * using this in its signature. For instance, when this is a parameter to a
 * callback, the lifetime will usually be the duration of the callback.
 * Functions that receive one of these must not call its methods beyond the
 * allowed lifetime.
 */
typedef struct rustls_slice_slice_bytes rustls_slice_slice_bytes;

/**
 * A read-only view of a slice of multiple Rust `&str`'s (that is, multiple
 * strings).
 *
 * Like `rustls_str`, this guarantees that each string contains
 * UTF-8 and no NUL bytes. Strings are not NUL-terminated.
 *
 * This is used to pass data from rustls-ffi to callback functions provided
 * by the user of the API. Because Vec and slice are not `#[repr(C)]`, we
 * can't provide a straightforward `data` and `len` structure. Instead, we
 * provide access via a pointer to an opaque struct and accessor methods.
 * Internally, the pointee is a `&[&str]`.
 *
 * The memory exposed is available as specified by the function
 * using this in its signature. For instance, when this is a parameter to a
 * callback, the lifetime will usually be the duration of the callback.
 * Functions that receive one of these must not call its methods beyond the
 * allowed lifetime.
 */
typedef struct rustls_slice_str rustls_slice_str;

/**
 * A cipher suite supported by rustls.
 */
typedef struct rustls_supported_ciphersuite rustls_supported_ciphersuite;

/**
 * A client certificate verifier being constructed.
 *
 * A builder can be modified by, e.g. `rustls_web_pki_client_cert_verifier_builder_add_crl`.
 *
 * Once you're done configuring settings, call `rustls_web_pki_client_cert_verifier_builder_build`
 * to turn it into a `rustls_client_cert_verifier`.
 *
 * This object is not safe for concurrent mutation.
 *
 * See also the rustls documentation for [`ClientCertVerifierBuilder`].
 *
 * [`ClientCertVerifierBuilder`]: https://docs.rs/rustls/latest/rustls/server/struct.ClientCertVerifierBuilder.html
 */
typedef struct rustls_web_pki_client_cert_verifier_builder rustls_web_pki_client_cert_verifier_builder;

/**
 * A server certificate verifier being constructed.
 *
 * A builder can be modified by, e.g. `rustls_web_pki_server_cert_verifier_builder_add_crl`.
 *
 * Once you're done configuring settings, call `rustls_web_pki_server_cert_verifier_builder_build`
 * to turn it into a `rustls_server_cert_verifier`. This object is not safe for concurrent mutation.
 *
 * See also the rustls documentation for [`ServerCertVerifierBuilder`].
 *
 * [`ServerCertVerifierBuilder`]: https://docs.rs/rustls/latest/rustls/client/struct.ServerCertVerifierBuilder.html
 */
typedef struct rustls_web_pki_server_cert_verifier_builder rustls_web_pki_server_cert_verifier_builder;

/**
 * A return value for a function that may return either success (0) or a
 * non-zero value representing an error.
 *
 * The values should match socket error numbers for your operating system --
 * for example, the integers for `ETIMEDOUT`, `EAGAIN`, or similar.
 */
typedef int rustls_io_result;

/**
 * A callback for `rustls_connection_read_tls`.
 *
 * An implementation of this callback should attempt to read up to `n` bytes from the
 * network, storing them in `buf`. If any bytes were stored, the implementation should
 * set `out_n` to the number of bytes stored and return 0.
 *
 * If there was an error, the implementation should return a nonzero `rustls_io_result`,
 * which will be passed through to the caller.
 *
 * On POSIX systems, returning `errno` is convenient.
 *
 * On other systems, any appropriate error code works.
 *
 * It's best to make one read attempt to the network per call. Additional reads will
 * be triggered by subsequent calls to one of the `_read_tls` methods.
 *
 * `userdata` is the value passed to the function invoking this callback. In most cases that
 * should point to a struct containing, at a minimum, a file descriptor.
 *
 * The `buf` and `out_n` pointers are borrowed and should not be retained across calls.
 */
typedef rustls_io_result (*rustls_read_callback)(void *userdata,
                                                 uint8_t *buf,
                                                 size_t n,
                                                 size_t *out_n);

/**
 * A read-only view on a Rust `&str`.
 *
 * The contents are guaranteed to be valid UTF-8.
 *
 * As an additional guarantee on top of Rust's normal UTF-8 guarantee,
 * a `rustls_str` is guaranteed not to contain internal NUL bytes. Its `data`
 * and `len` fields can be passed to APIs that accept an explicit byte length.
 * The `data` field is not NUL-terminated and must not be passed to functions
 * that expect a C string.
 *
 * The memory exposed is available as specified by the function
 * using this in its signature. For instance, when this is a parameter to a
 * callback, the lifetime will usually be the duration of the callback.
 * Functions that receive one of these must not dereference the data pointer
 * beyond the allowed lifetime.
 */
typedef struct rustls_str {
  const char *data;
  size_t len;
} rustls_str;

/**
 * A read-only view on a Rust byte slice.
 *
 * This is used to pass data from rustls-ffi to callback functions provided
 * by the user of the API.
 * `len` indicates the number of bytes that can be safely read.
 *
 * The memory exposed is available as specified by the function
 * using this in its signature. For instance, when this is a parameter to a
 * callback, the lifetime will usually be the duration of the callback.
 * Functions that receive one of these must not dereference the data pointer
 * beyond the allowed lifetime.
 */
typedef struct rustls_slice_bytes {
  const uint8_t *data;
  size_t len;
} rustls_slice_bytes;

/**
 * A callback for `rustls_connection_write_tls` or `rustls_accepted_alert_write_tls`.
 *
 * An implementation of this callback should attempt to write the `n` bytes in `buf`
 * to the network.
 *
 * If any bytes were written, the implementation should set `out_n` to the number of
 * bytes written and return 0.
 *
 * If there was an error, the implementation should return a nonzero `rustls_io_result`,
 * which will be passed through to the caller.
 *
 * On POSIX systems, returning `errno` is convenient.
 *
 * On other systems, any appropriate error code works.
 *
 * It's best to make one write attempt to the network per call. Additional writes will
 * be triggered by subsequent calls to `rustls_connection_write_tls`.
 *
 * `userdata` is the value passed to the function invoking this callback. In most cases that
 * should point to a struct containing, at a minimum, a file descriptor.
 *
 * The `buf` and `out_n` pointers are borrowed and should not be retained across calls.
 */
typedef rustls_io_result (*rustls_write_callback)(void *userdata,
                                                  const uint8_t *buf,
                                                  size_t n,
                                                  size_t *out_n);

/**
 * User-provided input to a custom certificate verifier callback.
 *
 * See `rustls_client_config_builder_dangerous_set_certificate_verifier()`.
 */
typedef void *rustls_verify_server_cert_user_data;

/**
 * Input to a custom certificate verifier callback.
 *
 * See `rustls_client_config_builder_dangerous_set_certificate_verifier()`.
 *
 * server_name can contain a hostname, an IPv4 address in textual form, or an
 * IPv6 address in textual form.
 */
typedef struct rustls_verify_server_cert_params {
  struct rustls_slice_bytes end_entity_cert_der;
  const struct rustls_slice_slice_bytes *intermediate_certs_der;
  struct rustls_str server_name;
  struct rustls_slice_bytes ocsp_response;
} rustls_verify_server_cert_params;

/**
 * A callback that is invoked to verify a server certificate.
 *
 * `userdata` is the value set with `rustls_connection_set_userdata`. `params` and all data
 * referenced by its fields are borrowed and valid only for the duration of the callback.
 *
 * See `rustls_client_config_builder_dangerous_set_certificate_verifier` for return values and
 * thread-safety requirements.
 */
typedef uint32_t (*rustls_verify_server_cert_callback)(rustls_verify_server_cert_user_data userdata,
                                                       const struct rustls_verify_server_cert_params *params);

/**
 * An optional callback for logging key material.
 *
 * See the documentation on `rustls_client_config_builder_set_key_log` and
 * `rustls_server_config_builder_set_key_log` for more information about the
 * lifetimes of the parameters.
 */
typedef void (*rustls_keylog_log_callback)(struct rustls_str label,
                                           const uint8_t *client_random,
                                           size_t client_random_len,
                                           const uint8_t *secret,
                                           size_t secret_len);

/**
 * An optional callback for deciding if key material will be logged.
 *
 * See the documentation on `rustls_client_config_builder_set_key_log` and
 * `rustls_server_config_builder_set_key_log` for more information about the
 * lifetimes of the parameters.
 */
typedef int (*rustls_keylog_will_log_callback)(struct rustls_str label);

/**
 * Numeric representation of a log level.
 *
 * Passed as a field of the `rustls_log_params` passed to a log callback.
 * Use with `rustls_log_level_str` to convert to a string label.
 */
typedef size_t rustls_log_level;

/**
 * Parameter structure passed to a `rustls_log_callback`.
 */
typedef struct rustls_log_params {
  /**
   * The log level the message was logged at.
   */
  rustls_log_level level;
  /**
   * The message that was logged.
   */
  struct rustls_str message;
} rustls_log_params;

/**
 * A callback that is invoked for messages logged by rustls.
 *
 * `params` and the message it references are borrowed and valid only for the duration of the
 * callback. `userdata` is the value set with `rustls_connection_set_userdata`.
 */
typedef void (*rustls_log_callback)(void *userdata, const struct rustls_log_params *params);

/**
 * A callback for `rustls_connection_write_tls_vectored`.
 *
 * An implementation of this callback should attempt to write the bytes in
 * the given `count` iovecs to the network.
 *
 * If any bytes were written, the implementation should set `out_n` to the number of
 * bytes written and return 0.
 *
 * If there was an error, the implementation should return a nonzero `rustls_io_result`,
 * which will be passed through to the caller.
 *
 * On POSIX systems, returning `errno` is convenient.
 *
 * On other systems, any appropriate error code works.
 *
 * It's best to make one write attempt to the network per call. Additional writes will
 * be triggered by subsequent calls to one of the `_write_tls` methods.
 *
 * `userdata` is the value passed to the function invoking this callback. In most cases that
 * should point to a struct containing, at a minimum, a file descriptor.
 *
 * The `iov` and `out_n` pointers are borrowed and should not be retained across calls.
 */
typedef rustls_io_result (*rustls_write_vectored_callback)(void *userdata,
                                                           const struct rustls_iovec *iov,
                                                           size_t count,
                                                           size_t *out_n);

/**
 * Any context information the callback will receive when invoked.
 */
typedef void *rustls_client_hello_userdata;

/**
 * A read-only view on a Rust slice of 16-bit integers in platform endianness.
 *
 * This is used to pass data from rustls-ffi to callback functions provided
 * by the user of the API.
 * `len` indicates the number of 16-bit integers that can be safely read.
 *
 * The memory exposed is available as specified by the function
 * using this in its signature. For instance, when this is a parameter to a
 * callback, the lifetime will usually be the duration of the callback.
 * Functions that receive one of these must not dereference the data pointer
 * beyond the allowed lifetime.
 */
typedef struct rustls_slice_u16 {
  const uint16_t *data;
  size_t len;
} rustls_slice_u16;

/**
 * The TLS ClientHello information provided to a `rustls_client_hello_callback`.
 *
 * `server_name` is the value of the server name indication (SNI) extension provided
 * by the client. If the client did not send an SNI, the length of this
 * `rustls_str` will be 0.
 *
 * `signature_schemes` carries the values supplied by the client or, if the
 * client did not send this TLS extension, the default schemes in the rustls library.
 * See the rustls documentation for [`SignatureScheme`] for more information.
 *
 * `named_groups` carries the values of the `named_groups` extension sent by the
 * client. If the client did not send a `named_groups` extension, the length of
 * this `rustls_slice_u16` will be 0. The meaning of this extension differs
 * based on TLS version. See the rustls documentation for
 * [`ClientHello::named_groups`] for more information.
 *
 * `alpn` carries the list of ALPN protocol names that the client proposed to
 * the server. Again, the length of this list will be 0 if none were supplied.
 *
 * All this data, when passed to a callback function, is only accessible during
 * the call and may not be modified. Users of this API must copy any values that
 * they want to access after the callback returns.
 *
 * EXPERIMENTAL: this feature of rustls-ffi is likely to change in the future, as
 * the rustls library is re-evaluating its current approach to ClientHello handling.
 *
 * [`SignatureScheme`]: https://docs.rs/rustls/latest/rustls/enum.SignatureScheme.html
 * [`ClientHello::named_groups`]: https://rustls.dev/docs/server/struct.ClientHello.html#method.named_groups
 */
typedef struct rustls_client_hello {
  struct rustls_str server_name;
  struct rustls_slice_u16 signature_schemes;
  struct rustls_slice_u16 named_groups;
  const struct rustls_slice_slice_bytes *alpn;
} rustls_client_hello;

/**
 * Prototype of a callback that can be installed by the application at the
 * `rustls_server_config`.
 *
 * This callback will be invoked by a `rustls_connection` once the TLS ClientHello
 * message has been received.
 *
 * `userdata` will be set based on `rustls_connection_set_userdata`.
 *
 * `hello` contains the client parameters parsed by rustls. See the definition of
 * `rustls_client_hello` for details.
 *
 * **Note:**
 *
 * - The passed-in `hello` and all its values are only valid during the callback invocation.
 * - The callback must be safe to call multiple times concurrently
 *   with the same `userdata`, unless there is only a single config and connection
 *   where it is installed.
 *
 * EXPERIMENTAL: this feature of rustls-ffi is likely to change in the future, as
 * the rustls library is re-evaluating its current approach to ClientHello handling.
 */
typedef const struct rustls_certified_key *(*rustls_client_hello_callback)(rustls_client_hello_userdata userdata,
                                                                           const struct rustls_client_hello *hello);

/**
 * Any context information the callback will receive when invoked.
 */
typedef void *rustls_session_store_userdata;

/**
 * Prototype of a callback that can be installed by the application at the
 * `rustls_server_config` or `rustls_client_config`.
 *
 * This callback will be invoked by a TLS session when looking up the data
 * for a TLS session ID.
 *
 * `userdata` will be supplied based on `rustls_connection_set_userdata`.
 *
 * The `buf` points to `count` consecutive bytes where the
 * callback is expected to copy the result to. The number of copied bytes
 * needs to be written to `out_n`. The callback should not read any
 * data from `buf`.
 *
 * If the value to copy is larger than `count`, the callback should never
 * do a partial copy but instead remove the value from its store and
 * act as if it was never found.
 *
 * The callback should return `RUSTLS_RESULT_OK` to indicate that a value was
 * retrieved and written in its entirety into `buf`, or `RUSTLS_RESULT_NOT_FOUND`
 * if no session was retrieved.
 *
 * When `remove_after` is nonzero, the returned data needs to be removed
 * from the store.
 *
 * **Notes:**
 *
 * - The passed-in `key` and `buf` are only valid during the callback invocation.
 * - Callbacks shared by several sessions through a common config must be thread-safe.
 */
typedef uint32_t (*rustls_session_store_get_callback)(rustls_session_store_userdata userdata,
                                                      const struct rustls_slice_bytes *key,
                                                      int remove_after,
                                                      uint8_t *buf,
                                                      size_t count,
                                                      size_t *out_n);

/**
 * Prototype of a callback that can be installed by the application at the
 * `rustls_server_config` or `rustls_client_config`.
 *
 * This callback will be invoked when a resumable TLS session has been created and a session ID
 * has either been sent to the client or received from the server.
 *
 * `userdata` will be supplied based on `rustls_connection_set_userdata`.
 *
 * The callback should return `RUSTLS_RESULT_OK` to indicate that a value was
 * successfully stored, or `RUSTLS_RESULT_IO` on failure.
 *
 * **Notes:**
 *
 * - The passed-in `key` and `val` are only valid during the callback invocation.
 * - Callbacks shared by several sessions through a common config must be thread-safe.
 */
typedef uint32_t (*rustls_session_store_put_callback)(rustls_session_store_userdata userdata,
                                                      const struct rustls_slice_bytes *key,
                                                      const struct rustls_slice_bytes *val);

/**
 * Rustls' list of supported protocol versions. The length of the array is
 * given by `RUSTLS_ALL_VERSIONS_LEN`.
 */
extern const uint16_t RUSTLS_ALL_VERSIONS[2];

/**
 * The length of the array `RUSTLS_ALL_VERSIONS`.
 */
extern const size_t RUSTLS_ALL_VERSIONS_LEN;

/**
 * Rustls' default list of protocol versions. The length of the array is
 * given by `RUSTLS_DEFAULT_VERSIONS_LEN`.
 */
extern const uint16_t RUSTLS_DEFAULT_VERSIONS[2];

/**
 * The length of the array `RUSTLS_DEFAULT_VERSIONS`.
 */
extern const size_t RUSTLS_DEFAULT_VERSIONS_LEN;

/**
 * Create and return a new `rustls_acceptor`.
 *
 * Caller owns the pointed-to memory and must eventually free it with
 * `rustls_acceptor_free()`.
 */
struct rustls_acceptor *rustls_acceptor_new(void);

/**
 * Free a `rustls_acceptor`.
 *
 * **Parameters:**
 *
 * - `acceptor`: The `rustls_acceptor` to free.
 *
 * Calling with NULL is fine. Must not be called twice with the same value.
 */
void rustls_acceptor_free(struct rustls_acceptor *acceptor);

/**
 * Read some TLS bytes from the network into internal buffers.
 *
 * The actual network I/O is performed by `callback`, which you provide.
 * Rustls will invoke your callback with a suitable buffer to store the
 * read bytes into. You don't have to fill it up, just fill with as many
 * bytes as you get in one syscall.
 *
 * **Parameters:**
 *
 * - `acceptor`: The `rustls_acceptor` to read bytes into.
 * - `callback`: A function that will perform the actual network I/O.
 *   It must be valid to call with the given `userdata` parameter until
 *   this function call returns.
 * - `userdata`: An opaque parameter to be passed directly to `callback`.
 *   Note: this is distinct from the `userdata` parameter set with
 *   `rustls_connection_set_userdata`.
 * - `out_n`: An output parameter that receives the number of bytes read when
 *   this function returns 0. It is unchanged on error.
 *
 * **Returns:**
 *
 * - 0: Success. You should call `rustls_acceptor_accept()` next.
 * - Any non-zero value: error.
 *
 * This function passes through return values from `callback`. Typically
 * `callback` should return an errno value. See `rustls_read_callback()` for
 * more details.
 */
rustls_io_result rustls_acceptor_read_tls(struct rustls_acceptor *acceptor,
                                          rustls_read_callback callback,
                                          void *userdata,
                                          size_t *out_n);

/**
 * Parse all TLS bytes read so far.
 *
 * If those bytes make up a ClientHello, create a `rustls_accepted` from them.
 *
 * **Parameters:**
 *
 * - `acceptor`: The `rustls_acceptor` to access.
 * - `out_accepted`: An output parameter. The pointed-to pointer will be set
 *   to a new `rustls_accepted` only when the function returns
 *   `RUSTLS_RESULT_OK`. The memory is owned by the caller and must eventually
 *   be freed with `rustls_accepted_free`.
 * - `out_alert`: An output parameter. The pointed-to pointer will be set
 *   to a new `rustls_accepted_alert` only when a complete ClientHello is rejected.
 *   `RUSTLS_RESULT_ACCEPTOR_NOT_READY` and earlier errors such as a NULL parameter do not
 *   write it. The memory is owned by the caller and must eventually
 *   be freed with `rustls_accepted_alert_free`. The caller should call
 *   `rustls_accepted_alert_write_tls` to write the alert bytes to the TLS
 *   connection before freeing the `rustls_accepted_alert`.
 *
 * The function does not initialize either output pointer. It writes at most one of
 * `out_accepted` and `out_alert`. The other retains its original value.
 *
 * **Returns:**
 *
 * - `RUSTLS_RESULT_OK`: a ClientHello has successfully been parsed.
 *   A pointer to a newly allocated `rustls_accepted` has been written to
 *   `*out_accepted`.
 * - `RUSTLS_RESULT_ACCEPTOR_NOT_READY`: a full ClientHello has not yet been read.
 *   Read more TLS bytes to continue.
 * - Any other `rustls_result`: the TLS bytes read so far cannot be parsed
 *   as a ClientHello, and reading additional bytes won't help.
 *
 * **Memory and lifetimes:**
 *
 * After this method returns `RUSTLS_RESULT_OK`, `acceptor` is
 * still allocated and valid. It needs to be freed regardless of success
 * or failure of this function.
 *
 * Calling `rustls_acceptor_accept()` multiple times on the same
 * `rustls_acceptor` is acceptable from a memory perspective but pointless
 * from a protocol perspective.
 */
rustls_result rustls_acceptor_accept(struct rustls_acceptor *acceptor,
                                     struct rustls_accepted **out_accepted,
                                     struct rustls_accepted_alert **out_alert);

/**
 * Get the server name indication (SNI) from the ClientHello.
 *
 * **Parameters:**
 *
 * - `accepted`: The `rustls_accepted` to access.
 *
 * **Returns:**
 *
 * A `rustls_str` containing the SNI field.
 *
 * The returned value is valid until `rustls_accepted_into_connection` or
 * `rustls_accepted_free` is called on the same `accepted`. It is not owned
 * by the caller and does not need to be freed.
 *
 * This will be a zero-length `rustls_str` in these error cases:
 *
 * - The ClientHello did not contain an SNI extension.
 * - The SNI contains a NUL byte.
 * - The `accepted` parameter was NULL.
 * - The `accepted` parameter was already transformed into a connection
 *   with `rustls_accepted_into_connection`.
 */
struct rustls_str rustls_accepted_server_name(const struct rustls_accepted *accepted);

/**
 * Get the i-th entry in the list of signature schemes offered in the ClientHello.
 *
 * This is useful in selecting a server certificate when there are multiple
 * available for the same server name, for instance when selecting
 * between an RSA and an ECDSA certificate.
 *
 * **Parameters:**
 *
 * - `accepted`: The `rustls_accepted` to access.
 * - `i`: Fetch the signature scheme at this offset.
 *
 * **Returns:**
 *
 * A TLS Signature Scheme from the [IANA TLS SignatureScheme registry].
 *
 * This will be 0 in these cases:
 *
 * - `i` is greater than or equal to the number of offered signature schemes.
 * - `accepted` is NULL.
 * - `rustls_accepted_into_connection` has already been called with `accepted`.
 *
 * [IANA TLS SignatureScheme registry]: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme
 */
uint16_t rustls_accepted_signature_scheme(const struct rustls_accepted *accepted,
                                          size_t i);

/**
 * Get the i-th entry in the list of cipher suites offered in the ClientHello.
 *
 * **Parameters:**
 *
 * - `accepted`: The `rustls_accepted` to access.
 * - `i`: Fetch the cipher suite at this offset.
 *
 * **Returns:**
 *
 * A cipher suite value from the [IANA TLS Cipher Suites registry].
 *
 * This will be 0 in these cases:
 *
 * - `i` is greater than or equal to the number of offered cipher suites.
 * - `accepted` is NULL.
 * - `rustls_accepted_into_connection` has already been called with `accepted`.
 *
 * Note that 0 is technically a valid cipher suite "TLS_NULL_WITH_NULL_NULL",
 * but this library will never support null ciphers.
 *
 * [IANA TLS Cipher Suites registry]: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
 */
uint16_t rustls_accepted_cipher_suite(const struct rustls_accepted *accepted,
                                      size_t i);

/**
 * Get the i-th entry in the list of ALPN protocols requested in the ClientHello.
 *
 * **Parameters:**
 *
 * - `accepted`: The `rustls_accepted` to access.
 * - `i`: Fetch the ALPN value at this offset.
 *
 * **Returns:**
 *
 * A `rustls_slice_bytes` containing the i-th ALPN protocol. This may
 * contain internal NUL bytes and is not guaranteed to contain valid
 * UTF-8.
 *
 * This will be a zero-length `rustls_slice_bytes` in these cases:
 *
 * - `i` is greater than or equal to the number of offered ALPN protocols.
 * - The client did not offer the ALPN extension.
 * - The `accepted` parameter was already transformed into a connection
 *   with `rustls_accepted_into_connection`.
 *
 * The returned value is valid until `rustls_accepted_into_connection` or
 * `rustls_accepted_free` is called on the same `accepted`. It is not owned
 * by the caller and does not need to be freed.
 *
 * If you are calling this from Rust, note that the `'static` lifetime
 * in the return signature is fake and must not be relied upon.
 */
struct rustls_slice_bytes rustls_accepted_alpn(const struct rustls_accepted *accepted, size_t i);

/**
 * Turn a `rustls_accepted` into a `rustls_connection`, given the provided
 * `rustls_server_config`.
 *
 * **Parameters:**
 *
 * - `accepted`: The `rustls_accepted` to transform.
 * - `config`: The configuration with which to create this connection.
 * - `out_conn`: An output parameter. The pointed-to pointer will be set
 *   to a new `rustls_connection` only when the function returns
 *   `RUSTLS_RESULT_OK`. The caller owns the connection and must eventually
 *   free it with `rustls_connection_free`.
 * - `out_alert`: An output parameter. The pointed-to pointer will be set
 *   to a new `rustls_accepted_alert` when constructing the connection fails
 *   with a TLS error. Earlier errors, such as a NULL parameter, do not write it.
 *   The memory is owned by the caller and must eventually
 *   be freed with `rustls_accepted_alert_free`. The caller should call
 *   `rustls_accepted_alert_write_tls` to write the alert bytes to
 *   the TLS connection before freeing the `rustls_accepted_alert`.
 *
 * The function does not initialize either output pointer. It writes at most one of
 * `out_conn` and `out_alert`. The other retains its original value.
 *
 * **Returns:**
 *
 * - `RUSTLS_RESULT_OK`: The `accepted` parameter was successfully
 *   transformed into a `rustls_connection`, and `*out_conn` was written to.
 * - `RUSTLS_RESULT_ALREADY_USED`: This function was called twice on the
 *   same `rustls_accepted`.
 * - `RUSTLS_RESULT_NULL_PARAMETER`: One of the input parameters was NULL.
 * - Any other `rustls_result`: constructing the connection failed and an alert was written
 *   to `out_alert`.
 *
 * **Memory and lifetimes:**
 *
 * In both success and failure cases, this consumes the contents of
 * `accepted` but does not free its allocated memory. In either case,
 * call `rustls_accepted_free` to avoid a memory leak.
 *
 * Calling accessor methods on an `accepted` after consuming it will
 * return zero or default values.
 *
 * This function does not take ownership of `config`. It does increment
 * `config`'s internal reference count, indicating that the
 * `rustls_connection` may hold a reference to it until it is done.
 * See the documentation for `rustls_connection` for details.
 */
rustls_result rustls_accepted_into_connection(struct rustls_accepted *accepted,
                                              const struct rustls_server_config *config,
                                              struct rustls_connection **out_conn,
                                              struct rustls_accepted_alert **out_alert);

/**
 * Free a `rustls_accepted`.
 *
 * **Parameters:**
 *
 * - `accepted`: The `rustls_accepted` to free.
 *
 * Calling with NULL is fine. Must not be called twice with the same value.
 */
void rustls_accepted_free(struct rustls_accepted *accepted);

/**
 * Write some TLS bytes (an alert) to the network.
 *
 * The actual network I/O is performed by `callback`, which you provide.
 * Rustls will invoke your callback with a suitable buffer containing TLS
 * bytes to send. You don't have to write them all, just as many as you can
 * in one syscall.
 *
 * The `userdata` parameter is passed through directly to `callback`. Note that
 * this is distinct from the `userdata` parameter set with
 * `rustls_connection_set_userdata`.
 *
 * On success, returns 0 and writes the number of bytes written to `out_n`.
 * On error, returns an errno value passed through from `callback` and leaves
 * `out_n` unchanged. See `rustls_write_callback` or rustls's [`AcceptedAlert`]
 * for more details.
 *
 * [`AcceptedAlert`]: https://docs.rs/rustls/latest/rustls/server/struct.AcceptedAlert.html
 */
rustls_io_result rustls_accepted_alert_write_tls(struct rustls_accepted_alert *accepted_alert,
                                                 rustls_write_callback callback,
                                                 void *userdata,
                                                 size_t *out_n);

/**
 * Free a `rustls_accepted_alert`.
 *
 * **Parameters:**
 *
 * - `accepted_alert`: The `rustls_accepted_alert` to free.
 *
 * Calling with NULL is fine. Must not be called twice with the same value.
 */
void rustls_accepted_alert_free(struct rustls_accepted_alert *accepted_alert);

/**
 * Get the certificate's DER data.
 *
 * On success, `out_der_data` receives a borrowed pointer and `out_der_len` receives its length.
 * The data remains owned by `cert` and is valid only as long as `cert`. The caller must not
 * modify or free it.
 *
 * On error, the output parameters are unchanged.
 */
rustls_result rustls_certificate_get_der(const struct rustls_certificate *cert,
                                         const uint8_t **out_der_data,
                                         size_t *out_der_len);

/**
 * Build a `rustls_certified_key` from a certificate chain and a private key
 * and the default process-wide crypto provider.
 *
 * `cert_chain` must point to a buffer of `cert_chain_len` bytes, containing
 * a series of PEM-encoded certificates, with the end-entity (leaf)
 * certificate first.
 *
 * `private_key` must point to a buffer of `private_key_len` bytes, containing
 * a PEM-encoded private key in either PKCS#1, PKCS#8, or SEC1 format when
 * using `aws-lc-rs` as the crypto provider. Supported formats may vary by
 * provider.
 *
 * On success, this writes a pointer to the newly created
 * `rustls_certified_key` in `certified_key_out`. That pointer must later
 * be freed with `rustls_certified_key_free` to avoid memory leaks. Note that
 * internally, this is an atomically reference-counted pointer, so even after
 * the original caller has called `rustls_certified_key_free`, other objects
 * may retain a pointer to the object. The memory will be freed when all
 * references are gone.
 *
 * This function does not take ownership of any of its input pointers. It
 * parses the pointed-to data and makes a copy of the result. You may
 * free the `cert_chain` and `private_key` buffers after calling it.
 *
 * `certified_key_out` is unchanged if the function returns an error.
 *
 * Typically, you will build a `rustls_certified_key`, use it to create a
 * `rustls_server_config` (which increments the reference count), and then
 * immediately call `rustls_certified_key_free`. That leaves the
 * `rustls_server_config` in possession of the sole reference, so the
 * `rustls_certified_key`'s memory will automatically be released when
 * the `rustls_server_config` is freed.
 */
rustls_result rustls_certified_key_build(const uint8_t *cert_chain,
                                         size_t cert_chain_len,
                                         const uint8_t *private_key,
                                         size_t private_key_len,
                                         const struct rustls_certified_key **certified_key_out);

/**
 * Build a `rustls_certified_key` from a certificate chain and a
 * `rustls_signing_key`.
 *
 * `cert_chain` must point to a buffer of `cert_chain_len` bytes, containing
 * a series of PEM-encoded certificates, with the end-entity (leaf)
 * certificate first.
 *
 * `signing_key` must point to a `rustls_signing_key` loaded using a
 * `rustls_crypto_provider` and `rustls_crypto_provider_load_key()`.
 *
 * On success, this writes a pointer to the newly created
 * `rustls_certified_key` in `certified_key_out`. That pointer must later
 * be freed with `rustls_certified_key_free` to avoid memory leaks. Note that
 * internally, this is an atomically reference-counted pointer, so even after
 * the original caller has called `rustls_certified_key_free`, other objects
 * may retain a pointer to the object. The memory will be freed when all
 * references are gone.
 *
 * This function copies the `cert_chain` data and does not take ownership of
 * that buffer. Once the `cert_chain` pointer has been validated, the function
 * takes ownership of `signing_key`, including when a later operation returns
 * an error. The caller must not use or free the signing key afterward. If
 * `cert_chain` is NULL, the function returns `RUSTLS_RESULT_NULL_PARAMETER`
 * without consuming `signing_key`.
 *
 * `certified_key_out` is unchanged if the function returns an error.
 *
 * Typically, you will build a `rustls_certified_key`, use it to create a
 * `rustls_server_config` (which increments the reference count), and then
 * immediately call `rustls_certified_key_free`. That leaves the
 * `rustls_server_config` in possession of the sole reference, so the
 * `rustls_certified_key`'s memory will automatically be released when
 * the `rustls_server_config` is freed.
 */
rustls_result rustls_certified_key_build_with_signing_key(const uint8_t *cert_chain,
                                                          size_t cert_chain_len,
                                                          struct rustls_signing_key *signing_key,
                                                          const struct rustls_certified_key **certified_key_out);

/**
 * Return the i-th `rustls_certificate` in the `rustls_certified_key`.
 *
 * 0 gives the end-entity certificate. 1 and higher give certificates from the chain.
 *
 * Indexes higher than the last available certificate return NULL.
 *
 * The returned certificate is valid until the `rustls_certified_key` is freed.
 */
const struct rustls_certificate *rustls_certified_key_get_certificate(const struct rustls_certified_key *certified_key,
                                                                      size_t i);

/**
 * Create a copy of the `rustls_certified_key` with the given OCSP response data
 * as DER encoded bytes.
 *
 * The OCSP response may be given as NULL to clear any possibly present OCSP
 * data from the cloned key.
 *
 * The function copies `ocsp_response` and does not take ownership of either input.
 * On success, `cloned_key_out` receives an independently owned key that the caller must
 * free with `rustls_certified_key_free`. On error, `cloned_key_out` is unchanged.
 */
rustls_result rustls_certified_key_clone_with_ocsp(const struct rustls_certified_key *certified_key,
                                                   const struct rustls_slice_bytes *ocsp_response,
                                                   const struct rustls_certified_key **cloned_key_out);

/**
 * Verify the consistency of this `rustls_certified_key`'s public and private keys.
 *
 * This is done by performing a comparison of subject public key information (SPKI) bytes
 * between the certificate and private key.
 *
 * If the private key matches the certificate this function returns `RUSTLS_RESULT_OK`,
 * otherwise an error `rustls_result` is returned.
 */
rustls_result rustls_certified_key_keys_match(const struct rustls_certified_key *key);

/**
 * Release the caller's reference to a `rustls_certified_key` previously returned from
 * `rustls_certified_key_build`.
 *
 * Other objects may still hold internal references to the atomically reference-counted
 * Rust object. Regardless, the caller must not use `key` after this function returns.
 *
 * Calling with NULL is fine. Must not be called twice with the same value.
 */
void rustls_certified_key_free(const struct rustls_certified_key *key);

/**
 * Create a `rustls_root_cert_store_builder`.
 *
 * The caller owns the returned builder and must eventually free it with
 * `rustls_root_cert_store_builder_free`, whether or not
 * `rustls_root_cert_store_builder_build` is called.
 */
struct rustls_root_cert_store_builder *rustls_root_cert_store_builder_new(void);

/**
 * Add one or more certificates to the root cert store builder using PEM
 * encoded data.
 *
 * When `strict` is true an error will return a `CertificateParseError`
 * result. So will an attempt to parse data that has zero certificates.
 *
 * When `strict` is false, unparseable root certificates will be ignored.
 * This may be useful on systems that have syntactically invalid root
 * certificates.
 *
 * This function copies the parsed certificates and does not retain `pem`.
 */
rustls_result rustls_root_cert_store_builder_add_pem(struct rustls_root_cert_store_builder *builder,
                                                     const uint8_t *pem,
                                                     size_t pem_len,
                                                     bool strict);

/**
 * Add one or more certificates to the root cert store builder using PEM
 * encoded data read from the named file.
 *
 * When `strict` is true an error will return a `CertificateParseError`
 * result. So will an attempt to parse data that has zero certificates.
 *
 * When `strict` is false, unparseable root certificates will be ignored.
 * This may be useful on systems that have syntactically invalid root
 * certificates.
 *
 * `filename` must be a NUL-terminated UTF-8 string. It is borrowed for the
 * duration of the call and is not retained.
 */
rustls_result rustls_root_cert_store_builder_load_roots_from_file(struct rustls_root_cert_store_builder *builder,
                                                                  const char *filename,
                                                                  bool strict);

/**
 * Create a new `rustls_root_cert_store` from the builder.
 *
 * The builder is consumed and cannot be used again, but must still be freed.
 *
 * On success, `root_cert_store_out` receives a new root certificate store. The caller owns
 * it and must free it with `rustls_root_cert_store_free` when no longer needed. The store can
 * be used in multiple verifier builders.
 */
rustls_result rustls_root_cert_store_builder_build(struct rustls_root_cert_store_builder *builder,
                                                   const struct rustls_root_cert_store **root_cert_store_out);

/**
 * Free a `rustls_root_cert_store_builder` previously returned from
 * `rustls_root_cert_store_builder_new`.
 *
 * Calling with NULL is fine. Must not be called twice with the same value.
 */
void rustls_root_cert_store_builder_free(struct rustls_root_cert_store_builder *builder);

/**
 * Free a `rustls_root_cert_store` previously returned from
 * `rustls_root_cert_store_builder_build`.
 *
 * Calling with NULL is fine. Must not be called twice with the same value.
 */
void rustls_root_cert_store_free(const struct rustls_root_cert_store *store);

/**
 * Return a 16-bit unsigned integer corresponding to this cipher suite's assignment
 * in the [IANA TLS Cipher Suites registry].
 *
 * The bytes from the assignment are interpreted in network order.
 *
 * [IANA TLS Cipher Suites registry]: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
 */
uint16_t rustls_supported_ciphersuite_get_suite(const struct rustls_supported_ciphersuite *supported_ciphersuite);

/**
 * Returns the name of the ciphersuite as a `rustls_str`.
 *
 * If the provided ciphersuite is invalid, the `rustls_str` will contain the
 * empty string. The lifetime of the `rustls_str` is the lifetime of the program,
 * it does not need to be freed.
 */
struct rustls_str rustls_supported_ciphersuite_get_name(const struct rustls_supported_ciphersuite *supported_ciphersuite);

/**
 * Returns the `rustls_tls_version` of the ciphersuite.
 *
 * See also `RUSTLS_ALL_VERSIONS`.
 */
enum rustls_tls_version rustls_supported_ciphersuite_protocol_version(const struct rustls_supported_ciphersuite *supported_ciphersuite);

/**
 * Create a `rustls_client_config_builder` using the process default crypto provider.
 *
 * Caller owns the memory and must eventually call `rustls_client_config_builder_build`,
 * then free the resulting `rustls_client_config`.
 *
 * Alternatively, if an error occurs or, you don't wish to build a config,
 * call `rustls_client_config_builder_free` to free the builder directly.
 *
 * This uses the process default provider's values for the cipher suites and key
 * exchange groups, as well as safe defaults for protocol versions.
 *
 * This starts out with no trusted roots. The caller must provide a verifier with
 * `rustls_client_config_builder_set_server_verifier` or
 * `rustls_client_config_builder_dangerous_set_certificate_verifier`.
 */
struct rustls_client_config_builder *rustls_client_config_builder_new(void);

/**
 * Create a `rustls_client_config_builder` using the specified crypto provider.
 *
 * Caller owns the memory and must eventually call `rustls_client_config_builder_build`,
 * then free the resulting `rustls_client_config`.
 *
 * Alternatively, if an error occurs or, you don't wish to build a config,
 * call `rustls_client_config_builder_free` to free the builder directly.
 *
 * `tls_versions` sets the TLS protocol versions to use when negotiating a
 * TLS session. Each value is a protocol version as defined in RFC 8446,
 * sections 4.2.1 and 5.1. Some values are defined in `rustls_tls_version`
 * for convenience, and the arrays
 * `RUSTLS_DEFAULT_VERSIONS` or `RUSTLS_ALL_VERSIONS` can be used directly.
 *
 * `tls_versions` will only be used during the call and the application retains
 * ownership. `tls_versions_len` is the number of consecutive `uint16_t`
 * pointed to by `tls_versions`.
 *
 * On `RUSTLS_RESULT_OK`, `builder_out` receives a builder owned by the caller.
 * It must eventually be passed to `rustls_client_config_builder_build` or freed with
 * `rustls_client_config_builder_free`. On error, `builder_out` is unchanged.
 *
 * The function borrows `provider` for the duration of the call and retains its own
 * reference afterward.
 *
 * Ciphersuites are configured separately via the crypto provider. See
 * `rustls_crypto_provider_builder_set_cipher_suites` for more information.
 */
rustls_result rustls_client_config_builder_new_custom(const struct rustls_crypto_provider *provider,
                                                      const uint16_t *tls_versions,
                                                      size_t tls_versions_len,
                                                      struct rustls_client_config_builder **builder_out);

/**
 * Set a custom server certificate verifier using the builder crypto provider.
 * Returns `RUSTLS_RESULT_NO_DEFAULT_CRYPTO_PROVIDER` if no process default crypto
 * provider has been set, and the builder was not constructed with an explicit
 * provider choice.
 *
 * The callback must not capture any of the pointers in its
 * `rustls_verify_server_cert_params`.
 * If `userdata` has been set with `rustls_connection_set_userdata`, it
 * will be passed to the callback. Otherwise the userdata param passed to
 * the callback will be NULL.
 *
 * The callback must be safe to call on any thread at any time, including
 * multiple concurrent calls. So, for instance, if the callback mutates
 * userdata (or other shared state), it must use synchronization primitives
 * to make such mutation safe.
 *
 * The callback receives certificate chain information as raw bytes.
 * Currently this library offers no functions to parse the certificates,
 * so you'll need to bring your own certificate parsing library
 * if you need to parse them.
 *
 * If the custom verifier accepts the certificate, it should return
 * `RUSTLS_RESULT_OK`. Otherwise, it may return any other `rustls_result` error,
 * including one of the certificate-related errors.
 *
 * See also the rustls documentation for
 * [`DangerousClientConfig::set_certificate_verifier`].
 *
 * [`DangerousClientConfig::set_certificate_verifier`]: https://docs.rs/rustls/latest/rustls/client/struct.DangerousClientConfig.html#method.set_certificate_verifier
 */
rustls_result rustls_client_config_builder_dangerous_set_certificate_verifier(struct rustls_client_config_builder *config_builder,
                                                                              rustls_verify_server_cert_callback callback);

/**
 * Configure the server certificate verifier.
 *
 * For the usual case of verifying servers against a custom set of root
 * certificates:
 *
 * 1. Create a `rustls_root_cert_store_builder` with
 *    `rustls_root_cert_store_builder_new`.
 * 2. Add roots with `rustls_root_cert_store_builder_add_pem` or
 *    `rustls_root_cert_store_builder_load_roots_from_file`, then call
 *    `rustls_root_cert_store_builder_build`.
 * 3. Pass the resulting store to
 *    `rustls_web_pki_server_cert_verifier_builder_new`, then call
 *    `rustls_web_pki_server_cert_verifier_builder_build`.
 * 4. Pass the resulting verifier to this function.
 *
 * Alternatively, `rustls_platform_server_cert_verifier` creates a verifier
 * using the platform's certificate facilities and trust store.
 *
 * This function increases the reference count of `verifier` and does not
 * take ownership. The caller must still free its verifier pointer with
 * `rustls_server_cert_verifier_free` when it is no longer needed.
 */
void rustls_client_config_builder_set_server_verifier(struct rustls_client_config_builder *builder,
                                                      const struct rustls_server_cert_verifier *verifier);

/**
 * Set the ALPN protocol list to the given protocols.
 *
 * `protocols` must point to a buffer of `rustls_slice_bytes` (built by the caller) with `len`
 * elements.
 *
 * Each element of the buffer must be a `rustls_slice_bytes` whose
 * data field points to a single ALPN protocol ID.
 *
 * Standard ALPN protocol IDs are defined in the [IANA registry].
 *
 * This function makes a copy of the data in `protocols` and does not retain
 * any pointers, so the caller can free the pointed-to memory after calling.
 *
 * See also the rustls documentation for [`ClientConfig::alpn_protocols`].
 *
 * [IANA registry]: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
 * [`ClientConfig::alpn_protocols`]: https://docs.rs/rustls/latest/rustls/client/struct.ClientConfig.html#structfield.alpn_protocols
 */
rustls_result rustls_client_config_builder_set_alpn_protocols(struct rustls_client_config_builder *builder,
                                                              const struct rustls_slice_bytes *protocols,
                                                              size_t len);

/**
 * Enable or disable verifying the selected ALPN was offered.
 *
 * The default is `true`.
 *
 * See also the rustls documentation for [`ClientConfig::check_selected_alpn`].
 *
 * [`ClientConfig::check_selected_alpn`]: https://docs.rs/rustls/latest/rustls/struct.ClientConfig.html#structfield.check_selected_alpn
 */
void rustls_client_config_builder_set_check_selected_alpn(struct rustls_client_config_builder *config,
                                                          bool enable);

/**
 * Request a specific number of TLS 1.3 session tickets.
 *
 * This is done via the RFC 9149 `ticket_request` extension.
 *
 * `new_session_count` is the number of tickets desired when the server
 * negotiates a new connection, and `resumption_count` the number desired
 * when the server resumes using a presented ticket.
 *
 * By default the extension is not sent. Note that servers are free to
 * ignore the request, it is only a hint.
 *
 * See also the rustls documentation for [`ClientConfig::send_ticket_request`].
 *
 * [`ClientConfig::send_ticket_request`]: https://docs.rs/rustls/latest/rustls/struct.ClientConfig.html#structfield.send_ticket_request
 */
rustls_result rustls_client_config_builder_set_send_ticket_request(struct rustls_client_config_builder *builder,
                                                                   uint8_t new_session_count,
                                                                   uint8_t resumption_count);

/**
 * Enable or disable SNI.
 *
 * See also the rustls documentation for [`ClientConfig::enable_sni`].
 *
 * [`ClientConfig::enable_sni`]: https://docs.rs/rustls/latest/rustls/struct.ClientConfig.html#structfield.enable_sni
 */
void rustls_client_config_builder_set_enable_sni(struct rustls_client_config_builder *config,
                                                 bool enable);

/**
 * Provide the configuration a list of certificates where the connection
 * will select the first one that is compatible with the server's signature
 * verification capabilities.
 *
 * Clients that want to support both ECDSA and RSA certificates will want the
 * ECSDA to go first in the list.
 *
 * The built configuration will keep a reference to all certified keys
 * provided. The client may `rustls_certified_key_free()` afterwards
 * without the configuration losing them. The same certified key may also
 * be used in multiple configs.
 *
 * EXPERIMENTAL: installing a client authentication callback will replace any
 * configured certified keys and vice versa.
 */
rustls_result rustls_client_config_builder_set_certified_key(struct rustls_client_config_builder *builder,
                                                             const struct rustls_certified_key *const *certified_keys,
                                                             size_t certified_keys_len);

/**
 * Log key material to the file specified by the `SSLKEYLOGFILE` environment variable.
 *
 * The key material will be logged in the [NSS key log format] and is compatible
 * with tools like Wireshark.
 *
 * Secrets logged in this manner are **extremely sensitive** and can break the security
 * of past, present and future sessions.
 *
 * For more control over which secrets are logged, or to customize the format, prefer
 * `rustls_client_config_builder_set_key_log`.
 *
 * [NSS key log format]: https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
 */
rustls_result rustls_client_config_builder_set_key_log_file(struct rustls_client_config_builder *builder);

/**
 * Provide callbacks to manage logging key material.
 *
 * The `log_cb` argument is mandatory and must not be `NULL` or a `NullParameter` error is
 * returned. The `log_cb` will be invoked with a `client_random` to identify the relevant session,
 * a `label` to identify the purpose of the `secret`, and the `secret` itself. See the
 * rustls documentation for [`KeyLog::log`] for more information on possible labels.
 *
 * The `will_log_cb` may be `NULL`, in which case all key material will be provided to
 * the `log_cb`. By providing a custom `will_log_cb` you may return `0` for labels you don't
 * wish to log, and non-zero for labels you _do_ wish to log as a performance optimization.
 *
 * Both callbacks **must** be thread-safe. Arguments provided to the callback live only for as
 * long as the callback is executing and are not valid after the callback returns. The
 * callbacks must not retain references to the provided data.
 *
 * Secrets provided to the `log_cb` are **extremely sensitive** and can break the security
 * of past, present and future sessions.
 *
 * See also `rustls_client_config_builder_set_key_log_file` for a simpler way to log
 * to a file specified by the `SSLKEYLOGFILE` environment variable.
 *
 * [`KeyLog::log`]: https://docs.rs/rustls/latest/rustls/trait.KeyLog.html#tymethod.log
 */
rustls_result rustls_client_config_builder_set_key_log(struct rustls_client_config_builder *builder,
                                                       rustls_keylog_log_callback log_cb,
                                                       rustls_keylog_will_log_callback will_log_cb);

/**
 * Configure the client for Encrypted Client Hello (ECH).
 *
 * This requires providing a TLS encoded list of ECH configurations that should
 * have been retrieved from the DNS HTTPS record for the domain you intend to connect to.
 * This should be done using DNS-over-HTTPS to avoid leaking the domain name you are
 * connecting to ahead of the TLS handshake.
 *
 * At least one of the ECH configurations must be compatible with the provided `rustls_hpke`
 * instance. See `rustls_supported_hpke()` for more information.
 *
 * Calling this function will replace any existing ECH configuration set by
 * previous calls to `rustls_client_config_builder_enable_ech()` or
 * `rustls_client_config_builder_enable_ech_grease()`.
 *
 * The provided `ech_config_list_bytes` and `rustls_hpke` must not be NULL or an
 * error will be returned. The caller maintains ownership of the ECH config list TLS bytes
 * and `rustls_hpke` instance. This function does not retain any reference to
 * `ech_config_list_bytes`.
 *
 * A `RUSTLS_RESULT_BUILDER_INCOMPATIBLE_TLS_VERSIONS` error is returned if the builder's
 * TLS versions have been customized via `rustls_client_config_builder_new_custom()`
 * and the customization isn't "only TLS 1.3". ECH may only be used with TLS 1.3.
 */
rustls_result rustls_client_config_builder_enable_ech(struct rustls_client_config_builder *builder,
                                                      const uint8_t *ech_config_list_bytes,
                                                      size_t ech_config_list_bytes_size,
                                                      const struct rustls_hpke *hpke);

/**
 * Configure the client for GREASE Encrypted Client Hello (ECH).
 *
 * This is a feature to prevent ossification of the TLS handshake by acting as though
 * ECH were configured for an imaginary ECH config generated with one of the
 * `rustls_hpke` supported suites, chosen at random.
 *
 * The provided `rustls_client_config_builder` and `rustls_hpke` must not be NULL or an
 * error will be returned. The caller maintains ownership of both the
 * `rustls_client_config_builder` and the `rustls_hpke` instance.
 *
 * Calling this function will replace any existing ECH configuration set by
 * previous calls to `rustls_client_config_builder_enable_ech()` or
 * `rustls_client_config_builder_enable_ech_grease()`.
 *
 * A `RUSTLS_RESULT_BUILDER_INCOMPATIBLE_TLS_VERSIONS` error is returned if the builder's
 * TLS versions have been customized via `rustls_client_config_builder_new_custom()`
 * and the customization isn't "only TLS 1.3". ECH may only be used with TLS 1.3.
 */
rustls_result rustls_client_config_builder_enable_ech_grease(struct rustls_client_config_builder *builder,
                                                             const struct rustls_hpke *hpke);

/**
 * Turn a mutable `rustls_client_config_builder` into a const `rustls_client_config`
 * (read-only).
 *
 * This function takes ownership of `builder`. The caller must not use or free the builder
 * after calling this function, regardless of the result.
 *
 * On `RUSTLS_RESULT_OK`, `config_out` receives a config owned by the caller, which must
 * eventually be freed with `rustls_client_config_free`. On error, `config_out` is unchanged.
 */
rustls_result rustls_client_config_builder_build(struct rustls_client_config_builder *builder,
                                                 const struct rustls_client_config **config_out);

/**
 * Free a `rustls_client_config_builder` without building it into a
 * `rustls_client_config`.
 *
 * Do not call this after `rustls_client_config_builder_build`, which consumes and frees the
 * builder. Calling with NULL is fine. Must not be called twice with the same value.
 */
void rustls_client_config_builder_free(struct rustls_client_config_builder *config);

/**
 * Returns true if a `rustls_connection` created from the `rustls_client_config` will
 * operate in FIPS mode.
 *
 * This is different from `rustls_crypto_provider_fips` which is concerned
 * only with cryptography, whereas this also covers TLS-level configuration that NIST
 * recommends, as well as ECH HPKE suites if applicable.
 */
bool rustls_client_config_fips(const struct rustls_client_config *config);

/**
 * Release the caller's reference to a `rustls_client_config` previously returned from
 * `rustls_client_config_builder_build`.
 *
 * Existing client connections may still hold internal references to the atomically
 * reference-counted Rust object. Regardless, the caller must not use `config` after this
 * function returns.
 *
 * Calling with NULL is fine. Must not be called twice with the same value.
 */
void rustls_client_config_free(const struct rustls_client_config *config);

/**
 * Create a new client `rustls_connection`.
 *
 * If this returns `RUSTLS_RESULT_OK`, the memory pointed to by `conn_out` is modified to
 * point at a valid `rustls_connection`. The caller now owns the `rustls_connection`
 * and must call `rustls_connection_free` when done with it.
 *
 * This function copies the contents of `server_name`.
 *
 * The connection retains an internal reference to `config`. This function
 * does not take ownership of the caller's config pointer.
 *
 * Uses the `rustls_client_config` to determine ALPN protocol support. Prefer
 * `rustls_client_connection_new_alpn` to customize this per-connection.
 *
 * If this returns an error code, the memory pointed to by `conn_out` remains
 * unchanged.
 *
 * The `server_name` parameter can contain a hostname or an IP address in
 * textual form (IPv4 or IPv6). This function will return an error if it
 * cannot be parsed as one of those types. It must be NUL-terminated.
 */
rustls_result rustls_client_connection_new(const struct rustls_client_config *config,
                                           const char *server_name,
                                           struct rustls_connection **conn_out);

/**
 * Create a new client `rustls_connection` with custom ALPN protocols.
 *
 * Operates the same as `rustls_client_connection_new`, but allows specifying
 * custom per-connection ALPN protocols instead of inheriting ALPN protocols
 * from the `rustls_client_config`.
 *
 * If this returns `RUSTLS_RESULT_OK`, the memory pointed to by `conn_out` is modified to
 * point at a valid `rustls_connection`. The caller now owns the `rustls_connection`
 * and must call `rustls_connection_free` when done with it.
 *
 * This function copies the contents of `server_name`.
 *
 * The connection retains an internal reference to `config`. This function
 * does not take ownership of the caller's config pointer.
 *
 * If this returns an error code, the memory pointed to by `conn_out` remains
 * unchanged.
 *
 * The `server_name` parameter can contain a hostname or an IP address in
 * textual form (IPv4 or IPv6). This function will return an error if it
 * cannot be parsed as one of those types. It must be NUL-terminated.
 *
 * `alpn_protocols` must point to a buffer of `rustls_slice_bytes` (built by the caller)
 * with `alpn_protocols_len` elements. Each element of the buffer must be a `rustls_slice_bytes`
 * whose data field points to a single ALPN protocol ID. This function makes a copy of the
 * data in `alpn_protocols` and does not retain any pointers, so the caller can free the
 * pointed-to memory after calling.
 *
 * Standard ALPN protocol IDs are defined in the [IANA registry].
 *
 * [IANA registry]: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
 */
rustls_result rustls_client_connection_new_alpn(const struct rustls_client_config *config,
                                                const char *server_name,
                                                const struct rustls_slice_bytes *alpn_protocols,
                                                size_t alpn_protocols_len,
                                                struct rustls_connection **conn_out);

/**
 * Set the userdata pointer associated with this connection. This will be passed
 * to any callbacks invoked by the connection, if you've set up callbacks in the config.
 *
 * The pointed-to data must remain valid until the userdata is replaced or the connection
 * is freed. Rustls does not take ownership of the data and will not free it.
 */
void rustls_connection_set_userdata(struct rustls_connection *conn, void *userdata);

/**
 * Set the logging callback for this connection. The log callback will be invoked
 * with the userdata parameter previously set by `rustls_connection_set_userdata`, or
 * NULL if no userdata was set.
 */
void rustls_connection_set_log_callback(struct rustls_connection *conn, rustls_log_callback cb);

/**
 * Read some TLS bytes from the network into internal buffers. The actual network
 * I/O is performed by `callback`, which you provide. Rustls will invoke your
 * callback with a suitable buffer to store the read bytes into. You don't have
 * to fill it up, just fill with as many bytes as you get in one syscall.
 * The `userdata` parameter is passed through directly to `callback`. Note that
 * this is distinct from the `userdata` parameter set with
 * `rustls_connection_set_userdata`.
 *
 * On success, returns 0 and writes the number of bytes read to `out_n`. On error, returns
 * an errno value passed through from `callback` and leaves `out_n` unchanged. See
 * `rustls_read_callback` for more details.
 *
 * See also the rustls documentation for [`Connection::read_tls`].
 *
 * [`Connection::read_tls`]: https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.read_tls
 */
rustls_io_result rustls_connection_read_tls(struct rustls_connection *conn,
                                            rustls_read_callback callback,
                                            void *userdata,
                                            size_t *out_n);

/**
 * Write some TLS bytes to the network. The actual network I/O is performed by
 * `callback`, which you provide. Rustls will invoke your callback with a
 * suitable buffer containing TLS bytes to send. You don't have to write them
 * all, just as many as you can in one syscall.
 * The `userdata` parameter is passed through directly to `callback`. Note that
 * this is distinct from the `userdata` parameter set with
 * `rustls_connection_set_userdata`.
 *
 * On success, returns 0 and writes the number of bytes written to `out_n`. On error,
 * returns an errno value passed through from `callback` and leaves `out_n` unchanged.
 * See `rustls_write_callback` for more details.
 *
 * See also the rustls documentation for [`Connection::write_tls`].
 *
 * [`Connection::write_tls`]: https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.write_tls
 */
rustls_io_result rustls_connection_write_tls(struct rustls_connection *conn,
                                             rustls_write_callback callback,
                                             void *userdata,
                                             size_t *out_n);

/**
 * Write all available TLS bytes to the network. The actual network I/O is performed by
 * `callback`, which you provide. Rustls will invoke your callback with an array
 * of `rustls_slice_bytes`, each containing a buffer with TLS bytes to send.
 * You don't have to write them all, just as many as you are willing.
 * The `userdata` parameter is passed through directly to `callback`. Note that
 * this is distinct from the `userdata` parameter set with
 * `rustls_connection_set_userdata`.
 *
 * On success, returns 0 and writes the number of bytes written to `out_n`. On error,
 * returns an errno value passed through from `callback` and leaves `out_n` unchanged.
 * See `rustls_write_vectored_callback` for more details.
 *
 * See also the rustls documentation for [`Writer::write_vectored`].
 *
 * [`Writer::write_vectored`]: https://docs.rs/rustls/latest/rustls/struct.Writer.html#method.write_vectored
 */
rustls_io_result rustls_connection_write_tls_vectored(struct rustls_connection *conn,
                                                      rustls_write_vectored_callback callback,
                                                      void *userdata,
                                                      size_t *out_n);

/**
 * Decrypt any available ciphertext from the internal buffer and put it
 * into the internal plaintext buffer, potentially making bytes available
 * for `rustls_connection_read()`.
 *
 * See also the rustls documentation for [`Connection::process_new_packets`].
 *
 * [`Connection::process_new_packets`]: https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.process_new_packets
 */
rustls_result rustls_connection_process_new_packets(struct rustls_connection *conn);

/**
 * See also the rustls documentation for [`CommonState::wants_read`].
 *
 * [`CommonState::wants_read`]: https://docs.rs/rustls/latest/rustls/struct.CommonState.html#method.wants_read
 */
bool rustls_connection_wants_read(const struct rustls_connection *conn);

/**
 * See also the rustls documentation for [`CommonState::wants_write`].
 *
 * [`CommonState::wants_write`]: https://docs.rs/rustls/latest/rustls/struct.CommonState.html#method.wants_write
 */
bool rustls_connection_wants_write(const struct rustls_connection *conn);

/**
 * Returns true if the connection is currently performing the TLS handshake.
 *
 * Note: This may return `false` while there are still handshake packets waiting
 * to be extracted and transmitted with `rustls_connection_write_tls()`.
 *
 * See also the rustls documentation for [`CommonState::is_handshaking`].
 *
 * [`CommonState::is_handshaking`]: https://docs.rs/rustls/latest/rustls/struct.CommonState.html#method.is_handshaking
 */
bool rustls_connection_is_handshaking(const struct rustls_connection *conn);

/**
 * Returns a `rustls_handshake_kind` describing the `rustls_connection`.
 */
enum rustls_handshake_kind rustls_connection_handshake_kind(const struct rustls_connection *conn);

/**
 * Sets a limit on the internal buffers used to buffer unsent plaintext (prior
 * to completing the TLS handshake) and unsent TLS records. By default, there
 * is no limit. The limit can be set at any time, even if the current buffer
 * use is higher.
 *
 * See also the rustls documentation for [`Connection::set_buffer_limit`].
 *
 * [`Connection::set_buffer_limit`]: https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.set_buffer_limit
 */
void rustls_connection_set_buffer_limit(struct rustls_connection *conn,
                                        size_t n);

/**
 * Queues a close_notify alert to be sent by the next call to
 * `rustls_connection_write_tls()`.
 *
 * See also the rustls documentation for [`Connection::send_close_notify`].
 *
 * [`Connection::send_close_notify`]: https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.send_close_notify
 */
void rustls_connection_send_close_notify(struct rustls_connection *conn);

/**
 * Queues a TLS1.3 key_update message to refresh a connection’s keys.
 *
 * Rustls internally manages key updates as required and so this function should
 * seldom be used. See the rustls documentation for
 * [`ConnectionCommon::refresh_traffic_keys`] for important caveats and suggestions
 * on occasions that merit its use.
 *
 * [`ConnectionCommon::refresh_traffic_keys`]: https://docs.rs/rustls/latest/rustls/struct.ConnectionCommon.html#method.refresh_traffic_keys
 */
rustls_result rustls_connection_refresh_traffic_keys(struct rustls_connection *conn);

/**
 * Return the i-th certificate provided by the peer.
 * Index 0 is the end entity certificate. Higher indexes are certificates
 * in the chain. Requesting an out-of-range index returns NULL.
 *
 * The returned pointer is valid until the next mutating function call
 * affecting the connection. A mutating function call is one where the first
 * argument is a mutable pointer to `rustls_connection` (as opposed to a const
 * pointer).
 *
 * See also the rustls documentation for [`Connection::peer_certificates`].
 *
 * [`Connection::peer_certificates`]: https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.peer_certificates
 */
const struct rustls_certificate *rustls_connection_get_peer_certificate(const struct rustls_connection *conn,
                                                                        size_t i);

/**
 * Get the ALPN protocol that was negotiated, if any. Stores a pointer to a
 * borrowed buffer of bytes, and that buffer's length, in the output parameters.
 * If the connection is still handshaking, or no ALPN protocol was negotiated,
 * stores NULL and 0 in the output parameters.
 *
 * The borrowed buffer is owned by the connection and is valid until the next
 * mutating function call affecting the connection. A mutating function call
 * is one where the first argument is a mutable pointer to
 * `rustls_connection` (as opposed to a const pointer).
 * The caller must not modify or free the borrowed buffer.
 *
 * If `conn` or either output parameter is NULL, both output values are unchanged.
 * Protocol identifiers are listed in the [IANA TLS Parameters registry]. See
 * also the rustls documentation for [`Connection::alpn_protocol`].
 *
 * [IANA TLS Parameters registry]: https://www.iana.org/assignments/tls-parameters/
 * [`Connection::alpn_protocol`]: https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.alpn_protocol
 */
void rustls_connection_get_alpn_protocol(const struct rustls_connection *conn,
                                         const uint8_t **protocol_out,
                                         size_t *protocol_out_len);

/**
 * Return the TLS protocol version that has been negotiated. Before this
 * has been decided during the handshake, this will return 0. Otherwise,
 * the u16 version number as defined in the relevant RFC is returned.
 *
 * See also the rustls documentation for [`Connection::protocol_version`] and
 * [`ProtocolVersion`].
 *
 * [`Connection::protocol_version`]: https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.protocol_version
 * [`ProtocolVersion`]: https://docs.rs/rustls/latest/rustls/internal/msgs/enums/enum.ProtocolVersion.html
 */
uint16_t rustls_connection_get_protocol_version(const struct rustls_connection *conn);

/**
 * Retrieves the [IANA registered cipher suite identifier] agreed with the peer.
 *
 * This returns `TLS_NULL_WITH_NULL_NULL` (0x0000) until the ciphersuite is agreed.
 *
 * [IANA registered cipher suite identifier]: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
 */
uint16_t rustls_connection_get_negotiated_ciphersuite(const struct rustls_connection *conn);

/**
 * Retrieves the cipher suite name agreed with the peer.
 *
 * This returns "" until the ciphersuite is agreed.
 *
 * The lifetime of the `rustls_str` is the lifetime of the program, it does not
 * need to be freed.
 *
 * See also the rustls documentation for [`Connection::negotiated_cipher_suite`].
 *
 * [`Connection::negotiated_cipher_suite`]: https://docs.rs/rustls/latest/rustls/enum.Connection.html#method.negotiated_cipher_suite
 */
struct rustls_str rustls_connection_get_negotiated_ciphersuite_name(const struct rustls_connection *conn);

/**
 * Retrieves the [IANA registered supported group identifier] agreed with the peer.
 *
 * This returns Reserved (0x0000) until the key exchange group is agreed.
 *
 * [IANA registered supported group identifier]: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
 */
uint16_t rustls_connection_get_negotiated_key_exchange_group(const struct rustls_connection *conn);

/**
 * Retrieves the key exchange group name agreed with the peer.
 *
 * This returns "" until the key exchange group is agreed.
 *
 * The lifetime of the `rustls_str` is the lifetime of the program, it does not
 * need to be freed.
 */
struct rustls_str rustls_connection_get_negotiated_key_exchange_group_name(const struct rustls_connection *conn);

/**
 * Retrieves the number of TLS 1.3 tickets that have been received by a client connection.
 *
 * This returns 0 if the `conn` is `NULL`, or a server connection.
 */
uint32_t rustls_connection_get_tls13_tickets_received(const struct rustls_connection *conn);

/**
 * Write up to `count` plaintext bytes from `buf` into the `rustls_connection`.
 * This will increase the number of output bytes available to
 * `rustls_connection_write_tls`.
 * On success, store the number of bytes actually written in `*out_n`
 * (this may be less than `count`).
 *
 * This function borrows `buf` for the duration of the call and does not retain it.
 * On error, `out_n` is unchanged.
 *
 * See also the rustls documentation for [`Writer::write`].
 *
 * [`Writer::write`]: https://docs.rs/rustls/latest/rustls/struct.Writer.html#method.write
 */
rustls_result rustls_connection_write(struct rustls_connection *conn,
                                      const uint8_t *buf,
                                      size_t count,
                                      size_t *out_n);

/**
 * Read up to `count` plaintext bytes from the `rustls_connection` into `buf`.
 * On success, store the number of bytes read in `*out_n` (this may be less
 * than `count`). A success with `*out_n` set to 0 means "all bytes currently
 * available have been read, but more bytes may become available after
 * subsequent calls to `rustls_connection_read_tls` and
 * `rustls_connection_process_new_packets`.
 *
 * Subtle note: Even though this function only writes to `buf` and does not
 * read from it, the memory in `buf` must be initialized before the call (for
 * Rust-internal reasons). Initializing a buffer once and then using it
 * multiple times without zeroizing before each call is fine.
 *
 * The function does not retain `buf`. On error, `out_n` is unchanged.
 *
 * See also the rustls documentation for [`Reader::read`].
 *
 * [`Reader::read`]: https://docs.rs/rustls/latest/rustls/struct.Reader.html#method.read
 */
rustls_result rustls_connection_read(struct rustls_connection *conn,
                                     uint8_t *buf,
                                     size_t count,
                                     size_t *out_n);

#if defined(DEFINE_READ_BUF)
/**
 * Read up to `count` plaintext bytes from the `rustls_connection` into `buf`.
 * On success, store the number of bytes read in `*out_n` (this may be less
 * than `count`). A success with `*out_n` set to 0 means "all bytes currently
 * available have been read, but more bytes may become available after
 * subsequent calls to `rustls_connection_read_tls` and
 * `rustls_connection_process_new_packets`.
 *
 * This experimental API is only available when using a nightly Rust compiler
 * and enabling the `read_buf` Cargo feature. It will be deprecated and later
 * removed in future versions.
 *
 * Unlike with `rustls_connection_read`, this function may be called with `buf`
 * pointing to an uninitialized memory buffer.
 *
 * The function does not retain `buf`. On error, `out_n` is unchanged.
 */
rustls_result rustls_connection_read_2(struct rustls_connection *conn,
                                       uint8_t *buf,
                                       size_t count,
                                       size_t *out_n);
#endif

/**
 * Returns true if the `rustls_connection` was made with a `rustls_client_config`
 * or `rustls_server_config` that is FIPS compatible.
 *
 * This is different from `rustls_crypto_provider_fips` which is concerned
 * only with cryptography, whereas this also covers TLS-level configuration that NIST
 * recommends, as well as ECH HPKE suites if applicable.
 */
bool rustls_connection_fips(const struct rustls_connection *conn);

/**
 * Free a `rustls_connection`. Calling with NULL is fine.
 * Must not be called twice with the same value.
 */
void rustls_connection_free(struct rustls_connection *conn);

/**
 * Constructs a new `rustls_crypto_provider_builder` using the process-wide default crypto
 * provider as the base crypto provider to be customized.
 *
 * When this function returns `RUSTLS_RESULT_OK`, a pointer to the
 * `rustls_crypto_provider_builder` is written to `builder_out`. It returns
 * `RUSTLS_RESULT_NO_DEFAULT_CRYPTO_PROVIDER` if no default provider has been registered.
 *
 * The caller owns the returned `rustls_crypto_provider_builder` and must free it using
 * `rustls_crypto_provider_builder_free`.
 *
 * On error, `builder_out` is unchanged.
 *
 * This function is typically used for customizing the default crypto provider for specific
 * connections. For example, a typical workflow might be to:
 *
 * * Either:
 *   * Use the default `aws-lc-rs` or `*ring*` provider that rustls-ffi is built with based on
 *     the `CRYPTO_PROVIDER` build variable.
 *   * Call `rustls_crypto_provider_builder_new_with_base` with the desired provider, and
 *     then install it as the process default with
 *     `rustls_crypto_provider_builder_build_as_default`.
 * * Afterward, as required for customization:
 *   * Use `rustls_crypto_provider_builder_new_from_default` to get a builder backed by the
 *     default crypto provider.
 *   * Use `rustls_crypto_provider_builder_set_cipher_suites` to customize the supported
 *     ciphersuites.
 *   * Use `rustls_crypto_provider_builder_build` to build a customized provider.
 *   * Provide that customized provider to client or server configuration builders.
 */
rustls_result rustls_crypto_provider_builder_new_from_default(struct rustls_crypto_provider_builder **builder_out);

/**
 * Constructs a new `rustls_crypto_provider_builder` using the given `rustls_crypto_provider`
 * as the base crypto provider to be customized.
 *
 * The caller owns the returned `rustls_crypto_provider_builder` and must free it using
 * `rustls_crypto_provider_builder_free`.
 *
 * This function does not take ownership of `base`. The builder retains its own
 * reference.
 *
 * This function can be used for setting the default process wide crypto provider,
 * or for constructing a custom crypto provider for a specific connection. A typical
 * workflow could be to:
 *
 * * Call `rustls_crypto_provider_builder_new_with_base` with a custom provider
 * * Install the custom provider as the process-wide default with
 *   `rustls_crypto_provider_builder_build_as_default`.
 *
 * Or, for per-connection customization:
 *
 * * Call `rustls_crypto_provider_builder_new_with_base` with a custom provider
 * * Use `rustls_crypto_provider_builder_set_cipher_suites` to customize the supported
 *   ciphersuites.
 * * Use `rustls_crypto_provider_builder_build` to build a customized provider.
 * * Provide that customized provider to client or server configuration builders.
 */
struct rustls_crypto_provider_builder *rustls_crypto_provider_builder_new_with_base(const struct rustls_crypto_provider *base);

/**
 * Customize the supported ciphersuites of the `rustls_crypto_provider_builder`.
 *
 * Returns an error if the builder has already been built. Overwrites any previously
 * set ciphersuites.
 */
rustls_result rustls_crypto_provider_builder_set_cipher_suites(struct rustls_crypto_provider_builder *builder,
                                                               const struct rustls_supported_ciphersuite *const *cipher_suites,
                                                               size_t cipher_suites_len);

/**
 * Builds a `rustls_crypto_provider` from the builder and returns it. Returns an error if the
 * builder has already been built.
 *
 * The `rustls_crypto_provider_builder` builder is consumed and should not be used
 * for further calls, except to `rustls_crypto_provider_builder_free`. The caller must
 * still free the builder after a successful build.
 *
 * On `RUSTLS_RESULT_OK`, `provider_out` receives a provider owned by the caller, which must
 * eventually be freed with `rustls_crypto_provider_free`. On error, `provider_out` is unchanged.
 */
rustls_result rustls_crypto_provider_builder_build(struct rustls_crypto_provider_builder *builder,
                                                   const struct rustls_crypto_provider **provider_out);

/**
 * Builds a `rustls_crypto_provider` from the builder and sets it as the
 * process-wide default crypto provider.
 *
 * Afterward, the default provider can be retrieved using `rustls_crypto_provider_default`.
 *
 * This can only be done once per process, and will return an error if a
 * default provider has already been set, or if the builder has already been built.
 *
 * The `rustls_crypto_provider_builder` builder is consumed and should not be used
 * for further calls, except to `rustls_crypto_provider_builder_free`. The caller must
 * still free the builder after a successful build.
 */
rustls_result rustls_crypto_provider_builder_build_as_default(struct rustls_crypto_provider_builder *builder);

/**
 * Free the `rustls_crypto_provider_builder`.
 *
 * Calling with `NULL` is fine.
 * Must not be called twice with the same value.
 */
void rustls_crypto_provider_builder_free(struct rustls_crypto_provider_builder *builder);

#if defined(DEFINE_RING)
/**
 * Return the `rustls_crypto_provider` backed by the `*ring*` cryptography library.
 *
 * The caller owns the returned `rustls_crypto_provider` and must free it using
 * `rustls_crypto_provider_free`.
 */
const struct rustls_crypto_provider *rustls_ring_crypto_provider(void);
#endif

#if defined(DEFINE_AWS_LC_RS)
/**
 * Return the `rustls_crypto_provider` backed by the `aws-lc-rs` cryptography library.
 *
 * The caller owns the returned `rustls_crypto_provider` and must free it using
 * `rustls_crypto_provider_free`.
 */
const struct rustls_crypto_provider *rustls_aws_lc_rs_crypto_provider(void);
#endif

#if defined(DEFINE_FIPS)
/**
 * Return a `rustls_crypto_provider` that uses FIPS140-3 approved cryptography.
 *
 * Using this function expresses in your code that you require FIPS-approved cryptography,
 * and will not compile if you make a mistake with cargo features.
 *
 * See the upstream [rustls FIPS documentation][FIPS] for more information.
 *
 * The caller owns the returned `rustls_crypto_provider` and must free it using
 * `rustls_crypto_provider_free`.
 *
 * [FIPS]: https://docs.rs/rustls/latest/rustls/manual/_06_fips/index.html
 */
const struct rustls_crypto_provider *rustls_default_fips_provider(void);
#endif

/**
 * Retrieve a pointer to the process default `rustls_crypto_provider`.
 *
 * This may return `NULL` if no process default provider has been set using
 * `rustls_crypto_provider_builder_build_as_default`.
 *
 * The caller owns the returned `rustls_crypto_provider` and must free it with
 * `rustls_crypto_provider_free`.
 */
const struct rustls_crypto_provider *rustls_crypto_provider_default(void);

/**
 * Returns the number of cipher suites the `rustls_crypto_provider` supports.
 *
 * Valid indices for `rustls_crypto_provider_ciphersuites_get` range from 0 (inclusive) to the
 * returned length (exclusive).
 *
 * This function will return 0 if the `provider` is NULL.
 */
size_t rustls_crypto_provider_ciphersuites_len(const struct rustls_crypto_provider *provider);

/**
 * Retrieve a pointer to a supported cipher suite of the `rustls_crypto_provider`.
 *
 * This function will return NULL if the `provider` is NULL, or if the index is out of bounds
 * with respect to `rustls_crypto_provider_ciphersuites_len`.
 *
 * The lifetime of the returned `rustls_supported_ciphersuite` is equal to the lifetime of the
 * `provider` and should not be used after the `provider` is freed. The returned pointer is
 * borrowed and must not be freed.
 */
const struct rustls_supported_ciphersuite *rustls_crypto_provider_ciphersuites_get(const struct rustls_crypto_provider *provider,
                                                                                   size_t index);

/**
 * Load a private key from the provided PEM content using the crypto provider.
 *
 * `private_key` must point to a buffer of `private_key_len` bytes, containing
 * a PEM-encoded private key. The exact formats supported will differ based on
 * the crypto provider in use. The default providers support PKCS#1, PKCS#8 or
 * SEC1 formats.
 *
 * When this function returns `RUSTLS_RESULT_OK`, a pointer to a `rustls_signing_key`
 * is written to `signing_key_out`. The caller owns the returned `rustls_signing_key`
 * and must free it with `rustls_signing_key_free`.
 *
 * The function copies the private key data and does not retain `private_key`. On error,
 * `signing_key_out` is unchanged.
 */
rustls_result rustls_crypto_provider_load_key(const struct rustls_crypto_provider *provider,
                                              const uint8_t *private_key,
                                              size_t private_key_len,
                                              struct rustls_signing_key **signing_key_out);

/**
 * Write `len` bytes of cryptographically secure random data to `buff` using the crypto provider.
 *
 * `buff` must point to a buffer of at least `len` bytes. The caller maintains ownership
 * of the buffer.
 *
 * Returns `RUSTLS_RESULT_OK` on success, or `RUSTLS_RESULT_GET_RANDOM_FAILED` on failure.
 */
rustls_result rustls_crypto_provider_random(const struct rustls_crypto_provider *provider,
                                            uint8_t *buff,
                                            size_t len);

/**
 * Returns true if the `rustls_crypto_provider` is operating in FIPS mode.
 *
 * This covers only the cryptographic parts of FIPS approval. There are also
 * TLS protocol-level recommendations made by NIST. You should prefer to call
 * `rustls_client_config_fips` or `rustls_server_config_fips` which take these
 * into account.
 */
bool rustls_crypto_provider_fips(const struct rustls_crypto_provider *provider);

/**
 * Frees the `rustls_crypto_provider`.
 *
 * Calling with `NULL` is fine.
 * Must not be called twice with the same value.
 */
void rustls_crypto_provider_free(const struct rustls_crypto_provider *provider);

/**
 * Returns the number of cipher suites the default process-wide crypto provider supports.
 *
 * Valid indices for `rustls_default_crypto_provider_ciphersuites_get` range from 0 (inclusive)
 * to the returned length (exclusive).
 *
 * This function will return 0 if no process-wide default `rustls_crypto_provider` is available.
 */
size_t rustls_default_crypto_provider_ciphersuites_len(void);

/**
 * Retrieve a pointer to a supported cipher suite of the default process-wide crypto provider.
 *
 * This function returns NULL if no process-wide default provider is available or if `index` is
 * out of bounds with respect to `rustls_default_crypto_provider_ciphersuites_len`.
 *
 * The lifetime of the returned `rustls_supported_ciphersuite` is static, as the process-wide
 * default provider lives for as long as the process. The returned pointer is borrowed and must
 * not be freed.
 */
const struct rustls_supported_ciphersuite *rustls_default_crypto_provider_ciphersuites_get(size_t index);

/**
 * Write `len` bytes of cryptographically secure random data to `buff` using the process-wide
 * default crypto provider.
 *
 * `buff` must point to a buffer of at least `len` bytes. The caller maintains ownership
 * of the buffer.
 *
 * Returns `RUSTLS_RESULT_OK` on success, and one of `RUSTLS_RESULT_NO_DEFAULT_CRYPTO_PROVIDER`
 * or `RUSTLS_RESULT_GET_RANDOM_FAILED` on failure.
 */
rustls_result rustls_default_crypto_provider_random(uint8_t *buff, size_t len);

/**
 * Frees the `rustls_signing_key`. This is safe to call with a `NULL` argument, but
 * must not be called twice with the same value.
 */
void rustls_signing_key_free(struct rustls_signing_key *signing_key);

/**
 * Returns a pointer to the supported `rustls_hpke` Hybrid Public Key Encryption (HPKE)
 * suites, or `NULL` if HPKE is not supported.
 *
 * HPKE is only supported with the `aws-lc-rs` cryptography provider.
 *
 * The returned pointer has a static lifetime equal to that of the program and does not
 * need to be freed.
 */
const struct rustls_hpke *rustls_supported_hpke(void);

/**
 * Convert a `rustls_handshake_kind` to a string with a friendly description of the kind
 * of handshake.
 *
 * The returned `rustls_str` has a static lifetime equal to that of the program and does
 * not need to be manually freed.
 */
struct rustls_str rustls_handshake_kind_str(enum rustls_handshake_kind kind);

/**
 * After a rustls function returns an error, you may call this to write a detailed error
 * message into the caller-provided `buf`.
 *
 * This writes at most `len` bytes and stores the number written in `out_n`. If the full
 * message is longer than `len`, it is truncated. The output is UTF-8 encoded and is not
 * NUL-terminated.
 *
 * If `buf` or `out_n` is NULL, this function does nothing. The caller retains ownership of
 * `buf`, and the function does not retain it.
 */
void rustls_error(unsigned int result, char *buf, size_t len, size_t *out_n);

/**
 * Returns true if the `result` is a certificate-related error.
 */
bool rustls_result_is_cert_error(unsigned int result);

/**
 * Return a `rustls_str` containing the stringified version of a log level.
 *
 * The returned string has static lifetime and does not need to be freed.
 */
struct rustls_str rustls_log_level_str(rustls_log_level level);

/**
 * Return the length of the outer slice. If the input pointer is NULL,
 * returns 0.
 */
size_t rustls_slice_slice_bytes_len(const struct rustls_slice_slice_bytes *input);

/**
 * Retrieve the nth element from the input slice of slices.
 *
 * If the input pointer is NULL, or `n` is greater than or equal to the length
 * of the `rustls_slice_slice_bytes`, returns a `rustls_slice_bytes` with a NULL data pointer
 * and a length of 0.
 *
 * Otherwise, the returned byte slice borrows its data from `input`. It remains valid for the
 * same lifetime as `input` and must not be freed.
 */
struct rustls_slice_bytes rustls_slice_slice_bytes_get(const struct rustls_slice_slice_bytes *input,
                                                       size_t n);

/**
 * Return the length of the outer slice.
 *
 * If the input pointer is NULL, returns 0.
 */
size_t rustls_slice_str_len(const struct rustls_slice_str *input);

/**
 * Retrieve the nth element from the input slice of `&str`s.
 *
 * If the input pointer is NULL, or `n` is greater than or equal to the length of the
 * `rustls_slice_str`, returns a `rustls_str` with a NULL data pointer and a length of 0.
 *
 * Otherwise, the returned string borrows its data from `input`. It remains valid for the same
 * lifetime as `input` and must not be freed.
 */
struct rustls_str rustls_slice_str_get(const struct rustls_slice_str *input, size_t n);

/**
 * Create a `rustls_server_config_builder` using the process default crypto provider.
 *
 * Caller owns the memory and must eventually call `rustls_server_config_builder_build`,
 * then free the resulting `rustls_server_config`.
 *
 * Alternatively, if an error occurs or, you don't wish to build a config, call
 * `rustls_server_config_builder_free` to free the builder directly.
 *
 * This uses the process default provider's values for the cipher suites and key exchange
 * groups, as well as safe defaults for protocol versions.
 */
struct rustls_server_config_builder *rustls_server_config_builder_new(void);

/**
 * Create a `rustls_server_config_builder` using the specified crypto provider.
 *
 * Caller owns the memory and must eventually call `rustls_server_config_builder_build`,
 * then free the resulting `rustls_server_config`.
 *
 * Alternatively, if an error occurs or, you don't wish to build a config, call
 * `rustls_server_config_builder_free` to free the builder directly.
 *
 * `tls_versions` sets the TLS protocol versions to use when negotiating a TLS session.
 * Each value is a protocol version as defined in RFC 8446, sections 4.2.1 and 5.1.
 * Some values are defined in
 * `rustls_tls_version` for convenience.
 *
 * `tls_versions` will only be used during the call and the application retains
 * ownership. `tls_versions_len` is the number of consecutive `uint16_t` pointed
 * to by `tls_versions`.
 *
 * On `RUSTLS_RESULT_OK`, `builder_out` receives a builder owned by the caller.
 * It must eventually be passed to `rustls_server_config_builder_build` or freed with
 * `rustls_server_config_builder_free`. On error, `builder_out` is unchanged.
 *
 * The function borrows `provider` for the duration of the call and retains its own
 * reference afterward.
 *
 * Ciphersuites are configured separately via the crypto provider. See
 * `rustls_crypto_provider_builder_set_cipher_suites` for more information.
 */
rustls_result rustls_server_config_builder_new_custom(const struct rustls_crypto_provider *provider,
                                                      const uint16_t *tls_versions,
                                                      size_t tls_versions_len,
                                                      struct rustls_server_config_builder **builder_out);

/**
 * Configure a `rustls_server_config_builder` to verify client certificates.
 * Client authentication is disabled unless this function is called.
 *
 * To require client certificates that chain to a custom set of roots:
 *
 * 1. Create a `rustls_root_cert_store_builder` with
 *    `rustls_root_cert_store_builder_new`.
 * 2. Add roots with `rustls_root_cert_store_builder_add_pem` or
 *    `rustls_root_cert_store_builder_load_roots_from_file`, then call
 *    `rustls_root_cert_store_builder_build`.
 * 3. Pass the resulting store to
 *    `rustls_web_pki_client_cert_verifier_builder_new`, then call
 *    `rustls_web_pki_client_cert_verifier_builder_build`.
 * 4. Pass the resulting verifier to this function.
 *
 * This function increases the reference count of `verifier` and does not
 * take ownership. The caller must still free its verifier pointer with
 * `rustls_client_cert_verifier_free` when it is no longer needed.
 */
void rustls_server_config_builder_set_client_verifier(struct rustls_server_config_builder *builder,
                                                      const struct rustls_client_cert_verifier *verifier);

/**
 * Log key material to the file specified by the `SSLKEYLOGFILE` environment variable.
 *
 * The key material will be logged in the [NSS key log format] and is compatible
 * with tools like Wireshark.
 *
 * Secrets logged in this manner are **extremely sensitive** and can break the security
 * of past, present and future sessions.
 *
 * For more control over which secrets are logged, or to customize the format, prefer
 * `rustls_server_config_builder_set_key_log`.
 *
 * [NSS key log format]: https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
 */
rustls_result rustls_server_config_builder_set_key_log_file(struct rustls_server_config_builder *builder);

/**
 * Provide callbacks to manage logging key material.
 *
 * The `log_cb` argument is mandatory and must not be `NULL` or a `NullParameter` error is
 * returned. The `log_cb` will be invoked with a `client_random` to identify the relevant session,
 * a `label` to identify the purpose of the `secret`, and the `secret` itself. See the
 * rustls documentation for [`KeyLog::log`] for more information on possible labels.
 *
 * The `will_log_cb` may be `NULL`, in which case all key material will be provided to
 * the `log_cb`. By providing a custom `will_log_cb` you may return `0` for labels you don't
 * wish to log, and non-zero for labels you _do_ wish to log as a performance optimization.
 *
 * Both callbacks **must** be thread-safe. Arguments provided to the callback live only for as
 * long as the callback is executing and are not valid after the callback returns. The
 * callbacks must not retain references to the provided data.
 *
 * Secrets provided to the `log_cb` are **extremely sensitive** and can break the security
 * of past, present and future sessions.
 *
 * See also `rustls_server_config_builder_set_key_log_file` for a simpler way to log
 * to a file specified by the `SSLKEYLOGFILE` environment variable.
 *
 * [`KeyLog::log`]: https://docs.rs/rustls/latest/rustls/trait.KeyLog.html#tymethod.log
 */
rustls_result rustls_server_config_builder_set_key_log(struct rustls_server_config_builder *builder,
                                                       rustls_keylog_log_callback log_cb,
                                                       rustls_keylog_will_log_callback will_log_cb);

/**
 * Free a `rustls_server_config_builder` without building it into a
 * `rustls_server_config`.
 *
 * Do not call this after `rustls_server_config_builder_build`, which consumes and frees the
 * builder. Calling with NULL is fine. Must not be called twice with the same value.
 */
void rustls_server_config_builder_free(struct rustls_server_config_builder *config);

/**
 * With `ignore` != 0, the server will ignore the client ordering of cipher
 * suites, aka preference, during handshake and respect its own ordering
 * as configured.
 *
 * See also the rustls documentation for [`ServerConfig::ignore_client_order`].
 *
 * [`ServerConfig::ignore_client_order`]: https://docs.rs/rustls/latest/rustls/struct.ServerConfig.html#structfield.ignore_client_order
 */
rustls_result rustls_server_config_builder_set_ignore_client_order(struct rustls_server_config_builder *builder,
                                                                   bool ignore);

/**
 * Set the number of TLS 1.3 NewSessionTickets sent after a full handshake.
 *
 * Setting this to 0 disables session ticket issuance entirely.
 *
 * See also the rustls documentation for [`ServerConfig::send_tls13_tickets`].
 *
 * [`ServerConfig::send_tls13_tickets`]: https://docs.rs/rustls/latest/rustls/server/struct.ServerConfig.html#structfield.send_tls13_tickets
 */
rustls_result rustls_server_config_builder_set_send_tls13_tickets(struct rustls_server_config_builder *builder,
                                                                  size_t n);

/**
 * Set the upper bound on the number of TLS 1.3 tickets sent in response to a client.
 *
 * This modifies the server's response to a client's RFC 9149 `ticket_request` extension.
 *
 * A client requesting `n` tickets receives `min(n, max)`. Setting this to
 * 0 (the default) ignores client requests entirely, clients get the configured
 * `send_tls13_tickets` count regardless.
 *
 * See also the rustls documentation for [`ServerConfig::max_tls13_tickets`].
 *
 * [`ServerConfig::max_tls13_tickets`]: https://docs.rs/rustls/latest/rustls/server/struct.ServerConfig.html#structfield.max_tls13_tickets
 */
rustls_result rustls_server_config_builder_set_max_tls13_tickets(struct rustls_server_config_builder *builder,
                                                                 size_t max);

/**
 * Set the ALPN protocol list to the given protocols.
 *
 * `protocols` must point to a buffer of `rustls_slice_bytes` (built by the caller)
 * with `len` elements. Each element of the buffer must point to a slice of bytes that
 * contains a single ALPN protocol from the [IANA registry].
 *
 * This function makes a copy of the data in `protocols` and does not retain
 * any pointers, so the caller can free the pointed-to memory after calling.
 *
 * See also the rustls documentation for [`ServerConfig::alpn_protocols`].
 *
 * [IANA registry]: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
 * [`ServerConfig::alpn_protocols`]: https://docs.rs/rustls/latest/rustls/server/struct.ServerConfig.html#structfield.alpn_protocols
 */
rustls_result rustls_server_config_builder_set_alpn_protocols(struct rustls_server_config_builder *builder,
                                                              const struct rustls_slice_bytes *protocols,
                                                              size_t len);

/**
 * Provide the configuration a list of certificates where the connection
 * will select the first one that is compatible with the client's signature
 * verification capabilities.
 *
 * Servers that want to support both ECDSA and RSA certificates will want
 * the ECDSA certificate to go first in the list.
 *
 * In the usual case, first call `rustls_certified_key_build` with the PEM
 * certificate chain and private key, then pass the resulting
 * `rustls_certified_key` pointer to this function. The builder and built
 * configuration keep a reference to each certified key, so the caller may
 * call `rustls_certified_key_free()` after this function returns. The same
 * certified key may also be used in multiple configs.
 *
 * EXPERIMENTAL: installing a client_hello callback will replace any
 * configured certified keys and vice versa.
 */
rustls_result rustls_server_config_builder_set_certified_keys(struct rustls_server_config_builder *builder,
                                                              const struct rustls_certified_key *const *certified_keys,
                                                              size_t certified_keys_len);

/**
 * Turn a mutable `rustls_server_config_builder` into a const `rustls_server_config`
 * (read-only). The constructed `rustls_server_config` will be written to the `config_out`
 * pointer when this function returns `RUSTLS_RESULT_OK`.
 *
 * This function takes ownership of `builder`. The caller must not use or free the builder
 * after calling this function, regardless of the result.
 *
 * On `RUSTLS_RESULT_OK`, `config_out` receives a config owned by the caller, which must
 * eventually be freed with `rustls_server_config_free`. On error, `config_out` is unchanged.
 *
 * This function may return an error if no process default crypto provider has been set
 * and the builder was constructed using `rustls_server_config_builder_new`, or if no
 * certificate resolver was set.
 */
rustls_result rustls_server_config_builder_build(struct rustls_server_config_builder *builder,
                                                 const struct rustls_server_config **config_out);

/**
 * Returns true if a `rustls_connection` created from the `rustls_server_config` will
 * operate in FIPS mode.
 *
 * This is different from `rustls_crypto_provider_fips` which is concerned
 * only with cryptography, whereas this also covers TLS-level configuration that NIST
 * recommends, as well as ECH HPKE suites if applicable.
 */
bool rustls_server_config_fips(const struct rustls_server_config *config);

/**
 * Release the caller's reference to a `rustls_server_config` previously returned from
 * `rustls_server_config_builder_build`.
 *
 * Existing server connections may still hold internal references to the atomically
 * reference-counted Rust object. Regardless, the caller must not use `config` after this
 * function returns.
 *
 * Calling with NULL is fine. Must not be called twice with the same value.
 */
void rustls_server_config_free(const struct rustls_server_config *config);

/**
 * Create a new `rustls_connection` containing a server connection, and return it.
 *
 * It is returned in the output parameter `conn_out`.
 *
 * If this returns an error code, the memory pointed to by `conn_out` remains unchanged.
 *
 * If this returns a non-error, the memory pointed to by `conn_out` is modified to point
 * at a valid `rustls_connection`
 *
 * The caller now owns the `rustls_connection` and must call `rustls_connection_free` when
 * done with it.
 *
 * The connection retains an internal reference to `config`. This function
 * does not take ownership of the caller's config pointer.
 */
rustls_result rustls_server_connection_new(const struct rustls_server_config *config,
                                           struct rustls_connection **conn_out);

/**
 * Returns a `rustls_str` reference to the server name sent by the client in a server name
 * indication (SNI) extension.
 *
 * The returned `rustls_str` is valid until the next mutating function call affecting the
 * connection. A mutating function call is one where the first argument is a mutable pointer to
 * `rustls_connection` (as opposed to a const pointer). The caller does not need to free the
 * `rustls_str`.
 *
 * Returns a zero-length `rustls_str` if:
 *
 * - the connection is not a server connection.
 * - the connection is a server connection but the SNI extension in the ClientHello has not
 *   been processed during the handshake yet. Check `rustls_connection_is_handshaking`.
 * - the SNI value contains null bytes.
 */
struct rustls_str rustls_server_connection_get_server_name(const struct rustls_connection *conn);

/**
 * Register a callback to be invoked when a connection created from this config
 * sees a TLS ClientHello message. If `userdata` has been set with
 * `rustls_connection_set_userdata`, it will be passed to the callback.
 * Otherwise the userdata param passed to the callback will be NULL.
 *
 * Any existing `ResolvesServerCert` implementation currently installed in the
 * `rustls_server_config` will be replaced. This also means registering twice
 * will overwrite the first registration. It is not permitted to pass a NULL
 * value for `callback`.
 *
 * EXPERIMENTAL: this feature of rustls-ffi is likely to change in the future, as
 * the rustls library is re-evaluating its current approach to ClientHello handling.
 * Installing a client_hello callback will replace any configured certified keys
 * and vice versa. Same holds true for the set_certified_keys variant.
 */
rustls_result rustls_server_config_builder_set_hello_callback(struct rustls_server_config_builder *builder,
                                                              rustls_client_hello_callback callback);

/**
 * Select a `rustls_certified_key` from the list that matches the cryptographic
 * parameters of a TLS ClientHello.
 *
 * Note that this does not do any SNI matching. The input certificates should
 * already have been filtered to ones matching the SNI from the ClientHello.
 *
 * This is intended for servers that are configured with several keys for the
 * same domain name(s), for example ECDSA and RSA types. The presented keys are
 * inspected in the order given and keys first in the list are given preference,
 * all else being equal. However rustls is free to choose whichever it considers
 * to be the best key with its knowledge about security issues and possible future
 * extensions of the protocol.
 *
 * Return `RUSTLS_RESULT_OK` if a key was selected and `RUSTLS_RESULT_NOT_FOUND`
 * if none was suitable.
 *
 * On success, `out_key` is set to one of the pointers from `certified_keys`. The function does
 * not take ownership or increment the reference count. The returned pointer remains valid only
 * while the caller keeps the corresponding input key alive and must not be freed separately.
 *
 * On error, `out_key` is unchanged.
 */
rustls_result rustls_client_hello_select_certified_key(const struct rustls_client_hello *hello,
                                                       const struct rustls_certified_key *const *certified_keys,
                                                       size_t certified_keys_len,
                                                       const struct rustls_certified_key **out_key);

/**
 * Register callbacks for persistence of TLS session IDs and secrets. Both
 * keys and values are highly sensitive data, containing enough information
 * to break the security of the connections involved.
 *
 * If `builder`, `get_cb`, or `put_cb` are NULL, this function will return
 * immediately without doing anything.
 *
 * If `userdata` has been set with `rustls_connection_set_userdata`, it
 * will be passed to the callbacks. Otherwise the userdata param passed to
 * the callbacks will be NULL.
 */
void rustls_server_config_builder_set_persistence(struct rustls_server_config_builder *builder,
                                                  rustls_session_store_get_callback get_cb,
                                                  rustls_session_store_put_callback put_cb);

/**
 * Free a `rustls_client_cert_verifier` previously returned from
 * `rustls_web_pki_client_cert_verifier_builder_build`. Calling with NULL is fine.
 * Must not be called twice with the same value.
 */
void rustls_client_cert_verifier_free(struct rustls_client_cert_verifier *verifier);

/**
 * Create a `rustls_web_pki_client_cert_verifier_builder` using the process-wide default
 * cryptography provider.
 *
 * Caller owns the memory and may eventually call `rustls_web_pki_client_cert_verifier_builder_free`
 * to free it, whether or not `rustls_web_pki_client_cert_verifier_builder_build` was called.
 *
 * Without further modification the builder will produce a client certificate verifier that
 * will require a client to present a client certificate that chains to one of the trust anchors
 * in the provided `rustls_root_cert_store`. The root cert store must not be empty.
 *
 * Revocation checking will not be performed unless
 * `rustls_web_pki_client_cert_verifier_builder_add_crl` is used to add certificate revocation
 * lists (CRLs) to the builder. If CRLs are added, revocation checking will be performed
 * for the entire certificate chain unless
 * `rustls_web_pki_client_cert_verifier_only_check_end_entity_revocation` is used. Unknown
 * revocation status for certificates considered for revocation status will be treated as
 * an error unless `rustls_web_pki_client_cert_verifier_allow_unknown_revocation_status` is
 * used.
 *
 * Unauthenticated clients will not be permitted unless
 * `rustls_web_pki_client_cert_verifier_builder_allow_unauthenticated` is used.
 *
 * This does not take ownership of `store`. The builder retains its own
 * reference, so the caller may free its root certificate store pointer after
 * this function returns.
 */
struct rustls_web_pki_client_cert_verifier_builder *rustls_web_pki_client_cert_verifier_builder_new(const struct rustls_root_cert_store *store);

/**
 * Create a `rustls_web_pki_client_cert_verifier_builder` using the specified
 * cryptography provider.
 *
 * Caller owns the memory and may eventually call
 * `rustls_web_pki_client_cert_verifier_builder_free` to free it, whether or
 * not `rustls_web_pki_client_cert_verifier_builder_build` was called.
 *
 * Without further modification the builder will produce a client certificate verifier that
 * will require a client to present a client certificate that chains to one of the trust anchors
 * in the provided `rustls_root_cert_store`. The root cert store must not be empty.
 *
 * Revocation checking will not be performed unless
 * `rustls_web_pki_client_cert_verifier_builder_add_crl` is used to add certificate revocation
 * lists (CRLs) to the builder. If CRLs are added, revocation checking will be performed
 * for the entire certificate chain unless
 * `rustls_web_pki_client_cert_verifier_only_check_end_entity_revocation` is used. Unknown
 * revocation status for certificates considered for revocation status will be treated as
 * an error unless `rustls_web_pki_client_cert_verifier_allow_unknown_revocation_status` is
 * used.
 *
 * Unauthenticated clients will not be permitted unless
 * `rustls_web_pki_client_cert_verifier_builder_allow_unauthenticated` is used.
 *
 * This does not take ownership of `provider` or `store`. The builder retains
 * its own references, so the caller may free both input pointers after this
 * function returns.
 */
struct rustls_web_pki_client_cert_verifier_builder *rustls_web_pki_client_cert_verifier_builder_new_with_provider(const struct rustls_crypto_provider *provider,
                                                                                                                  const struct rustls_root_cert_store *store);

/**
 * Add one or more certificate revocation lists (CRLs) to the client certificate verifier
 * builder by reading the CRL content from the provided buffer of PEM encoded content.
 *
 * By default revocation checking will be performed on the entire certificate chain. To only
 * check the revocation status of the end entity certificate, use
 * `rustls_web_pki_client_cert_verifier_only_check_end_entity_revocation`.
 *
 * This function returns an error if the provided buffer is not valid PEM encoded content.
 *
 * It copies the parsed CRLs and does not retain `crl_pem`.
 */
rustls_result rustls_web_pki_client_cert_verifier_builder_add_crl(struct rustls_web_pki_client_cert_verifier_builder *builder,
                                                                  const uint8_t *crl_pem,
                                                                  size_t crl_pem_len);

/**
 * When CRLs are provided with `rustls_web_pki_client_cert_verifier_builder_add_crl`, only
 * check the revocation status of end entity certificates, ignoring any intermediate certificates
 * in the chain.
 */
rustls_result rustls_web_pki_client_cert_verifier_only_check_end_entity_revocation(struct rustls_web_pki_client_cert_verifier_builder *builder);

/**
 * When CRLs are provided with `rustls_web_pki_client_cert_verifier_builder_add_crl`, and it
 * isn't possible to determine the revocation status of a considered certificate, do not treat
 * it as an error condition.
 *
 * Overrides the default behavior where unknown revocation status is considered an error.
 */
rustls_result rustls_web_pki_client_cert_verifier_allow_unknown_revocation_status(struct rustls_web_pki_client_cert_verifier_builder *builder);

/**
 * Allow unauthenticated anonymous clients in addition to those that present a client
 * certificate that chains to one of the verifier's configured trust anchors.
 */
rustls_result rustls_web_pki_client_cert_verifier_builder_allow_unauthenticated(struct rustls_web_pki_client_cert_verifier_builder *builder);

/**
 * Clear the list of trust anchor hint subjects.
 *
 * By default, the client cert verifier will use the subjects provided by the root cert
 * store configured for client authentication. Calling this function will remove these
 * hint subjects, indicating the client should make a free choice of which certificate
 * to send.
 */
rustls_result rustls_web_pki_client_cert_verifier_clear_root_hint_subjects(struct rustls_web_pki_client_cert_verifier_builder *builder);

/**
 * Add additional distinguished names to the list of trust anchor hint subjects.
 *
 * By default, the client cert verifier will use the subjects provided by the root cert
 * store configured for client authentication. Calling this function will add to these
 * existing hint subjects. Calling this function with an empty `store` will have no
 * effect, use `rustls_web_pki_client_cert_verifier_clear_root_hint_subjects` to clear
 * the subject hints.
 */
rustls_result rustls_web_pki_client_cert_verifier_add_root_hint_subjects(struct rustls_web_pki_client_cert_verifier_builder *builder,
                                                                         const struct rustls_root_cert_store *store);

/**
 * Create a new client certificate verifier from the builder.
 *
 * The builder is consumed and cannot be used again, but must still be freed.
 *
 * On `RUSTLS_RESULT_OK`, `verifier_out` receives a verifier owned by the caller. It can be
 * used in several `rustls_server_config` instances and must be freed with
 * `rustls_client_cert_verifier_free` when no longer needed. On error, `verifier_out` is
 * unchanged.
 */
rustls_result rustls_web_pki_client_cert_verifier_builder_build(struct rustls_web_pki_client_cert_verifier_builder *builder,
                                                                struct rustls_client_cert_verifier **verifier_out);

/**
 * Free a `rustls_web_pki_client_cert_verifier_builder` previously returned from
 * `rustls_web_pki_client_cert_verifier_builder_new`.
 *
 * Calling with NULL is fine. Must not be called twice with the same value.
 */
void rustls_web_pki_client_cert_verifier_builder_free(struct rustls_web_pki_client_cert_verifier_builder *builder);

/**
 * Create a `rustls_web_pki_server_cert_verifier_builder` using the process-wide default
 * crypto provider.
 *
 * Caller owns the memory and may free it with `rustls_web_pki_server_cert_verifier_builder_free`,
 * regardless of whether `rustls_web_pki_server_cert_verifier_builder_build` was called.
 *
 * Without further modification the builder will produce a server certificate verifier that
 * will require a server to present a certificate that chains to one of the trust anchors
 * in the provided `rustls_root_cert_store`. The root cert store must not be empty.
 *
 * Revocation checking will not be performed unless
 * `rustls_web_pki_server_cert_verifier_builder_add_crl` is used to add certificate revocation
 * lists (CRLs) to the builder.  If CRLs are added, revocation checking will be performed
 * for the entire certificate chain unless
 * `rustls_web_pki_server_cert_verifier_only_check_end_entity_revocation` is used. Unknown
 * revocation status for certificates considered for revocation status will be treated as
 * an error unless `rustls_web_pki_server_cert_verifier_allow_unknown_revocation_status` is
 * used.
 *
 * This does not take ownership of `store`. The builder retains its own
 * reference, so the caller may free its root certificate store pointer after
 * this function returns.
 */
struct rustls_web_pki_server_cert_verifier_builder *rustls_web_pki_server_cert_verifier_builder_new(const struct rustls_root_cert_store *store);

/**
 * Create a `rustls_web_pki_server_cert_verifier_builder` using the specified
 * crypto provider. Caller owns the memory and may free it with
 * `rustls_web_pki_server_cert_verifier_builder_free`, regardless of whether
 * `rustls_web_pki_server_cert_verifier_builder_build` was called.
 *
 * Without further modification the builder will produce a server certificate verifier that
 * will require a server to present a certificate that chains to one of the trust anchors
 * in the provided `rustls_root_cert_store`. The root cert store must not be empty.
 *
 * Revocation checking will not be performed unless
 * `rustls_web_pki_server_cert_verifier_builder_add_crl` is used to add certificate revocation
 * lists (CRLs) to the builder.  If CRLs are added, revocation checking will be performed
 * for the entire certificate chain unless
 * `rustls_web_pki_server_cert_verifier_only_check_end_entity_revocation` is used. Unknown
 * revocation status for certificates considered for revocation status will be treated as
 * an error unless `rustls_web_pki_server_cert_verifier_allow_unknown_revocation_status` is
 * used. Expired CRLs will not be treated as an error unless
 * `rustls_web_pki_server_cert_verifier_enforce_revocation_expiry` is used.
 *
 * This does not take ownership of `provider` or `store`. The builder retains
 * its own references, so the caller may free both input pointers after this
 * function returns.
 */
struct rustls_web_pki_server_cert_verifier_builder *rustls_web_pki_server_cert_verifier_builder_new_with_provider(const struct rustls_crypto_provider *provider,
                                                                                                                  const struct rustls_root_cert_store *store);

/**
 * Add one or more certificate revocation lists (CRLs) to the server certificate verifier
 * builder by reading the CRL content from the provided buffer of PEM encoded content.
 *
 * By default revocation checking will be performed on the entire certificate chain. To only
 * check the revocation status of the end entity certificate, use
 * `rustls_web_pki_server_cert_verifier_only_check_end_entity_revocation`.
 *
 * This function returns an error if the provided buffer is not valid PEM encoded content.
 *
 * It copies the parsed CRLs and does not retain `crl_pem`.
 */
rustls_result rustls_web_pki_server_cert_verifier_builder_add_crl(struct rustls_web_pki_server_cert_verifier_builder *builder,
                                                                  const uint8_t *crl_pem,
                                                                  size_t crl_pem_len);

/**
 * When CRLs are provided with `rustls_web_pki_server_cert_verifier_builder_add_crl`, only
 * check the revocation status of end entity certificates, ignoring any intermediate certificates
 * in the chain.
 */
rustls_result rustls_web_pki_server_cert_verifier_only_check_end_entity_revocation(struct rustls_web_pki_server_cert_verifier_builder *builder);

/**
 * When CRLs are provided with `rustls_web_pki_server_cert_verifier_builder_add_crl`, and it
 * isn't possible to determine the revocation status of a considered certificate, do not treat
 * it as an error condition.
 *
 * Overrides the default behavior where unknown revocation status is considered an error.
 */
rustls_result rustls_web_pki_server_cert_verifier_allow_unknown_revocation_status(struct rustls_web_pki_server_cert_verifier_builder *builder);

/**
 * When CRLs are provided with `rustls_web_pki_server_cert_verifier_builder_add_crl`, and the
 * CRL nextUpdate field is in the past, treat it as an error condition.
 *
 * Overrides the default behavior where CRL expiration is ignored.
 */
rustls_result rustls_web_pki_server_cert_verifier_enforce_revocation_expiry(struct rustls_web_pki_server_cert_verifier_builder *builder);

/**
 * Create a new server certificate verifier from the builder.
 *
 * The builder is consumed and cannot be used again, but must still be freed.
 *
 * On `RUSTLS_RESULT_OK`, `verifier_out` receives a verifier owned by the caller. It can be
 * used in several `rustls_client_config` instances and must be freed with
 * `rustls_server_cert_verifier_free` when no longer needed. On error, `verifier_out` is
 * unchanged.
 */
rustls_result rustls_web_pki_server_cert_verifier_builder_build(struct rustls_web_pki_server_cert_verifier_builder *builder,
                                                                struct rustls_server_cert_verifier **verifier_out);

/**
 * Free a `rustls_web_pki_server_cert_verifier_builder` previously returned from
 * `rustls_web_pki_server_cert_verifier_builder_new`.
 *
 * Calling with NULL is fine. Must not be called twice with the same value.
 */
void rustls_web_pki_server_cert_verifier_builder_free(struct rustls_web_pki_server_cert_verifier_builder *builder);

/**
 * Create a verifier that uses the default behavior for the current platform.
 *
 * This uses [`rustls-platform-verifier`][].
 *
 * The verifier can be used in several `rustls_client_config` instances and must be freed by
 * the application using `rustls_server_cert_verifier_free` when no longer needed.
 *
 * On error, `verifier_out` is unchanged.
 *
 * [`rustls-platform-verifier`]: https://github.com/rustls/rustls-platform-verifier
 */
rustls_result rustls_platform_server_cert_verifier(struct rustls_server_cert_verifier **verifier_out);

/**
 * Create a verifier that uses the default behavior for the current platform.
 *
 * This uses [`rustls-platform-verifier`][] and the specified crypto provider.
 *
 * The verifier can be used in several `rustls_client_config` instances and must be freed by
 * the application using `rustls_server_cert_verifier_free` when no longer needed.
 *
 * If the initialization of `rustls-platform-verifier` fails, this function returns
 * `NULL`.
 *
 * [`rustls-platform-verifier`]: https://github.com/rustls/rustls-platform-verifier
 */
DEPRECATED_FUNC("prefer to use rustls_platform_server_cert_verifier_try_with_provider")
struct rustls_server_cert_verifier *rustls_platform_server_cert_verifier_with_provider(const struct rustls_crypto_provider *provider);

/**
 * Create a verifier that uses the default behavior for the current platform.
 *
 * This uses [`rustls-platform-verifier`][] and the specified crypto provider.
 *
 * If the initialization of `rustls-platform-verifier` fails, this function returns
 * an error and `NULL` is written to `verifier_out`.  Otherwise it fills in `verifier_out`
 * (whose ownership is transferred to the caller) and returns `RUSTLS_RESULT_OK`.
 *
 * The verifier can be used in several `rustls_client_config` instances and must be freed by
 * the application using `rustls_server_cert_verifier_free` when no longer needed.
 *
 * [`rustls-platform-verifier`]: https://github.com/rustls/rustls-platform-verifier
 */
rustls_result rustls_platform_server_cert_verifier_try_with_provider(const struct rustls_crypto_provider *provider,
                                                                     struct rustls_server_cert_verifier **verifier_out);

/**
 * Free a `rustls_server_cert_verifier` previously returned from
 * `rustls_web_pki_server_cert_verifier_builder_build` or
 * `rustls_platform_server_cert_verifier`.
 *
 * Calling with NULL is fine. Must not be called twice with the same value.
 */
void rustls_server_cert_verifier_free(struct rustls_server_cert_verifier *verifier);

/**
 * Returns a static string containing the rustls-ffi version as well as the
 * rustls version. The string is alive for the lifetime of the program and does
 * not need to be freed.
 */
struct rustls_str rustls_version(void);

#endif  /* RUSTLS_H */
