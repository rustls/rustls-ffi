#ifndef CRUSTLS_H
#define CRUSTLS_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef enum {
  RUSTLS_RESULT_OK = 7000,
  RUSTLS_RESULT_IO,
  RUSTLS_RESULT_NULL_PARAMETER,
  RUSTLS_RESULT_CORRUPT_MESSAGE,
  RUSTLS_RESULT_NO_CERTIFICATES_PRESENTED,
  RUSTLS_RESULT_DECRYPT_ERROR,
  RUSTLS_RESULT_FAILED_TO_GET_CURRENT_TIME,
  RUSTLS_RESULT_HANDSHAKE_NOT_COMPLETE,
  RUSTLS_RESULT_PEER_SENT_OVERSIZED_RECORD,
  RUSTLS_RESULT_NO_APPLICATION_PROTOCOL,
  RUSTLS_RESULT_PEER_INCOMPATIBLE_ERROR,
  RUSTLS_RESULT_PEER_MISBEHAVED_ERROR,
  RUSTLS_RESULT_INAPPROPRIATE_MESSAGE,
  RUSTLS_RESULT_INAPPROPRIATE_HANDSHAKE_MESSAGE,
  RUSTLS_RESULT_CORRUPT_MESSAGE_PAYLOAD,
  RUSTLS_RESULT_GENERAL,
  RUSTLS_RESULT_ALERT_CLOSE_NOTIFY,
  RUSTLS_RESULT_ALERT_UNEXPECTED_MESSAGE,
  RUSTLS_RESULT_ALERT_BAD_RECORD_MAC,
  RUSTLS_RESULT_ALERT_DECRYPTION_FAILED,
  RUSTLS_RESULT_ALERT_RECORD_OVERFLOW,
  RUSTLS_RESULT_ALERT_DECOMPRESSION_FAILURE,
  RUSTLS_RESULT_ALERT_HANDSHAKE_FAILURE,
  RUSTLS_RESULT_ALERT_NO_CERTIFICATE,
  RUSTLS_RESULT_ALERT_BAD_CERTIFICATE,
  RUSTLS_RESULT_ALERT_UNSUPPORTED_CERTIFICATE,
  RUSTLS_RESULT_ALERT_CERTIFICATE_REVOKED,
  RUSTLS_RESULT_ALERT_CERTIFICATE_EXPIRED,
  RUSTLS_RESULT_ALERT_CERTIFICATE_UNKNOWN,
  RUSTLS_RESULT_ALERT_ILLEGAL_PARAMETER,
  RUSTLS_RESULT_ALERT_UNKNOWN_CA,
  RUSTLS_RESULT_ALERT_ACCESS_DENIED,
  RUSTLS_RESULT_ALERT_DECODE_ERROR,
  RUSTLS_RESULT_ALERT_DECRYPT_ERROR,
  RUSTLS_RESULT_ALERT_EXPORT_RESTRICTION,
  RUSTLS_RESULT_ALERT_PROTOCOL_VERSION,
  RUSTLS_RESULT_ALERT_INSUFFICIENT_SECURITY,
  RUSTLS_RESULT_ALERT_INTERNAL_ERROR,
  RUSTLS_RESULT_ALERT_INAPPROPRIATE_FALLBACK,
  RUSTLS_RESULT_ALERT_USER_CANCELED,
  RUSTLS_RESULT_ALERT_NO_RENEGOTIATION,
  RUSTLS_RESULT_ALERT_MISSING_EXTENSION,
  RUSTLS_RESULT_ALERT_UNSUPPORTED_EXTENSION,
  RUSTLS_RESULT_ALERT_CERTIFICATE_UNOBTAINABLE,
  RUSTLS_RESULT_ALERT_UNRECOGNISED_NAME,
  RUSTLS_RESULT_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE,
  RUSTLS_RESULT_ALERT_BAD_CERTIFICATE_HASH_VALUE,
  RUSTLS_RESULT_ALERT_UNKNOWN_PSK_IDENTITY,
  RUSTLS_RESULT_ALERT_CERTIFICATE_REQUIRED,
  RUSTLS_RESULT_ALERT_NO_APPLICATION_PROTOCOL,
  RUSTLS_RESULT_ALERT_UNKNOWN,
  RUSTLS_RESULT_CERT_BAD_DER,
  RUSTLS_RESULT_CERT_BAD_DER_TIME,
  RUSTLS_RESULT_CERT_CA_USED_AS_END_ENTITY,
  RUSTLS_RESULT_CERT_EXPIRED,
  RUSTLS_RESULT_CERT_NOT_VALID_FOR_NAME,
  RUSTLS_RESULT_CERT_NOT_VALID_YET,
  RUSTLS_RESULT_CERT_END_ENTITY_USED_AS_CA,
  RUSTLS_RESULT_CERT_EXTENSION_VALUE_INVALID,
  RUSTLS_RESULT_CERT_INVALID_CERT_VALIDITY,
  RUSTLS_RESULT_CERT_INVALID_SIGNATURE_FOR_PUBLIC_KEY,
  RUSTLS_RESULT_CERT_NAME_CONSTRAINT_VIOLATION,
  RUSTLS_RESULT_CERT_PATH_LEN_CONSTRAINT_VIOLATED,
  RUSTLS_RESULT_CERT_SIGNATURE_ALGORITHM_MISMATCH,
  RUSTLS_RESULT_CERT_REQUIRED_EKU_NOT_FOUND,
  RUSTLS_RESULT_CERT_UNKNOWN_ISSUER,
  RUSTLS_RESULT_CERT_UNSUPPORTED_CERT_VERSION,
  RUSTLS_RESULT_CERT_UNSUPPORTED_CRITICAL_EXTENSION,
  RUSTLS_RESULT_CERT_UNSUPPORTED_SIGNATURE_ALGORITHM_FOR_PUBLIC_KEY,
  RUSTLS_RESULT_CERT_UNSUPPORTED_SIGNATURE_ALGORITHM,
  RUSTLS_RESULT_CERT_SCT_MALFORMED,
  RUSTLS_RESULT_CERT_SCT_INVALID_SIGNATURE,
  RUSTLS_RESULT_CERT_SCT_TIMESTAMP_IN_FUTURE,
  RUSTLS_RESULT_CERT_SCT_UNSUPPORTED_VERSION,
  RUSTLS_RESULT_CERT_SCT_UNKNOWN_LOG,
} rustls_result;

/**
 * A client config that is done being constructed and is now read-only.
 * Under the hood, this object corresponds to an Arc<ClientConfig>.
 * https://docs.rs/rustls/0.19.0/rustls/struct.ClientConfig.html
 */
typedef struct rustls_client_config rustls_client_config;

/**
 * A client config being constructed. A builder can be modified by,
 * e.g. rustls_client_config_builder_load_native_roots. Once you're
 * done configuring settings, call rustls_client_config_builder_build
 * to turn it into a *rustls_client_config. This object is not safe
 * for concurrent mutation. Under the hood, it corresponds to a
 * Box<ClientConfig>.
 * https://docs.rs/rustls/0.19.0/rustls/struct.ClientConfig.html
 */
typedef struct rustls_client_config_builder rustls_client_config_builder;

typedef struct rustls_client_session rustls_client_session;

/**
 * Write the version of the crustls C bindings and rustls itself into the
 * provided buffer, up to a max of `len` bytes. Output is UTF-8 encoded
 * and NUL terminated. Returns the number of bytes written before the NUL.
 */
size_t rustls_version(char *buf, size_t len);

/**
 * Create a rustls_client_config_builder. Caller owns the memory and must
 * eventually call rustls_client_config_builder_build, then free the
 * resulting rustls_client_config. This starts out with no trusted roots.
 * Caller must add roots with rustls_client_config_builder_load_native_roots
 * or rustls_client_config_builder_load_roots_from_file.
 */
rustls_client_config_builder *rustls_client_config_builder_new(void);

/**
 * Turn a *rustls_client_config_builder (mutable) into a *rustls_client_config
 * (read-only).
 */
const rustls_client_config *rustls_client_config_builder_build(rustls_client_config_builder *builder);

/**
 * Add certificates from platform's native root store, using
 * https://github.com/ctz/rustls-native-certs#readme.
 */
rustls_result rustls_client_config_builder_load_native_roots(rustls_client_config_builder *config);

/**
 * Add trusted root certificates from the named file, which should contain
 * PEM-formatted certificates.
 */
rustls_result rustls_client_config_builder_load_roots_from_file(rustls_client_config_builder *config,
                                                                const char *filename);

/**
 * "Free" a client_config previously returned from
 * rustls_client_config_builder_build. Since client_config is actually an
 * atomically reference-counted pointer, extant client_sessions may still
 * hold an internal reference to the Rust object. However, C code must
 * consider this pointer unusable after "free"ing it.
 * Calling with NULL is fine. Must not be called twice with the same value.
 */
void rustls_client_config_free(const rustls_client_config *config);

/**
 * Create a new rustls::ClientSession, and return it in the output parameter `out`.
 * If this returns an error code, the memory pointed to by `session_out` remains unchanged.
 * If this returns a non-error, the memory pointed to by `session_out` is modified to point
 * at a valid ClientSession. The caller now owns the ClientSession and must call
 * `rustls_client_session_free` when done with it.
 */
rustls_result rustls_client_session_new(const rustls_client_config *config,
                                        const char *hostname,
                                        rustls_client_session **session_out);

bool rustls_client_session_wants_read(const rustls_client_session *session);

bool rustls_client_session_wants_write(const rustls_client_session *session);

bool rustls_client_session_is_handshaking(const rustls_client_session *session);

rustls_result rustls_client_session_process_new_packets(rustls_client_session *session);

/**
 * Queues a close_notify fatal alert to be sent in the next write_tls call.
 * https://docs.rs/rustls/0.19.0/rustls/trait.Session.html#tymethod.send_close_notify
 */
void rustls_client_session_send_close_notify(rustls_client_session *session);

/**
 * Free a client_session previously returned from rustls_client_session_new.
 * Calling with NULL is fine. Must not be called twice with the same value.
 */
void rustls_client_session_free(rustls_client_session *session);

/**
 * Write up to `count` plaintext bytes from `buf` into the ClientSession.
 * This will increase the number of output bytes available to
 * `rustls_client_session_write_tls`.
 * On success, store the number of bytes actually written in *out_n
 * (this may be less than `count`).
 * https://docs.rs/rustls/0.19.0/rustls/struct.ClientSession.html#method.write
 */
rustls_result rustls_client_session_write(const rustls_client_session *session,
                                          const uint8_t *buf,
                                          size_t count,
                                          size_t *out_n);

/**
 * Read up to `count` plaintext bytes from the ClientSession into `buf`.
 * On success, store the number of bytes read in *out_n (this may be less
 * than `count`). A success with *out_n set to 0 means "all bytes currently
 * available have been read, but more bytes may become available after
 * subsequent calls to rustls_client_session_read_tls and
 * rustls_client_session_process_new_packets."
 * https://docs.rs/rustls/0.19.0/rustls/struct.ClientSession.html#method.read
 */
rustls_result rustls_client_session_read(const rustls_client_session *session,
                                         uint8_t *buf,
                                         size_t count,
                                         size_t *out_n);

/**
 * Read up to `count` TLS bytes from `buf` (usually read from a socket) into
 * the ClientSession. This may make packets available to
 * `rustls_client_session_process_new_packets`, which in turn may make more
 * bytes available to `rustls_client_session_read`.
 * On success, store the number of bytes actually read in *out_n (this may
 * be less than `count`). This function returns success and stores 0 in
 * *out_n when the input count is 0.
 * https://docs.rs/rustls/0.19.0/rustls/trait.Session.html#tymethod.read_tls
 */
rustls_result rustls_client_session_read_tls(const rustls_client_session *session,
                                             const uint8_t *buf,
                                             size_t count,
                                             size_t *out_n);

/**
 * Write up to `count` TLS bytes from the ClientSession into `buf`. Those
 * bytes should then be written to a socket. On success, store the number of
 * bytes actually written in *out_n (this maybe less than `count`).
 * https://docs.rs/rustls/0.19.0/rustls/trait.Session.html#tymethod.write_tls
 */
rustls_result rustls_client_session_write_tls(const rustls_client_session *session,
                                              uint8_t *buf,
                                              size_t count,
                                              size_t *out_n);

/**
 * After a rustls_client_session method returns an error, you may call
 * this method to get a pointer to a buffer containing a detailed error
 * message. The contents of the error buffer will be out_n bytes long,
 * UTF-8 encoded, and not NUL-terminated.
 */
void rustls_error(rustls_result result, char *buf, size_t len, size_t *out_n);

bool rustls_result_is_cert_error(rustls_result result);

#endif /* CRUSTLS_H */
