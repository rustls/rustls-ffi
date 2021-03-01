#ifndef CRUSTLS_H
#define CRUSTLS_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef enum rustls_result {
  RUSTLS_RESULT_OK = 7000,
  RUSTLS_RESULT_IO = 7001,
  RUSTLS_RESULT_NULL_PARAMETER = 7002,
  RUSTLS_RESULT_INVALID_DNS_NAME_ERROR = 7003,
  RUSTLS_RESULT_PANIC = 7004,
  RUSTLS_RESULT_CERTIFICATE_PARSE_ERROR = 7005,
  RUSTLS_RESULT_PRIVATE_KEY_PARSE_ERROR = 7006,
  RUSTLS_RESULT_INSUFFICIENT_SIZE = 7007,
  RUSTLS_RESULT_CORRUPT_MESSAGE = 7100,
  RUSTLS_RESULT_NO_CERTIFICATES_PRESENTED = 7101,
  RUSTLS_RESULT_DECRYPT_ERROR = 7102,
  RUSTLS_RESULT_FAILED_TO_GET_CURRENT_TIME = 7103,
  RUSTLS_RESULT_HANDSHAKE_NOT_COMPLETE = 7104,
  RUSTLS_RESULT_PEER_SENT_OVERSIZED_RECORD = 7105,
  RUSTLS_RESULT_NO_APPLICATION_PROTOCOL = 7106,
  RUSTLS_RESULT_PEER_INCOMPATIBLE_ERROR = 7107,
  RUSTLS_RESULT_PEER_MISBEHAVED_ERROR = 7108,
  RUSTLS_RESULT_INAPPROPRIATE_MESSAGE = 7109,
  RUSTLS_RESULT_INAPPROPRIATE_HANDSHAKE_MESSAGE = 7110,
  RUSTLS_RESULT_CORRUPT_MESSAGE_PAYLOAD = 7111,
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
  RUSTLS_RESULT_CERT_BAD_DER = 7300,
  RUSTLS_RESULT_CERT_BAD_DER_TIME = 7301,
  RUSTLS_RESULT_CERT_CA_USED_AS_END_ENTITY = 7302,
  RUSTLS_RESULT_CERT_EXPIRED = 7303,
  RUSTLS_RESULT_CERT_NOT_VALID_FOR_NAME = 7304,
  RUSTLS_RESULT_CERT_NOT_VALID_YET = 7305,
  RUSTLS_RESULT_CERT_END_ENTITY_USED_AS_CA = 7306,
  RUSTLS_RESULT_CERT_EXTENSION_VALUE_INVALID = 7307,
  RUSTLS_RESULT_CERT_INVALID_CERT_VALIDITY = 7308,
  RUSTLS_RESULT_CERT_INVALID_SIGNATURE_FOR_PUBLIC_KEY = 7309,
  RUSTLS_RESULT_CERT_NAME_CONSTRAINT_VIOLATION = 7310,
  RUSTLS_RESULT_CERT_PATH_LEN_CONSTRAINT_VIOLATED = 7311,
  RUSTLS_RESULT_CERT_SIGNATURE_ALGORITHM_MISMATCH = 7312,
  RUSTLS_RESULT_CERT_REQUIRED_EKU_NOT_FOUND = 7313,
  RUSTLS_RESULT_CERT_UNKNOWN_ISSUER = 7314,
  RUSTLS_RESULT_CERT_UNSUPPORTED_CERT_VERSION = 7315,
  RUSTLS_RESULT_CERT_UNSUPPORTED_CRITICAL_EXTENSION = 7316,
  RUSTLS_RESULT_CERT_UNSUPPORTED_SIGNATURE_ALGORITHM_FOR_PUBLIC_KEY = 7317,
  RUSTLS_RESULT_CERT_UNSUPPORTED_SIGNATURE_ALGORITHM = 7318,
  RUSTLS_RESULT_CERT_SCT_MALFORMED = 7319,
  RUSTLS_RESULT_CERT_SCT_INVALID_SIGNATURE = 7320,
  RUSTLS_RESULT_CERT_SCT_TIMESTAMP_IN_FUTURE = 7321,
  RUSTLS_RESULT_CERT_SCT_UNSUPPORTED_VERSION = 7322,
  RUSTLS_RESULT_CERT_SCT_UNKNOWN_LOG = 7323,
} rustls_result;

/**
 * The complete chain of certificates plus private key for
 * being certified against someones list of trust anchors (commonly
 * called root store). Corresponds to `CertifiedKey` in the Rust API.
 */
typedef struct rustls_cipher_certified_key rustls_cipher_certified_key;

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
 * A server config that is done being constructed and is now read-only.
 * Under the hood, this object corresponds to an Arc<ServerConfig>.
 * https://docs.rs/rustls/0.19.0/rustls/struct.ServerConfig.html
 */
typedef struct rustls_server_config rustls_server_config;

/**
 * A server config being constructed. A builder can be modified by,
 * e.g. rustls_server_config_builder_load_native_roots. Once you're
 * done configuring settings, call rustls_server_config_builder_build
 * to turn it into a *rustls_server_config. This object is not safe
 * for concurrent mutation. Under the hood, it corresponds to a
 * Box<ServerConfig>.
 * https://docs.rs/rustls/0.19.0/rustls/struct.ServerConfig.html
 */
typedef struct rustls_server_config_builder rustls_server_config_builder;

typedef struct rustls_server_session rustls_server_session;

/**
 * A read-only view on a Rust byte slice.
 *
 * This is used to pass data from crustls to callback functions provided
 * by the user of the API.
 * `len` indicates the number of bytes than can be safely read.
 * A `len` of 0 is used to represent a missing value OR an empty slice.
 *
 * The memory exposed is available for the duration of the call (e.g.
 * when passed to a callback) and must be copied if the values are
 * needed for longer.
 */
typedef struct rustls_slice_bytes {
  const uint8_t *data;
  size_t len;
} rustls_slice_bytes;

/**
 * Any context information the callback will receive when invoked.
 */
typedef void *rustls_client_hello_userdata;

/**
 * A read-only view on a Rust utf-8 string slice.
 * This is used to pass data from crustls to callback functions provided
 * by the user of the API. The `data` is not NUL-terminated.
 * `len` indicates the number of bytes than can be safely read.
 * A `len` of 0 is used to represent a missing value OR an empty string.
 *
 * The memory exposed is available for the duration of the call (e.g.
 * when passed to a callback) and must be copied if the values are
 * needed for longer.
 */
typedef struct rustls_str {
  const char *data;
  size_t len;
} rustls_str;

/**
 * A read-only view on a list of Rust owned unsigned short values.
 * This is used to pass data from crustls to callback functions provided
 * by the user of the API. The `data` is an array of `len` 16 bit values.
 *
 * The memory exposed is available for the duration of the call (e.g.
 * when passed to a callback) and must be copied if the values are
 * needed for longer.
 */
typedef struct rustls_vec_ushort {
  const unsigned short *data;
  size_t len;
} rustls_vec_ushort;

/**
 * A read-only view on a vector of Rust byte slices.
 *
 * This is used to pass data from crustls to callback functions provided
 * by the user of the API. The `data` is an array of `rustls_slice_bytes`
 * structures with `len` elements.
 *
 * The memory exposed is available for the duration of the call (e.g.
 * when passed to a callback) and must be copied if the values are
 * needed for longer.
 */
typedef struct rustls_slice_slice_bytes {
  const struct rustls_slice_bytes *data;
  size_t len;
} rustls_slice_slice_bytes;

/**
 * The TLS Client Hello information provided to a ClientHelloCallback function.
 * `sni_name` is the SNI servername provided by the client. If the client
 * did not provide an SNI, the length of this `rustls_string` will be 0.
 * The signature_schemes carries the values supplied by the client or, should
 * the client not use this TLS extension, the default schemes in the rustls
 * library. See:
 * https://docs.rs/rustls/0.19.0/rustls/internal/msgs/enums/enum.SignatureScheme.html
 * `alpn` carries the list of ALPN protocol names that the client proposed to
 * the server. Again, the length of this list will be 0 if non were supplied.
 *
 * All this data, when passed to a callback function, is only accessible during
 * the call and may not be modified. Users of this API must copy any values that
 * they want to access when the callback returned.
 *
 * EXPERIMENTAL: this feature of crustls is likely to change in the future, as
 * the rustls library is re-evaluating their current approach to client hello handling.
 */
typedef struct rustls_client_hello {
  struct rustls_str sni_name;
  struct rustls_vec_ushort signature_schemes;
  struct rustls_slice_slice_bytes alpn;
} rustls_client_hello;

/**
 * Prototype of a callback that can be installed by the application at the
 * `rustls_server_config`. This callback will be invoked by a `rustls_server_session`
 * once the TLS client hello message has been received.
 * `userdata` will be supplied as provided when registering the callback.
 * `hello`gives the value of the available client announcements, as interpreted
 * by rustls. See the definition of `rustls_client_hello` for details.
 *
 * NOTE: the passed in `hello` and all its values are only availabe during the
 * callback invocations.
 *
 * EXPERIMENTAL: this feature of crustls is likely to change in the future, as
 * the rustls library is re-evaluating their current approach to client hello handling.
 */
typedef const struct rustls_cipher_certified_key *(*rustls_client_hello_callback)(rustls_client_hello_userdata userdata, const struct rustls_client_hello *hello);

/**
 * Write the version of the crustls C bindings and rustls itself into the
 * provided buffer, up to a max of `len` bytes. Output is UTF-8 encoded
 * and NUL terminated. Returns the number of bytes written before the NUL.
 */
size_t rustls_version(char *buf, size_t len);

/**
 * Get the name of a SignatureScheme, represented by the `scheme` short value,
 * if known by the rustls library. For unknown schemes, this returns a string
 * with the scheme value in hex notation.
 * Mainly useful for debugging output.
 * The caller provides `buf` for holding the string and gives its size as `len`
 * bytes. On return `out_n` carries the number of bytes copied into `buf`. The
 * `buf` is not NUL-terminated.
 *
 */
void rustls_cipher_get_signature_scheme_name(unsigned short scheme,
                                             char *buf,
                                             size_t len,
                                             size_t *out_n);

enum rustls_result rustls_cipher_certified_key_build(const uint8_t *cert_chain,
                                                     size_t cert_chain_len,
                                                     const uint8_t *private_key,
                                                     size_t private_key_len,
                                                     const struct rustls_cipher_certified_key **certified_key_out);

/**
 * "Free" a certified_key previously returned from
 * rustls_cipher_certified_key_build. Since certified_key is actually an
 * atomically reference-counted pointer, extant certified_key may still
 * hold an internal reference to the Rust object. However, C code must
 * consider this pointer unusable after "free"ing it.
 * Calling with NULL is fine. Must not be called twice with the same value.
 */
void rustls_cipher_certified_key_free(const struct rustls_cipher_certified_key *config);

/**
 * Create a rustls_client_config_builder. Caller owns the memory and must
 * eventually call rustls_client_config_builder_build, then free the
 * resulting rustls_client_config. This starts out with no trusted roots.
 * Caller must add roots with rustls_client_config_builder_load_native_roots
 * or rustls_client_config_builder_load_roots_from_file.
 */
struct rustls_client_config_builder *rustls_client_config_builder_new(void);

/**
 * Turn a *rustls_client_config_builder (mutable) into a *rustls_client_config
 * (read-only).
 */
const struct rustls_client_config *rustls_client_config_builder_build(struct rustls_client_config_builder *builder);

/**
 * Add certificates from platform's native root store, using
 * https://github.com/ctz/rustls-native-certs#readme.
 */
enum rustls_result rustls_client_config_builder_load_native_roots(struct rustls_client_config_builder *config);

/**
 * Add trusted root certificates from the named file, which should contain
 * PEM-formatted certificates.
 */
enum rustls_result rustls_client_config_builder_load_roots_from_file(struct rustls_client_config_builder *config,
                                                                     const char *filename);

/**
 * "Free" a client_config previously returned from
 * rustls_client_config_builder_build. Since client_config is actually an
 * atomically reference-counted pointer, extant client_sessions may still
 * hold an internal reference to the Rust object. However, C code must
 * consider this pointer unusable after "free"ing it.
 * Calling with NULL is fine. Must not be called twice with the same value.
 */
void rustls_client_config_free(const struct rustls_client_config *config);

/**
 * Create a new rustls::ClientSession, and return it in the output parameter `out`.
 * If this returns an error code, the memory pointed to by `session_out` remains unchanged.
 * If this returns a non-error, the memory pointed to by `session_out` is modified to point
 * at a valid ClientSession. The caller now owns the ClientSession and must call
 * `rustls_client_session_free` when done with it.
 */
enum rustls_result rustls_client_session_new(const struct rustls_client_config *config,
                                             const char *hostname,
                                             struct rustls_client_session **session_out);

bool rustls_client_session_wants_read(const struct rustls_client_session *session);

bool rustls_client_session_wants_write(const struct rustls_client_session *session);

bool rustls_client_session_is_handshaking(const struct rustls_client_session *session);

enum rustls_result rustls_client_session_process_new_packets(struct rustls_client_session *session);

/**
 * Queues a close_notify fatal alert to be sent in the next write_tls call.
 * https://docs.rs/rustls/0.19.0/rustls/trait.Session.html#tymethod.send_close_notify
 */
void rustls_client_session_send_close_notify(struct rustls_client_session *session);

/**
 * Free a client_session previously returned from rustls_client_session_new.
 * Calling with NULL is fine. Must not be called twice with the same value.
 */
void rustls_client_session_free(struct rustls_client_session *session);

/**
 * Write up to `count` plaintext bytes from `buf` into the ClientSession.
 * This will increase the number of output bytes available to
 * `rustls_client_session_write_tls`.
 * On success, store the number of bytes actually written in *out_n
 * (this may be less than `count`).
 * https://docs.rs/rustls/0.19.0/rustls/struct.ClientSession.html#method.write
 */
enum rustls_result rustls_client_session_write(struct rustls_client_session *session,
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
enum rustls_result rustls_client_session_read(struct rustls_client_session *session,
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
enum rustls_result rustls_client_session_read_tls(struct rustls_client_session *session,
                                                  const uint8_t *buf,
                                                  size_t count,
                                                  size_t *out_n);

/**
 * Write up to `count` TLS bytes from the ClientSession into `buf`. Those
 * bytes should then be written to a socket. On success, store the number of
 * bytes actually written in *out_n (this maybe less than `count`).
 * https://docs.rs/rustls/0.19.0/rustls/trait.Session.html#tymethod.write_tls
 */
enum rustls_result rustls_client_session_write_tls(struct rustls_client_session *session,
                                                   uint8_t *buf,
                                                   size_t count,
                                                   size_t *out_n);

/**
 * After a rustls_client_session method returns an error, you may call
 * this method to get a pointer to a buffer containing a detailed error
 * message. The contents of the error buffer will be out_n bytes long,
 * UTF-8 encoded, and not NUL-terminated.
 */
void rustls_error(enum rustls_result result, char *buf, size_t len, size_t *out_n);

bool rustls_result_is_cert_error(enum rustls_result result);

/**
 * Create a rustls_server_config_builder. Caller owns the memory and must
 * eventually call rustls_server_config_builder_build, then free the
 * resulting rustls_server_config. This starts out with no trusted roots.
 * Caller must add roots with rustls_server_config_builder_load_native_roots
 * or rustls_server_config_builder_load_roots_from_file.
 * https://docs.rs/rustls/0.19.0/rustls/struct.ServerConfig.html#method.new
 */
struct rustls_server_config_builder *rustls_server_config_builder_new(void);

/**
 * "Free" a server_config_builder before transmogrifying it into a server_config.
 * Normally builders are consumed to server_configs via `rustls_server_config_builder_build`
 * and may not be free'd or otherwise used afterwards.
 * Use free only when the building of a config has to be aborted before a config
 * was created.
 */
void rustls_server_config_builder_free(struct rustls_server_config_builder *config);

/**
 * Create a rustls_server_config_builder from an existing rustls_server_config. The
 * builder will be used to create a new, separate config that starts with the settings
 * from the supplied configuration.
 */
struct rustls_server_config_builder *rustls_server_config_builder_from_config(const struct rustls_server_config *config);

/**
 * With `ignore` != 0, the server will ignore the client ordering of cipher
 * suites, aka preference, during handshake and respect its own ordering
 * as configured.
 * https://docs.rs/rustls/0.19.0/rustls/struct.ServerConfig.html#fields
 */
enum rustls_result rustls_server_config_builder_set_ignore_client_order(struct rustls_server_config_builder *builder,
                                                                        bool ignore);

enum rustls_result rustls_server_config_builder_set_protocols(struct rustls_server_config_builder *builder,
                                                              const struct rustls_slice_bytes *protocols,
                                                              size_t len);

/**
 * Sets a single certificate chain and matching private key.
 * This certificate and key is used for all subsequent connections,
 * irrespective of things like SNI hostname.
 * cert_chain must point to a byte array of length cert_chain_len containing
 * a series of PEM-encoded certificates, with the end-entity certificate
 * first.
 * private_key must point to a byte array of length private_key_len containing
 * a private key in PEM-encoded PKCS#8 or PKCS#1 format.
 *
 * EXPERIMENTAL: installing a client_hello callback will replace any
 * configured certified keys and vice versa. Same holds true for the
 * set_single_cert variant.
 */
enum rustls_result rustls_server_config_builder_set_single_cert_pem(struct rustls_server_config_builder *builder,
                                                                    const uint8_t *cert_chain,
                                                                    size_t cert_chain_len,
                                                                    const uint8_t *private_key,
                                                                    size_t private_key_len);

/**
 * Provide the configuration a list of certificates where the session
 * will select the first one that is compatible with the client's signing
 * capabilities. Servers that want to support ECDSA and RSA certificates
 * will want the ECSDA to go first in the list.
 *
 * The built configuration will keep a reference to all certified keys
 * provided. The client may `rustls_cipher_certified_key_free()` afterwards
 * without the configuration losing them. The same certified key may also
 * be appear in multiple configs.
 *
 * EXPERIMENTAL: installing a client_hello callback will replace any
 * configured certified keys and vice versa. Same holds true for the
 * set_single_cert variant.
 */
enum rustls_result rustls_server_config_builder_set_certified_keys(struct rustls_server_config_builder *builder,
                                                                   const struct rustls_cipher_certified_key *const *certified_keys,
                                                                   size_t certified_keys_len);

/**
 * Turn a *rustls_server_config_builder (mutable) into a *rustls_server_config
 * (read-only).
 */
const struct rustls_server_config *rustls_server_config_builder_build(struct rustls_server_config_builder *builder);

/**
 * "Free" a server_config previously returned from
 * rustls_server_config_builder_build. Since server_config is actually an
 * atomically reference-counted pointer, extant server_sessions may still
 * hold an internal reference to the Rust object. However, C code must
 * consider this pointer unusable after "free"ing it.
 * Calling with NULL is fine. Must not be called twice with the same value.
 */
void rustls_server_config_free(const struct rustls_server_config *config);

/**
 * Create a new rustls::ServerSession, and return it in the output parameter `out`.
 * If this returns an error code, the memory pointed to by `session_out` remains unchanged.
 * If this returns a non-error, the memory pointed to by `session_out` is modified to point
 * at a valid ServerSession. The caller now owns the ServerSession and must call
 * `rustls_server_session_free` when done with it.
 */
enum rustls_result rustls_server_session_new(const struct rustls_server_config *config,
                                             struct rustls_server_session **session_out);

bool rustls_server_session_wants_read(const struct rustls_server_session *session);

bool rustls_server_session_wants_write(const struct rustls_server_session *session);

bool rustls_server_session_is_handshaking(const struct rustls_server_session *session);

enum rustls_result rustls_server_session_process_new_packets(struct rustls_server_session *session);

/**
 * Queues a close_notify fatal alert to be sent in the next write_tls call.
 * https://docs.rs/rustls/0.19.0/rustls/trait.Session.html#tymethod.send_close_notify
 */
void rustls_server_session_send_close_notify(struct rustls_server_session *session);

/**
 * Free a server_session previously returned from rustls_server_session_new.
 * Calling with NULL is fine. Must not be called twice with the same value.
 */
void rustls_server_session_free(struct rustls_server_session *session);

/**
 * Write up to `count` plaintext bytes from `buf` into the ServerSession.
 * This will increase the number of output bytes available to
 * `rustls_server_session_write_tls`.
 * On success, store the number of bytes actually written in *out_n
 * (this may be less than `count`).
 * https://docs.rs/rustls/0.19.0/rustls/struct.ServerSession.html#method.write
 */
enum rustls_result rustls_server_session_write(struct rustls_server_session *session,
                                               const uint8_t *buf,
                                               size_t count,
                                               size_t *out_n);

/**
 * Read up to `count` plaintext bytes from the ServerSession into `buf`.
 * On success, store the number of bytes read in *out_n (this may be less
 * than `count`). A success with *out_n set to 0 means "all bytes currently
 * available have been read, but more bytes may become available after
 * subsequent calls to rustls_server_session_read_tls and
 * rustls_server_session_process_new_packets."
 * https://docs.rs/rustls/0.19.0/rustls/struct.ServerSession.html#method.read
 */
enum rustls_result rustls_server_session_read(struct rustls_server_session *session,
                                              uint8_t *buf,
                                              size_t count,
                                              size_t *out_n);

/**
 * Read up to `count` TLS bytes from `buf` (usually read from a socket) into
 * the ServerSession. This may make packets available to
 * `rustls_server_session_process_new_packets`, which in turn may make more
 * bytes available to `rustls_server_session_read`.
 * On success, store the number of bytes actually read in *out_n (this may
 * be less than `count`). This function returns success and stores 0 in
 * *out_n when the input count is 0.
 * https://docs.rs/rustls/0.19.0/rustls/trait.Session.html#tymethod.read_tls
 */
enum rustls_result rustls_server_session_read_tls(struct rustls_server_session *session,
                                                  const uint8_t *buf,
                                                  size_t count,
                                                  size_t *out_n);

/**
 * Write up to `count` TLS bytes from the ServerSession into `buf`. Those
 * bytes should then be written to a socket. On success, store the number of
 * bytes actually written in *out_n (this maybe less than `count`).
 * https://docs.rs/rustls/0.19.0/rustls/trait.Session.html#tymethod.write_tls
 */
enum rustls_result rustls_server_session_write_tls(struct rustls_server_session *session,
                                                   uint8_t *buf,
                                                   size_t count,
                                                   size_t *out_n);

/**
 * Copy the SNI hostname to `buf` which can hold up  to `count` bytes,
 * and the length of that hostname in `out_n`. The string is stored in UTF-8
 * with no terminating NUL byte.
 * Returns RUSTLS_RESULT_INSUFFICIENT_SIZE if the SNI hostname is longer than `count`.
 * Returns Ok with *out_n == 0 if there is no SNI hostname available on this session
 * because it hasn't been processed yet, or because the client did not send SNI.
 * https://docs.rs/rustls/0.19.0/rustls/struct.ServerSession.html#method.get_sni_hostname
 */
enum rustls_result rustls_server_session_get_sni_hostname(const struct rustls_server_session *session,
                                                          uint8_t *buf,
                                                          size_t count,
                                                          size_t *out_n);

/**
 * Register a callback to be invoked when a session created from this config
 * is seeing a TLS ClientHello message. The given `userdata` will be passed
 * to the callback when invoked.
 * Any existing `ResolvesServerCert` implementation currently installed in the
 * `rustls_server_config` will be replaced. This also means registering twice
 * will overwrite the first registration. It is not permitted to pass a NULL
 * value for `callback`, but it is possible to have `userdata` as NULL.
 *
 * EXPERIMENTAL: this feature of crustls is likely to change in the future, as
 * the rustls library is re-evaluating their current approach to client hello handling.
 * Installing a client_hello callback will replace any configured certified keys
 * and vice versa. Same holds true for the set_single_cert variant.
 */
enum rustls_result rustls_server_config_builder_set_hello_callback(struct rustls_server_config_builder *builder,
                                                                   rustls_client_hello_callback callback,
                                                                   rustls_client_hello_userdata userdata);

#endif /* CRUSTLS_H */
