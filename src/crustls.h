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
  RUSTLS_RESULT_NOT_FOUND = 7008,
  RUSTLS_RESULT_INVALID_PARAMETER = 7009,
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
 * Definitions of known TLS protocol versions.
 */
typedef enum rustls_tls_version {
  RUSTLS_TLS_VERSION_SSLV2 = 512,
  RUSTLS_TLS_VERSION_SSSLV3 = 768,
  RUSTLS_TLS_VERSION_TLSV1_0 = 769,
  RUSTLS_TLS_VERSION_TLSV1_1 = 770,
  RUSTLS_TLS_VERSION_TLSV1_2 = 771,
  RUSTLS_TLS_VERSION_TLSV1_3 = 772,
} rustls_tls_version;

/**
 * The complete chain of certificates to send during a TLS handshake,
 * plus a private key that matches the end-entity (leaf) certificate.
 * Corresponds to `CertifiedKey` in the Rust API.
 * https://docs.rs/rustls/0.19.0/rustls/sign/struct.CertifiedKey.html
 */
typedef struct rustls_certified_key rustls_certified_key;

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
 * Currently just a placeholder with no accessors yet.
 * https://docs.rs/rustls/0.19.0/rustls/struct.RootCertStore.html
 */
typedef struct rustls_root_cert_store rustls_root_cert_store;

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
 * A read-only view of a slice of Rust byte slices.
 *
 * This is used to pass data from crustls to callback functions provided
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
 * strings). Like `rustls_str`, this guarantees that each string contains
 * UTF-8 and no NUL bytes. Strings are not NUL-terminated.
 *
 * This is used to pass data from crustls to callback functions provided
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
 * User-provided input to a custom certificate verifier callback. See
 * rustls_client_config_builder_dangerous_set_certificate_verifier().
 */
typedef void *rustls_verify_server_cert_user_data;

/**
 * A read-only view on a Rust byte slice.
 *
 * This is used to pass data from crustls to callback functions provided
 * by the user of the API.
 * `len` indicates the number of bytes than can be safely read.
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
 * A read-only view on a Rust `&str`. The contents are guaranteed to be valid
 * UTF-8. As an additional guarantee on top of Rust's normal UTF-8 guarantee,
 * a `rustls_str` is guaranteed not to contain internal NUL bytes, so it is
 * safe to interpolate into a C string or compare using strncmp. Keep in mind
 * that it is not NUL-terminated.
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
 * Input to a custom certificate verifier callback. See
 * rustls_client_config_builder_dangerous_set_certificate_verifier().
 */
typedef struct rustls_verify_server_cert_params {
  struct rustls_slice_bytes end_entity_cert_der;
  const struct rustls_slice_slice_bytes *intermediate_certs_der;
  const struct rustls_root_cert_store *roots;
  struct rustls_str dns_name;
  struct rustls_slice_bytes ocsp_response;
} rustls_verify_server_cert_params;

typedef enum rustls_result (*rustls_verify_server_cert_callback)(rustls_verify_server_cert_user_data userdata, const struct rustls_verify_server_cert_params *params);

/**
 * Any context information the callback will receive when invoked.
 */
typedef void *rustls_session_store_userdata;

/**
 * Prototype of a callback that can be installed by the application at the
 * `rustls_server_config` or `rustls_client_config`. This callback will be
 * invoked by a TLS session when looking up the data for a TLS session id.
 * `userdata` will be supplied as provided when registering the callback.
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
 * The callback should return != 0 to indicate that a value was retrieved
 * and written in its entirety into `buf`.
 *
 * When `remove_after` is != 0, the returned data needs to be removed
 * from the store.
 *
 * NOTE: the passed in `key` and `buf` are only available during the
 * callback invocation.
 * NOTE: callbacks used in several sessions via a common config
 * must be implemented thread-safe.
 */
typedef enum rustls_result (*rustls_session_store_get_callback)(rustls_session_store_userdata userdata, const struct rustls_slice_bytes *key, int remove_after, uint8_t *buf, size_t count, size_t *out_n);

/**
 * Prototype of a callback that can be installed by the application at the
 * `rustls_server_config` or `rustls_client_config`. This callback will be
 * invoked by a TLS session when a TLS session has been created and an id
 * for later use is handed to the client/has been received from the server.
 * `userdata` will be supplied as provided when registering the callback.
 *
 * The callback should return != 0 to indicate that the value has been
 * successfully persisted in its store.
 *
 * NOTE: the passed in `key` and `val` are only available during the
 * callback invocation.
 * NOTE: callbacks used in several sessions via a common config
 * must be implemented thread-safe.
 */
typedef enum rustls_result (*rustls_session_store_put_callback)(rustls_session_store_userdata userdata, const struct rustls_slice_bytes *key, const struct rustls_slice_bytes *val);

/**
 * Any context information the callback will receive when invoked.
 */
typedef void *rustls_client_hello_userdata;

/**
 * A read-only view on a Rust slice of 16-bit integers in platform endianness.
 *
 * This is used to pass data from crustls to callback functions provided
 * by the user of the API.
 * `len` indicates the number of bytes than can be safely read.
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
 * The TLS Client Hello information provided to a ClientHelloCallback function.
 * `sni_name` is the SNI servername provided by the client. If the client
 * did not provide an SNI, the length of this `rustls_string` will be 0.
 * The signature_schemes carries the values supplied by the client or, should
 * the client not use this TLS extension, the default schemes in the rustls
 * library. See:
 * https://docs.rs/rustls/0.19.0/rustls/internal/msgs/enums/enum.SignatureScheme.html
 * `alpn` carries the list of ALPN protocol names that the client proposed to
 * the server. Again, the length of this list will be 0 if none were supplied.
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
  struct rustls_slice_u16 signature_schemes;
  const struct rustls_slice_slice_bytes *alpn;
} rustls_client_hello;

/**
 * Prototype of a callback that can be installed by the application at the
 * `rustls_server_config`. This callback will be invoked by a `rustls_server_session`
 * once the TLS client hello message has been received.
 * `userdata` will be supplied as provided when registering the callback.
 * `hello` gives the value of the available client announcements, as interpreted
 * by rustls. See the definition of `rustls_client_hello` for details.
 *
 * NOTE:
 * - the passed in `hello` and all its values are only available during the
 *   callback invocations.
 * - the passed callback function must be implemented thread-safe, unless
 *   there is only a single config and session where it is installed.
 * - `userdata` must live as long as the config object and any sessions
 *   or other config created from that config object.
 *
 * EXPERIMENTAL: this feature of crustls is likely to change in the future, as
 * the rustls library is re-evaluating their current approach to client hello handling.
 */
typedef const struct rustls_certified_key *(*rustls_client_hello_callback)(rustls_client_hello_userdata userdata, const struct rustls_client_hello *hello);

/**
 * Write the version of the crustls C bindings and rustls itself into the
 * provided buffer, up to a max of `len` bytes. Output is UTF-8 encoded
 * and NUL terminated. Returns the number of bytes written before the NUL.
 */
size_t rustls_version(char *buf, size_t len);

/**
 * Build a `rustls_certified_key` from a certificate chain and a private key.
 * `cert_chain` must point to a buffer of `cert_chain_len` bytes, containing
 * a series of PEM-encoded certificates, with the end-entity (leaf)
 * certificate first.
 *
 * `private_key` must point to a buffer of `private_key_len` bytes, containing
 * a PEM-encoded private key in either PKCS#1 or PKCS#8 format.
 *
 * On success, this writes a pointer to the newly created
 * `rustls_certified_key` in `certified_key_out`. That pointer must later
 * be freed with `rustls_certified_key_free` to avoid memory leaks. Note that
 * internally, this is an atomically reference-counted pointer, so even after
 * the original caller has called `rustls_certified_key_free`, other objects
 * may retain a pointer to the object. The memory will be freed when all
 * references are gone.
 */
enum rustls_result rustls_certified_key_build(const uint8_t *cert_chain,
                                              size_t cert_chain_len,
                                              const uint8_t *private_key,
                                              size_t private_key_len,
                                              const struct rustls_certified_key **certified_key_out);

/**
 * "Free" a certified_key previously returned from
 * rustls_certified_key_build. Since certified_key is actually an
 * atomically reference-counted pointer, extant certified_key may still
 * hold an internal reference to the Rust object. However, C code must
 * consider this pointer unusable after "free"ing it.
 * Calling with NULL is fine. Must not be called twice with the same value.
 */
void rustls_certified_key_free(const struct rustls_certified_key *key);

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
 * Set a custom server certificate verifier.
 *
 * The userdata pointer must stay valid until (a) all sessions created with this
 * config have been freed, and (b) the config itself has been freed.
 * The callback must not capture any of the pointers in its
 * rustls_verify_server_cert_params.
 *
 * The callback must be safe to call on any thread at any time, including
 * multiple concurrent calls. So, for instance, if the callback mutates
 * userdata (or other shared state), it must use synchronization primitives
 * to make such mutation safe.
 *
 * The callback receives certificate chain information as raw bytes.
 * Currently this library offers no functions for C code to parse the
 * certificates, so you'll need to bring your own certificate parsing library
 * if you need to parse them.
 *
 * If you intend to write a verifier that accepts all certificates, be aware
 * that special measures are required for IP addresses. Rustls currently
 * (0.19.0) doesn't support building a ClientSession with an IP address
 * (because it's not a valid DNSNameRef). One workaround is to detect IP
 * addresses and rewrite them to `example.invalid`, and _also_ to disable
 * SNI via rustls_client_config_builder_set_enable_sni (IP addresses don't
 * need SNI).
 *
 * If the custom verifier accepts the certificate, it should return
 * RUSTLS_RESULT_OK. Otherwise, it may return any other rustls_result error.
 * Feel free to use an appropriate error from the RUSTLS_RESULT_CERT_*
 * section.
 *
 * https://docs.rs/rustls/0.19.0/rustls/struct.DangerousClientConfig.html#method.set_certificate_verifier
 */
void rustls_client_config_builder_dangerous_set_certificate_verifier(struct rustls_client_config_builder *config,
                                                                     rustls_verify_server_cert_callback callback,
                                                                     rustls_verify_server_cert_user_data userdata);

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
 * Enable or disable SNI.
 * https://docs.rs/rustls/0.19.0/rustls/struct.ClientConfig.html#structfield.enable_sni
 */
void rustls_client_config_builder_set_enable_sni(struct rustls_client_config_builder *config,
                                                 bool enable);

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
 *
 * Subtle note: Even though this function only writes to `buf` and does not
 * read from it, the memory in `buf` must be initialized before the call (for
 * Rust-internal reasons). Initializing a buffer once and then using it
 * multiple times without zeroizing before each call is fine.
 *
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
 *
 * Subtle note: Even though this function only writes to `buf` and does not
 * read from it, the memory in `buf` must be initialized before the call (for
 * Rust-internal reasons). Initializing a buffer once and then using it
 * multiple times without zeroizing before each call is fine.
 *
 * https://docs.rs/rustls/0.19.0/rustls/trait.Session.html#tymethod.write_tls
 */
enum rustls_result rustls_client_session_write_tls(struct rustls_client_session *session,
                                                   uint8_t *buf,
                                                   size_t count,
                                                   size_t *out_n);

/**
 * Register callbacks for persistence of TLS session data. This means either
 * session IDs (TLSv1.2) or . Both
 * keys and values are highly sensitive data, containing enough information
 * to break the security of the sessions involved.
 *
 * `userdata` must live as long as the config object and any sessions
 * or other config created from that config object.
 *
 */
enum rustls_result rustls_client_config_builder_set_persistence(struct rustls_client_config_builder *builder,
                                                                rustls_session_store_userdata userdata,
                                                                rustls_session_store_get_callback get_cb,
                                                                rustls_session_store_put_callback put_cb);

/**
 * After a rustls_client_session method returns an error, you may call
 * this method to get a pointer to a buffer containing a detailed error
 * message. The contents of the error buffer will be out_n bytes long,
 * UTF-8 encoded, and not NUL-terminated.
 */
void rustls_error(enum rustls_result result, char *buf, size_t len, size_t *out_n);

bool rustls_result_is_cert_error(enum rustls_result result);

/**
 * Return the length of the outer slice. If the input pointer is NULL,
 * returns 0.
 */
size_t rustls_slice_slice_bytes_len(const struct rustls_slice_slice_bytes *input);

/**
 * Retrieve the nth element from the input slice of slices. If the input
 * pointer is NULL, or n is greater than the length of the
 * rustls_slice_slice_bytes, returns rustls_slice_bytes{NULL, 0}.
 */
struct rustls_slice_bytes rustls_slice_slice_bytes_get(const struct rustls_slice_slice_bytes *input,
                                                       size_t n);

/**
 * Return the length of the outer slice. If the input pointer is NULL,
 * returns 0.
 */
size_t rustls_slice_str_len(const struct rustls_slice_str *input);

/**
 * Retrieve the nth element from the input slice of `&str`s. If the input
 * pointer is NULL, or n is greater than the length of the
 * rustls_slice_str, returns rustls_str{NULL, 0}.
 */
struct rustls_str rustls_slice_str_get(const struct rustls_slice_str *input, size_t n);

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
 * Set the TLS protocol versions to use when negotiating a TLS session.
 *
 * `tls_version` is the version of the protocol, as defined in rfc8446,
 * ch. 4.2.1 and end of ch. 5.1. Some values are defined in
 * `rustls_tls_version` for convenience.
 *
 * `versions` will only be used during the call and the application retains
 * ownership. `len` is the number of consecutive `ui16` pointed to by `versions`.
 */
enum rustls_result rustls_server_config_builder_set_versions(struct rustls_server_config_builder *builder,
                                                             const uint16_t *tls_versions,
                                                             size_t len);

/**
 * With `ignore` != 0, the server will ignore the client ordering of cipher
 * suites, aka preference, during handshake and respect its own ordering
 * as configured.
 * https://docs.rs/rustls/0.19.0/rustls/struct.ServerConfig.html#fields
 */
enum rustls_result rustls_server_config_builder_set_ignore_client_order(struct rustls_server_config_builder *builder,
                                                                        bool ignore);

/**
 * Set the ALPN protocol list to the given protocols. `protocols` must point
 * to a buffer of `rustls_slice_bytes` (built by the caller) with `len`
 * elements. Each element of the buffer must point to a slice of bytes that
 * contains a single ALPN protocol from
 * https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids.
 *
 * This function makes a copy of the data in `protocols` and does not retain
 * any pointers, so the caller can free the pointed-to memory after calling.
 *
 * https://docs.rs/rustls/0.19.0/rustls/struct.ServerConfig.html#method.set_protocols
 */
enum rustls_result rustls_server_config_builder_set_protocols(struct rustls_server_config_builder *builder,
                                                              const struct rustls_slice_bytes *protocols,
                                                              size_t len);

/**
 * Provide the configuration a list of certificates where the session
 * will select the first one that is compatible with the client's signature
 * verification capabilities. Servers that want to support both ECDSA and
 * RSA certificates will want the ECSDA to go first in the list.
 *
 * The built configuration will keep a reference to all certified keys
 * provided. The client may `rustls_certified_key_free()` afterwards
 * without the configuration losing them. The same certified key may also
 * be used in multiple configs.
 *
 * EXPERIMENTAL: installing a client_hello callback will replace any
 * configured certified keys and vice versa. Same holds true for the
 * set_single_cert variant.
 */
enum rustls_result rustls_server_config_builder_set_certified_keys(struct rustls_server_config_builder *builder,
                                                                   const struct rustls_certified_key *const *certified_keys,
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

/**
 * Return the TLS protocol version that has been negotiated. Before this
 * has been decided during the handshake, this will return 0. Otherwise,
 * the u16 version number as defined in the relevant RFC is returned.
 */
uint16_t rustls_server_session_get_protocol_version(const struct rustls_server_session *session);

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
 *
 * Subtle note: Even though this function only writes to `buf` and does not
 * read from it, the memory in `buf` must be initialized before the call (for
 * Rust-internal reasons). Initializing a buffer once and then using it
 * multiple times without zeroizing before each call is fine.
 *
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
 *
 * Subtle note: Even though this function only writes to `buf` and does not
 * read from it, the memory in `buf` must be initialized before the call (for
 * Rust-internal reasons). Initializing a buffer once and then using it
 * multiple times without zeroizing before each call is fine.
 *
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
 *
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

/**
 * Register callbacks for persistence of TLS session IDs and secrets. Both
 * keys and values are highly sensitive data, containing enough information
 * to break the security of the sessions involved.
 *
 * `userdata` must live as long as the config object and any sessions
 * or other config created from that config object.
 */
enum rustls_result rustls_server_config_builder_set_persistence(struct rustls_server_config_builder *builder,
                                                                rustls_session_store_userdata userdata,
                                                                rustls_session_store_get_callback get_cb,
                                                                rustls_session_store_put_callback put_cb);

#endif /* CRUSTLS_H */
