#ifndef CLIENT_H
#define CLIENT_H

#include <stdbool.h>

#include "rustls.h"
#include "common.h"

// A structure to hold client demo option state.
typedef struct demo_client_options
{
  // Options for certificate verification. Only one should be set.
  bool use_no_verifier;
  bool use_platform_verifier;
  const char *use_ca_certificate_verifier;

  // Optional client authentication using a certificate/key. None, or both
  // must be set.
  const char *use_auth_cert_file;
  const char *use_auth_cert_key_file;

  // Optional encrypted client hello (ECH) settings. Only one should be set.
  bool use_ech_grease;
  const char *use_ech_config_list_files;

  // Optional SSL keylog support. At most one should be set.
  const char *use_ssl_keylog_file;
  bool use_stderr_keylog;

  // Optional custom ciphersuite name. If set _only_ this ciphersuite
  // will be used.
  const char *custom_ciphersuite_name;

  // Optional vectored IO support.
  bool use_vectored_io;
} demo_client_options;

// Populate the provided options with values from the environment.
// Returns 0 on success, or non-zero on failure after printing error
// messages to stderr.
int options_from_env(demo_client_options *opts);

// Construct a rustls_client_config based on the provided demo_client_options.
//
// Caller owns the returned rustls_client_config and must free it with
// rustls_client_config_free. The rustls_client_config must out-live any
// demo_client_request_options made referencing it.
//
// Returns NULL on failure after printing error messages to stderr.
const rustls_client_config *new_tls_config(const demo_client_options *opts);

// Options for an HTTPS GET request.
typedef struct demo_client_request_options
{
  const rustls_client_config *tls_config;
  const char *hostname;
  const char *port;
  const char *path;
  bool use_vectored_io;
} demo_client_request_options;

// Make an HTTP request based on the provided options. The resulting
// plaintext is printed to STDOUT.
//
// Returns 0 on success, or non-zero on failure after printing error
// messages to stderr.
int do_get_request(const demo_client_request_options *options);

// State related to a demo HTTPS client connection.
typedef struct demo_client_connection
{
  // the options used to create the connection.
  const demo_client_request_options *options;
  // the socket file descriptor for the connection.
  int sockfd;
  // the rustls_connection for TLS.
  rustls_connection *rconn;
  // the connection data for the rustls_connection.
  conndata *data;
  // whether the connection is closing
  bool closing;
  // whether the connection was closed cleanly.
  bool clean_closure;
} demo_client_connection;

// Free a demo_client_connection.
void demo_client_connection_free(demo_client_connection *conn);

// Create a new demo_client_connection by connecting to the server
// specified by the options.
//
// The caller owns the resulting demo_client_connection and must free it
// with demo_client_connection_free. The provided
// options must outlive the connection.
//
// Returns NULL on failure after printing error messages to stderr.
demo_client_connection *demo_client_connect(
  const demo_client_request_options *options);

// Number of attempts to make in connect_socket.
#define MAX_CONNECT_ATTEMPTS 10

// Connect a socket to the hostname/port specified in the
// demo_client_request_options. Tries up to MAX_CONNECT_ATTEMPTS times before
// giving up.
//
// Returns a non-zero FD for the connected socket if successful, or 0 on
// failure after printing error messages to stderr.
int connect_socket(const demo_client_request_options *options);

// Write a GET request to the provided demo_client_connection.
int demo_client_connection_write_get(const demo_client_connection *demo_conn);

// Read TLS data from the provided demo_client_connection's socket, updating
// the rustls connection and putting any available plaintext in the demo
// connection's data.
//
// Returns a demo_result indicating the result of the read.
demo_result demo_client_connection_read_tls(demo_client_connection *demo_conn);

// Write queued TLS data to the provided demo_client_connection's socket.
//
// Returns a demo_result indicating the result of the write.
demo_result demo_client_connection_write_tls(
  const demo_client_connection *demo_conn);

// A callback for rustls certificate validation that *unsafely* allows all
// presented certificate chains, printing their contents to stderr.
uint32_t unsafe_skip_verify(void *userdata,
                            const rustls_verify_server_cert_params *params);

#endif // CLIENT_H
