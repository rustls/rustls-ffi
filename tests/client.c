/*
 * A simple demonstration client for rustls-ffi.
 *
 * This client connects to an HTTPS server, sends an HTTP GET request, and
 * prints the response to stdout.
 *
 * Notably it _does not_ attempt to implement the semantics of HTTP 1.1 by
 * parsing the response and processing content-length or chunked encoding.
 */
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h> /* gai_strerror() */
#include <io.h> /* write() */
#include <fcntl.h> /* O_BINARY */
#else
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#endif

#include <sys/types.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "rustls.h"
#include "common.h"
#include "client.h"

int
main(const int argc, const char **argv)
{
#ifdef _WIN32
  WSADATA wsa;
  WSAStartup(MAKEWORD(1, 1), &wsa);
  setmode(STDOUT_FILENO, O_BINARY);
#endif
  const rustls_client_config *tls_config = NULL;

  // Set the program name global variable for logging purposes.
  programname = "client";

  // Process command line arguments.
  int ret = 1;
  if(argc <= 3) {
    fprintf(
      stderr,
      "usage: %s hostname port path [numreqs]\n\n"
      "Connect to a host via HTTPS on the provided port, make [numreqs] \n"
      "requests for the given path, and emit each response to stdout.\n",
      argv[0]);
    goto cleanup;
  }
  const char *hostname = argv[1];
  const char *port = argv[2];
  const char *path = argv[3];
  const char *numreqs = argc > 4 ? argv[4] : "3";

  char *end;
  const long int numreqs_int = strtol(numreqs, &end, 10);
  if(end == numreqs || *end != '\0') {
    fprintf(stderr, "numreqs must be a positive integer\n");
    goto cleanup;
  }
  if(numreqs_int <= 0) {
    fprintf(stderr, "numreqs must be a positive integer\n");
    goto cleanup;
  }

  // Build a demo client options struct based on the environment.
  demo_client_options opts = { 0 };
  if(options_from_env(&opts)) {
    goto cleanup;
  }

  // Build a rustls TLS client config with our client options.
  tls_config = new_tls_config(&opts);
  if(tls_config == NULL) {
    goto cleanup;
  }

  // Describe the connection we're about to make.
  const demo_client_request_options req_opts = {
    .tls_config = tls_config,
    .hostname = hostname,
    .port = port,
    .path = path,
    .use_vectored_io = opts.use_vectored_io,
  };

  // Make GET requests with the rustls client config.
  for(int i = 0; i < numreqs_int; i++) {
    LOG("request %d of %ld", i + 1, numreqs_int);

    if(do_get_request(&req_opts)) {
      LOG("request %d of %ld FAILED", i + 1, numreqs_int);
      goto cleanup;
    }

    LOG("request %d of %ld successful", i + 1, numreqs_int);
  }
  ret = 0; // Success.

cleanup:
  // Free the rustls TLS config.
  rustls_client_config_free(tls_config);

#ifdef _WIN32
  WSACleanup();
#endif

  return ret;
}

int
options_from_env(demo_client_options *opts)
{
  // Consider verifier options.
  const char *use_platform_verifier = getenv("RUSTLS_PLATFORM_VERIFIER");
  const char *use_ca_certificate_verifier = getenv("CA_FILE");
  const char *use_no_verifier = getenv("NO_CHECK_CERTIFICATE");

  if(use_platform_verifier) {
    LOG_SIMPLE("using the platform verifier for certificate verification.");
    opts->use_platform_verifier = true;
  }
  else if(use_ca_certificate_verifier) {
    LOG("using the CA file '%s' for certificate verification.",
        use_ca_certificate_verifier);
    opts->use_ca_certificate_verifier = use_ca_certificate_verifier;
  }
  else if(use_no_verifier) {
    LOG_SIMPLE("skipping certificate verification (DANGER!).");
    opts->use_no_verifier = true;
  }
  else {
    LOG_SIMPLE("must set RUSTLS_PLATFORM_VERIFIER, CA_FILE or "
               "NO_CHECK_CERTIFICATE env var");
    return 1;
  }

  // Consider client auth options.
  const char *auth_cert = getenv("AUTH_CERT");
  const char *auth_key = getenv("AUTH_KEY");
  if(auth_cert && auth_key) {
    LOG("using client auth with cert '%s' and key '%s'", auth_cert, auth_key);
    opts->use_auth_cert_file = auth_cert;
    opts->use_auth_cert_key_file = auth_key;
  }
  else if(auth_cert || auth_key) {
    LOG_SIMPLE("must set both or neither of AUTH_CERT and AUTH_KEY env vars");
    return 1;
  }

  // Consider ECH options.
  const char *ech_grease = getenv("ECH_GREASE");
  const char *ech_config_lists = getenv("ECH_CONFIG_LIST");
  if(ech_grease && ech_config_lists) {
    LOG_SIMPLE(
      "must set at most one of ECH_GREASE or ECH_CONFIG_LIST env vars");
    return 1;
  }
  else if(ech_grease) {
    LOG_SIMPLE("using ECH grease");
    opts->use_ech_grease = true;
  }
  else if(ech_config_lists) {
    LOG("using ECH config lists '%s'", ech_config_lists);
    opts->use_ech_config_list_files = ech_config_lists;
  }

  // Consider SSLKEYLOGFILE options.
  const char *sslkeylogfile = getenv("SSLKEYLOGFILE");
  const char *stderrkeylog = getenv("STDERRKEYLOG");
  if(sslkeylogfile && stderrkeylog) {
    LOG_SIMPLE(
      "must set at most one of SSLKEYLOGFILE or STDERRKEYLOG env vars");
    return 1;
  }
  if(sslkeylogfile) {
    opts->use_ssl_keylog_file = sslkeylogfile;
    LOG("using SSLKEYLOGFILE '%s'", opts->use_ssl_keylog_file);
  }
  else if(stderrkeylog) {
    opts->use_stderr_keylog = true;
    LOG_SIMPLE("using stderr for keylog output");
  }

  // Consider custom ciphersuite name option.
  const char *custom_ciphersuite_name = getenv("RUSTLS_CIPHERSUITE");
  if(custom_ciphersuite_name) {
    opts->custom_ciphersuite_name = custom_ciphersuite_name;
    LOG("using custom ciphersuite '%s'", opts->custom_ciphersuite_name);
  }

  // Consider vectored I/O (if supported)
#if !defined(_WIN32)
  if(getenv("USE_VECTORED_IO")) {
    LOG_SIMPLE("using vectored I/O");
    opts->use_vectored_io = true;
  }
#endif

  return 0;
}

const rustls_client_config *
new_tls_config(const demo_client_options *opts)
{
  const rustls_client_config *result = NULL;
  if(opts == NULL) {
    return result;
  }

  // Initialize things we may need to clean up.
  const rustls_crypto_provider *custom_provider = NULL;
  rustls_client_config_builder *config_builder = NULL;
  rustls_web_pki_server_cert_verifier_builder *server_cert_verifier_builder =
    NULL;
  rustls_server_cert_verifier *server_cert_verifier = NULL;
  rustls_root_cert_store_builder *server_cert_root_store_builder = NULL;
  const rustls_root_cert_store *server_cert_root_store = NULL;

  // First, construct the client config builder. If the user has requested
  // a custom ciphersuite, we first build a custom crypto provider that
  // has only that suite, and then build the config builder with that.
  if(opts->custom_ciphersuite_name != NULL) {
    custom_provider =
      default_provider_with_custom_ciphersuite(opts->custom_ciphersuite_name);
    if(custom_provider == NULL) {
      goto cleanup;
    }
    LOG("customized to use ciphersuite: %s", opts->custom_ciphersuite_name);

    const rustls_result rr =
      rustls_client_config_builder_new_custom(custom_provider,
                                              default_tls_versions,
                                              default_tls_versions_len,
                                              &config_builder);
    if(rr != RUSTLS_RESULT_OK) {
      print_error("creating custom client config builder", rr);
      goto cleanup;
    }
  }
  else {
    config_builder = rustls_client_config_builder_new();
  }

  // Then configure a verifier for the client config builder.
  if(opts->use_platform_verifier) {
    const rustls_result rr =
      rustls_platform_server_cert_verifier(&server_cert_verifier);
    if(rr != RUSTLS_RESULT_OK) {
      print_error("failed to construct platform verifier", rr);
      goto cleanup;
    }
    rustls_client_config_builder_set_server_verifier(config_builder,
                                                     server_cert_verifier);
  }
  else if(opts->use_ca_certificate_verifier != NULL) {
    server_cert_root_store_builder = rustls_root_cert_store_builder_new();
    rustls_result rr = rustls_root_cert_store_builder_load_roots_from_file(
      server_cert_root_store_builder, opts->use_ca_certificate_verifier, true);
    if(rr != RUSTLS_RESULT_OK) {
      print_error("loading trusted certificates", rr);
      goto cleanup;
    }
    rr = rustls_root_cert_store_builder_build(server_cert_root_store_builder,
                                              &server_cert_root_store);
    if(rr != RUSTLS_RESULT_OK) {
      goto cleanup;
    }
    server_cert_verifier_builder =
      rustls_web_pki_server_cert_verifier_builder_new(server_cert_root_store);

    rr = rustls_web_pki_server_cert_verifier_builder_build(
      server_cert_verifier_builder, &server_cert_verifier);
    if(rr != RUSTLS_RESULT_OK) {
      goto cleanup;
    }
    rustls_client_config_builder_set_server_verifier(config_builder,
                                                     server_cert_verifier);
  }
  else if(opts->use_no_verifier) {
    rustls_client_config_builder_dangerous_set_certificate_verifier(
      config_builder, unsafe_skip_verify);
  }

  // Then configure ECH if required.
  if(opts->use_ech_grease) {
    const rustls_hpke *hpke = rustls_supported_hpke();
    if(hpke == NULL) {
      LOG_SIMPLE("client: no HPKE suites for ECH available");
      goto cleanup;
    }
    const rustls_result rr =
      rustls_client_config_builder_enable_ech_grease(config_builder, hpke);
    if(rr != RUSTLS_RESULT_OK) {
      print_error("enabling ECH GREASE", rr);
      goto cleanup;
    }
  }
  else if(opts->use_ech_config_list_files) {
    const rustls_hpke *hpke = rustls_supported_hpke();
    if(hpke == NULL) {
      LOG_SIMPLE("client: no HPKE suites for ECH available");
      goto cleanup;
    }

    // Duplicate the config lists var value - calling STRTOK_R will modify the
    // string to add null terminators between tokens.
    char *ech_config_list_copy = strdup(opts->use_ech_config_list_files);
    if(!ech_config_list_copy) {
      LOG_SIMPLE("failed to allocate memory for ECH config list");
      goto cleanup;
    }

    bool ech_configured = false;
    // Tokenize the ech_config_list_copy by comma. The first invocation takes
    // ech_config_list_copy. This is reentrant by virtue of saving state to
    // saveptr. Only the _first_ invocation is given the original string.
    // Subsequent calls should pass NULL and the same delim/saveptr.
    const char *delim = ",";
    char *saveptr = NULL;
    char *ech_config_list_path =
      STRTOK_R(ech_config_list_copy, delim, &saveptr);

    while(ech_config_list_path) {
      // Skip leading spaces
      while(*ech_config_list_path == ' ') {
        ech_config_list_path++;
      }

      // Try to read the token as a file path to an ECH config list.
      char ech_config_list_buf[10000];
      size_t ech_config_list_len;
      const enum demo_result read_result =
        read_file(ech_config_list_path,
                  ech_config_list_buf,
                  sizeof(ech_config_list_buf),
                  &ech_config_list_len);

      // If we can't read the file, warn and continue
      if(read_result != DEMO_OK) {
        // Continue to the next token.
        LOG("unable to read ECH config list from '%s'", ech_config_list_path);
        ech_config_list_path = STRTOK_R(NULL, delim, &saveptr);
        continue;
      }

      // Try to enable ECH with the config list. This may error if none
      // of the ECH configs are valid/compatible.
      const rustls_result rr =
        rustls_client_config_builder_enable_ech(config_builder,
                                                (uint8_t *)ech_config_list_buf,
                                                ech_config_list_len,
                                                hpke);

      // If we successfully configured ECH with the config list then break.
      if(rr == RUSTLS_RESULT_OK) {
        LOG("using ECH with config list from '%s'", ech_config_list_path);
        ech_configured = true;
        break;
      }

      // Otherwise continue to the next token.
      LOG("no compatible/valid ECH configs found in '%s'",
          ech_config_list_path);
      ech_config_list_path = STRTOK_R(NULL, delim, &saveptr);
    }

    // Free the copy of the env var we made.
    free(ech_config_list_copy);

    if(!ech_configured) {
      LOG_SIMPLE("failed to configure ECH with any provided config files");
      goto cleanup;
    }
  }

  // Then configure client authentication if required.
  if(opts->use_auth_cert_file != NULL &&
     opts->use_auth_cert_key_file != NULL) {
    const rustls_certified_key *certified_key = load_cert_and_key(
      opts->use_auth_cert_file, opts->use_auth_cert_key_file);
    if(certified_key == NULL) {
      goto cleanup;
    }
    rustls_client_config_builder_set_certified_key(
      config_builder, &certified_key, 1);
    // Per docs we are allowed to free the certified key after giving it to the
    // builder.
    rustls_certified_key_free(certified_key);
  }

  // Then configure SSLKEYLOG as required
  if(opts->use_ssl_keylog_file != NULL) {
    const rustls_result rr =
      rustls_client_config_builder_set_key_log_file(config_builder);
    if(rr != RUSTLS_RESULT_OK) {
      print_error("enabling keylog", rr);
      goto cleanup;
    }
  }
  else if(opts->use_stderr_keylog) {
    const rustls_result rr = rustls_client_config_builder_set_key_log(
      config_builder, stderr_key_log_cb, NULL);
    if(rr != RUSTLS_RESULT_OK) {
      print_error("enabling keylog", rr);
      goto cleanup;
    }
  }

  // Then configure ALPN.
  rustls_slice_bytes alpn_http11 = { .data = (unsigned char *)"http/1.1",
                                     .len = 8 };
  rustls_result rr = rustls_client_config_builder_set_alpn_protocols(
    config_builder, &alpn_http11, 1);
  if(rr != RUSTLS_RESULT_OK) {
    print_error("setting ALPN", rr);
    goto cleanup;
  }

  // Finally consume the config_builder by trying to build it into a client
  // config. We can't use the config_builder (even to free it!) after this
  // point.
  rr = rustls_client_config_builder_build(config_builder, &result);
  config_builder = NULL;
  if(rr != RUSTLS_RESULT_OK) {
    print_error("building client config builder", rr);
    goto cleanup;
  }

cleanup:
  rustls_root_cert_store_builder_free(server_cert_root_store_builder);
  rustls_root_cert_store_free(server_cert_root_store);
  rustls_web_pki_server_cert_verifier_builder_free(
    server_cert_verifier_builder);
  rustls_server_cert_verifier_free(server_cert_verifier);
  rustls_crypto_provider_free(custom_provider);
  rustls_client_config_builder_free(config_builder);
  return result;
}

int
do_get_request(const demo_client_request_options *options)
{
  if(options == NULL || options->tls_config == NULL ||
     options->hostname == NULL || options->port == NULL ||
     options->path == NULL) {
    return 1;
  }

  int ret = 1;
  LOG("making GET request to https://%s:%s%s",
      options->hostname,
      options->port,
      options->path);

  // Construct a new connection to the server.
  demo_client_connection *demo_conn = demo_client_connect(options);

  // Write a plaintext HTTP GET request.
  if(demo_client_connection_write_get(demo_conn)) {
    goto cleanup;
  }

  // Process I/O with select().
  struct timeval timeout;
  timeout.tv_sec = 4; // Picked arbitrarily.
  timeout.tv_usec = 0;
  fd_set read_fds;
  fd_set write_fds;
  for(;;) {
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);

    if(rustls_connection_wants_read(demo_conn->rconn)) {
      FD_SET(demo_conn->sockfd, &read_fds);
    }
    if(rustls_connection_wants_write(demo_conn->rconn)) {
      FD_SET(demo_conn->sockfd, &write_fds);
    }

    if(!rustls_connection_wants_read(demo_conn->rconn) &&
       !rustls_connection_wants_write(demo_conn->rconn)) {
      LOG_SIMPLE("rustls wants neither read nor write. Breaking i/o loop.");
      break;
    }

    const int select_result =
      select(demo_conn->sockfd + 1, &read_fds, &write_fds, NULL, &timeout);
    if(select_result == -1) {
      perror("client: select");
      goto cleanup;
    }
    else if(select_result == 0) {
      LOG_SIMPLE("select timed out");
      break;
    }

    // If we can read data from the socket, read it and pass it to rustls.
    if(FD_ISSET(demo_conn->sockfd, &read_fds)) {
      LOG_SIMPLE("doing TLS reads");
      const demo_result dr = demo_client_connection_read_tls(demo_conn);
      if(dr == DEMO_ERROR || dr == DEMO_EOF) {
        demo_conn->closing = true;
      }
      if(dr == DEMO_AGAIN) {
        LOG_SIMPLE("reading from socket: EAGAIN or EWOULDBLOCK");
        continue;
      }
    }

    // If we can write data to the socket, write whatever rustls has queued.
    if(FD_ISSET(demo_conn->sockfd, &write_fds)) {
      LOG_SIMPLE("doing TLS writes");
      const demo_result dr = demo_client_connection_write_tls(demo_conn);
      if(dr == DEMO_ERROR) {
        demo_conn->closing = true;
      }
      if(dr == DEMO_AGAIN) {
        LOG_SIMPLE("writing to socket: EAGAIN or EWOULDBLOCK");
        continue;
      }
    }

    // Handle closure.
    if(demo_conn->closing) {
      LOG("Connection closed. Clean? %s",
          demo_conn->clean_closure ? "yes" : "no");
      // fail result if it wasn't a clean closure.
      ret = !demo_conn->clean_closure;
      break;
    }
  }
  LOG_SIMPLE("I/O loop fell through");
  log_connection_info(demo_conn->rconn);

  // Print whatever is in the user data buffer.
  // TODO(@cpu): refactor conndata struct to avoid "data data data" naming
  //  when digging in to the conndata's bytevec's data.
  const char *data = demo_conn->data->data.data;
  const size_t data_len = demo_conn->data->data.len;
  if(data_len > 0) {
    LOG("writing %zu plaintext response bytes to stdout", data_len);
    if(write(STDOUT_FILENO, data, data_len) < 0) {
      LOG_SIMPLE("error writing to stderr");
      goto cleanup;
    }
  }
  else if(ret == 0) {
    LOG_SIMPLE("no plaintext response data was read");
    ret = 1;
  }

cleanup:
  // Free connection resources and return.
  demo_client_connection_free(demo_conn);
  return ret;
}

demo_client_connection *
demo_client_connect(const demo_client_request_options *options)
{
  if(options == NULL) {
    return NULL;
  }

  conndata *data = NULL;
  demo_client_connection *demo_conn = NULL;

  demo_conn = calloc(1, sizeof(demo_client_connection));
  if(demo_conn == NULL) {
    perror("demo_client_connection calloc");
    goto cleanup;
  }
  demo_conn->options = options;

  // Connect the TCP socket.
  const int sockfd = connect_socket(demo_conn->options);
  if(sockfd <= 0) {
    perror("client: connect_socket");
    goto cleanup;
  }
  LOG_SIMPLE("socket connected");
  demo_conn->sockfd = sockfd;

  // Construct the rustls request with the client config.
  const rustls_result rr = rustls_client_connection_new(
    options->tls_config, options->hostname, &demo_conn->rconn);
  if(rr != RUSTLS_RESULT_OK) {
    print_error("client_connection_new", rr);
    goto cleanup;
  }

  data = calloc(1, sizeof(conndata));
  if(data == NULL) {
    perror("client: conndata calloc");
    goto cleanup;
  }
  data->rconn = demo_conn->rconn;
  data->fd = demo_conn->sockfd;
  data->verify_arg = "verify_arg";
  demo_conn->data = data;

  rustls_connection_set_userdata(demo_conn->rconn, data);
  rustls_connection_set_log_callback(demo_conn->rconn, log_cb);

  return demo_conn;

cleanup:
  if(demo_conn != NULL) {
    demo_client_connection_free(demo_conn);
  }

  return NULL;
}

int
connect_socket(const demo_client_request_options *options)
{
  if(options == NULL) {
    return -1;
  }

  int sockfd = 0;
  struct addrinfo *getaddrinfo_output = NULL, hints = { 0 };
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM; /* looking for TCP */

  const int getaddrinfo_result =
    getaddrinfo(options->hostname, options->port, &hints, &getaddrinfo_output);
  if(getaddrinfo_result != 0) {
    LOG("getaddrinfo: %s", gai_strerror(getaddrinfo_result));
    goto cleanup;
  }

  int connect_result = -1;
  for(int attempts = 0; attempts < MAX_CONNECT_ATTEMPTS; attempts++) {
    LOG("connect attempt %d of %d", attempts + 1, MAX_CONNECT_ATTEMPTS);
    sockfd = socket(getaddrinfo_output->ai_family,
                    getaddrinfo_output->ai_socktype,
                    getaddrinfo_output->ai_protocol);
    if(sockfd < 0) {
      perror("client: making socket");
      sleep(1);
      continue;
    }
    connect_result = connect(
      sockfd, getaddrinfo_output->ai_addr, getaddrinfo_output->ai_addrlen);
    if(connect_result < 0) {
      if(sockfd > 0) {
        close(sockfd);
      }
      perror("client: connecting");
      sleep(1);
      continue;
    }
    break;
  }
  if(connect_result < 0) {
    perror("client: connecting");
    goto cleanup;
  }
  const demo_result dr = nonblock(sockfd);
  if(dr != DEMO_OK) {
    // no need to perror() - nonblock() already did.
    return -1;
  }

  freeaddrinfo(getaddrinfo_output);
  return sockfd; // Success

cleanup:
  if(getaddrinfo_output != NULL) {
    freeaddrinfo(getaddrinfo_output);
  }
  if(sockfd > 0) {
    close(sockfd);
  }
  return -1;
}

int
demo_client_connection_write_get(const demo_client_connection *demo_conn)
{
  if(demo_conn == NULL || demo_conn->options == NULL) {
    return 1;
  }

  // Construct a plaintext HTTP request buffer.
  const rustls_str version = rustls_version();
  char get_request_buf[2048];
  int get_request_size =
    snprintf(get_request_buf,
             sizeof(get_request_buf),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: %.*s\r\n"
             "Accept: carcinization/inevitable, text/html\r\n"
             "Connection: close\r\n"
             "\r\n",
             demo_conn->options->path,
             demo_conn->options->hostname,
             (int)version.len,
             version.data);

  // Write the plaintext to the rustls connection.
  size_t n = 0;
  const rustls_result rr = rustls_connection_write(
    demo_conn->rconn, (uint8_t *)get_request_buf, get_request_size, &n);
  if(rr != RUSTLS_RESULT_OK) {
    LOG_SIMPLE(
      "error writing plaintext GET request bytes to rustls_connection");
    return 1;
  }
  if(n != (size_t)get_request_size) {
    LOG_SIMPLE(
      "short write writing plaintext GET request bytes to rustls_connection");
    return 1;
  }

  return 0; // Success.
}

demo_result
demo_client_connection_read_tls(demo_client_connection *demo_conn)
{
  size_t n = 0;

  const rustls_io_result io_res =
    rustls_connection_read_tls(demo_conn->rconn, read_cb, demo_conn->data, &n);

  if(io_res == EAGAIN) {
    return DEMO_AGAIN;
  }
  else if(io_res != 0) {
    LOG("reading from socket failed: errno %d", io_res);
    return DEMO_ERROR;
  }

  if(n == 0) {
    LOG_SIMPLE("read 0 bytes from socket, connection closed");
    demo_conn->closing = true;
    demo_conn->clean_closure = true;
    return DEMO_EOF;
  }

  rustls_result rr = rustls_connection_process_new_packets(demo_conn->rconn);
  if(rr != RUSTLS_RESULT_OK) {
    print_error("processing new TLS packets", rr);
    return DEMO_ERROR;
  }
  LOG("read %zu TLS bytes from socket", n);

  bytevec *bv = &demo_conn->data->data;
  if(bytevec_ensure_available(bv, 1024) != DEMO_OK) {
    return DEMO_ERROR;
  }

  for(;;) {
    char *buf = bytevec_writeable(bv);
    const size_t avail = bytevec_available(bv);

    rr = rustls_connection_read(demo_conn->rconn, (uint8_t *)buf, avail, &n);
    if(rr == RUSTLS_RESULT_PLAINTEXT_EMPTY) {
      /* This is expected. It just means "no more bytes for now." */
      return DEMO_OK;
    }
    if(rr != RUSTLS_RESULT_OK) {
      print_error("error in rustls_connection_read", rr);
      return DEMO_ERROR;
    }
    if(n == 0) {
      break;
    }
    bytevec_consume(bv, n);
    if(bytevec_ensure_available(bv, 1024) != DEMO_OK) {
      return DEMO_ERROR;
    }
  }

  /* If we got an EOF on the plaintext stream (peer closed connection cleanly),
   * verify that the sender then closed the TCP connection. */
  char buf[1];
  const ssize_t signed_n = read(demo_conn->sockfd, buf, sizeof(buf));
  if(signed_n > 0) {
    LOG("error: read returned %zu bytes after receiving close_notify", n);
    return DEMO_ERROR;
  }
  else if(signed_n < 0 && errno != EWOULDBLOCK) {
    LOG("wrong error after receiving close_notify: %s", strerror(errno));
    return DEMO_ERROR;
  }
  demo_conn->closing = true;
  demo_conn->clean_closure = true;
  return DEMO_EOF;
}

demo_result
demo_client_connection_write_tls(const demo_client_connection *demo_conn)
{
  if(demo_conn == NULL || demo_conn->options == NULL) {
    return DEMO_ERROR;
  }

  size_t n;
  rustls_io_result io_res;

#if !defined(_WIN32)
  if(demo_conn->options->use_vectored_io) {
    io_res = rustls_connection_write_tls_vectored(
      demo_conn->rconn, write_vectored_cb, demo_conn->data, &n);
  }
  else {
    io_res = rustls_connection_write_tls(
      demo_conn->rconn, write_cb, demo_conn->data, &n);
  }
#else
  io_res = rustls_connection_write_tls(
    demo_conn->rconn, write_cb, demo_conn->data, &n);
#endif

  if(io_res == EAGAIN) {
    return DEMO_AGAIN;
  }
  else if(io_res != 0) {
    LOG("writing to socket failed: errno %d", io_res);
    return DEMO_ERROR;
  }

  LOG("wrote %zu bytes of data to socket", n);
  return DEMO_OK;
}

void
demo_client_connection_free(demo_client_connection *conn)
{
  if(conn == NULL) {
    return;
  }

  if(conn->rconn != NULL) {
    rustls_connection_free(conn->rconn);
  }

  if(conn->data != NULL) {
    conndata *data = conn->data;
    if(data->data.data != NULL) {
      free(data->data.data);
    }
    free(data);
  }

  if(conn->sockfd != 0) {
    close(conn->sockfd);
  }

  free(conn);
}

uint32_t
unsafe_skip_verify(void *userdata,
                   const rustls_verify_server_cert_params *params)
{
  size_t i = 0;
  const rustls_slice_slice_bytes *intermediates =
    params->intermediate_certs_der;
  const size_t intermediates_len = rustls_slice_slice_bytes_len(intermediates);
  const conndata *conn = (struct conndata *)userdata;

  LOG("custom certificate verifier called for %.*s",
      (int)params->server_name.len,
      params->server_name.data);
  LOG("end entity len: %zu", params->end_entity_cert_der.len);
  LOG_SIMPLE("intermediates:");
  for(i = 0; i < intermediates_len; i++) {
    const rustls_slice_bytes bytes =
      rustls_slice_slice_bytes_get(intermediates, i);
    if(bytes.data != NULL) {
      LOG("   intermediate, len = %zu", bytes.len);
    }
  }
  LOG("ocsp response len: %zu", params->ocsp_response.len);
  if(0 != strcmp(conn->verify_arg, "verify_arg")) {
    LOG("invalid argument to verify: %p", userdata);
    return RUSTLS_RESULT_GENERAL;
  }
  return RUSTLS_RESULT_OK;
}
