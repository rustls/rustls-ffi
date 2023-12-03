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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

/* rustls.h is autogenerated in the Makefile using cbindgen. */
#include "rustls.h"
#include "common.h"

/*
 * Connect to the given hostname on the given port and return the file
 * descriptor of the socket. Tries to connect up to 10 times. On error,
 * print the error and return 1. Caller is responsible for closing socket.
 */
int
make_conn(const char *hostname, const char *port)
{
  int sockfd = 0;
  struct addrinfo *getaddrinfo_output = NULL, hints;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM; /* looking for TCP */

  LOG("connecting to %s:%s", hostname, port);
  int getaddrinfo_result =
    getaddrinfo(hostname, port, &hints, &getaddrinfo_output);
  if(getaddrinfo_result != 0) {
    LOG("getaddrinfo: %s", gai_strerror(getaddrinfo_result));
    goto cleanup;
  }

  int connect_result;
  for(int attempts = 0; attempts < 10; attempts++) {
    LOG("connect attempt %d", attempts);
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
  enum demo_result result = nonblock(sockfd);
  if(result != DEMO_OK) {
    return 1;
  }

  freeaddrinfo(getaddrinfo_output);
  return sockfd;

cleanup:
  if(getaddrinfo_output != NULL) {
    freeaddrinfo(getaddrinfo_output);
  }
  if(sockfd > 0) {
    close(sockfd);
  }
  return -1;
}

/*
 * Do one read from the socket, and process all resulting bytes into the
 * rustls_connection, then copy all plaintext bytes from the session to stdout.
 * Returns:
 *  - DEMO_OK for success
 *  - DEMO_AGAIN if we got an EAGAIN or EWOULDBLOCK reading from the
 *    socket
 *  - DEMO_EOF if we got EOF
 *  - DEMO_ERROR for other errors.
 */
enum demo_result
do_read(struct conndata *conn, struct rustls_connection *rconn)
{
  int err = 1;
  unsigned result = 1;
  size_t n = 0;
  ssize_t signed_n = 0;
  char buf[1];

  err = rustls_connection_read_tls(rconn, read_cb, conn, &n);

  if(err == EAGAIN || err == EWOULDBLOCK) {
    LOG("reading from socket: EAGAIN or EWOULDBLOCK: %s", strerror(errno));
    return DEMO_AGAIN;
  }
  else if(err != 0) {
    LOG("reading from socket: errno %d", err);
    return DEMO_ERROR;
  }

  result = rustls_connection_process_new_packets(rconn);
  if(result != RUSTLS_RESULT_OK) {
    print_error("in process_new_packets", result);
    return DEMO_ERROR;
  }

  result = copy_plaintext_to_buffer(conn);
  if(result != DEMO_EOF) {
    return result;
  }

  /* If we got an EOF on the plaintext stream (peer closed connection cleanly),
   * verify that the sender then closed the TCP connection. */
  signed_n = read(conn->fd, buf, sizeof(buf));
  if(signed_n > 0) {
    LOG("error: read returned %zu bytes after receiving close_notify", n);
    return DEMO_ERROR;
  }
  else if(signed_n < 0 && errno != EWOULDBLOCK) {
    LOG("wrong error after receiving close_notify: %s", strerror(errno));
    return DEMO_ERROR;
  }
  return DEMO_EOF;
}

static const char *CONTENT_LENGTH = "Content-Length";

/*
 * Given an established TCP connection, and a rustls_connection, send an
 * HTTP request and read the response. On success, return 0. On error, print
 * the message and return 1.
 */
int
send_request_and_read_response(struct conndata *conn,
                               struct rustls_connection *rconn,
                               const char *hostname, const char *path)
{
  int sockfd = conn->fd;
  int ret = 1;
  int err = 1;
  unsigned result = 1;
  char buf[2048];
  fd_set read_fds;
  fd_set write_fds;
  size_t n = 0;
  const char *body;
  const char *content_length_str;
  const char *content_length_end;
  unsigned long content_length = 0;
  size_t headers_len = 0;
  struct rustls_str version;

  version = rustls_version();
  memset(buf, '\0', sizeof(buf));
  snprintf(buf,
           sizeof(buf),
           "GET %s HTTP/1.1\r\n"
           "Host: %s\r\n"
           "User-Agent: %.*s\r\n"
           "Accept: carcinization/inevitable, text/html\r\n"
           "Connection: close\r\n"
           "\r\n",
           path,
           hostname,
           (int)version.len,
           version.data);
  /* First we write the plaintext - the data that we want rustls to encrypt for
   * us- to the rustls connection. */
  result = rustls_connection_write(rconn, (uint8_t *)buf, strlen(buf), &n);
  if(result != RUSTLS_RESULT_OK) {
    LOG_SIMPLE("error writing plaintext bytes to rustls_connection");
    goto cleanup;
  }
  if(n != strlen(buf)) {
    LOG_SIMPLE("short write writing plaintext bytes to rustls_connection");
    goto cleanup;
  }

  for(;;) {
    FD_ZERO(&read_fds);
    /* These two calls just inspect the state of the connection - if it's time
    for us to write more, or to read more. */
    if(rustls_connection_wants_read(rconn)) {
      FD_SET(sockfd, &read_fds);
    }
    FD_ZERO(&write_fds);
    if(rustls_connection_wants_write(rconn)) {
      FD_SET(sockfd, &write_fds);
    }

    if(!rustls_connection_wants_read(rconn) &&
       !rustls_connection_wants_write(rconn)) {
      LOG_SIMPLE(
        "rustls wants neither read nor write. drain plaintext and exit");
      goto drain_plaintext;
    }

    int select_result = select(sockfd + 1, &read_fds, &write_fds, NULL, NULL);
    if(select_result == -1) {
      perror("client: select");
      goto cleanup;
    }

    if(FD_ISSET(sockfd, &read_fds)) {
      /* Read all bytes until we get EAGAIN. Then loop again to wind up in
         select awaiting the next bit of data. */
      for(;;) {
        result = do_read(conn, rconn);
        if(result == DEMO_AGAIN) {
          break;
        }
        else if(result == DEMO_EOF) {
          goto drain_plaintext;
        }
        else if(result != DEMO_OK) {
          goto cleanup;
        }
        if(headers_len == 0) {
          body = body_beginning(&conn->data);
          if(body != NULL) {
            headers_len = body - conn->data.data;
            LOG("body began at %zu", headers_len);
            content_length_str = get_first_header_value(conn->data.data,
                                                        headers_len,
                                                        CONTENT_LENGTH,
                                                        strlen(CONTENT_LENGTH),
                                                        &n);
            if(content_length_str == NULL) {
              LOG_SIMPLE("content length header not found");
              goto cleanup;
            }
            content_length =
              strtoul(content_length_str, (char **)&content_length_end, 10);
            if(content_length_end == content_length_str) {
              LOG("invalid Content-Length '%.*s'", (int)n, content_length_str);
              goto cleanup;
            }
            LOG("content length %lu", content_length);
          }
        }
        if(headers_len != 0 &&
           conn->data.len >= headers_len + content_length) {
          goto drain_plaintext;
        }
      }
    }
    if(FD_ISSET(sockfd, &write_fds)) {
      for(;;) {
        /* This invokes rustls_connection_write_tls. We pass a callback to
         * that function. Rustls will pass a buffer to that callback with
         * encrypted bytes, that we will write to `conn`. */
        err = write_tls(rconn, conn, &n);
        if(err != 0) {
          LOG("error in rustls_connection_write_tls: errno %d", err);
          goto cleanup;
        }
        if(result == DEMO_AGAIN) {
          break;
        }
        else if(n == 0) {
          LOG_SIMPLE("write returned 0 from rustls_connection_write_tls");
          break;
        }
      }
    }
  }

  LOG_SIMPLE("send_request_and_read_response: loop fell through");

drain_plaintext:
  result = copy_plaintext_to_buffer(conn);
  if(result != DEMO_OK && result != DEMO_EOF) {
    goto cleanup;
  }
  LOG("writing %zu bytes to stdout", conn->data.len);
  if(write(STDOUT_FILENO, conn->data.data, conn->data.len) < 0) {
    LOG_SIMPLE("error writing to stderr");
    goto cleanup;
  }
  ret = 0;

cleanup:
  if(sockfd > 0) {
    close(sockfd);
  }
  return ret;
}

int
do_request(const struct rustls_client_config *client_config,
           const char *hostname, const char *port,
           const char *path) // NOLINT(bugprone-easily-swappable-parameters)
{
  struct rustls_connection *rconn = NULL;
  struct conndata *conn = NULL;
  int ret = 1;
  int sockfd = make_conn(hostname, port);
  if(sockfd < 0) {
    // No perror because make_conn printed error already.
    goto cleanup;
  }

  rustls_result result =
    rustls_client_connection_new(client_config, hostname, &rconn);
  if(result != RUSTLS_RESULT_OK) {
    print_error("client_connection_new", result);
    goto cleanup;
  }

  conn = calloc(1, sizeof(struct conndata));
  if(conn == NULL) {
    goto cleanup;
  }
  conn->rconn = rconn;
  conn->fd = sockfd;
  conn->verify_arg = "verify_arg";

  rustls_connection_set_userdata(rconn, conn);
  rustls_connection_set_log_callback(rconn, log_cb);

  ret = send_request_and_read_response(conn, rconn, hostname, path);
  if(ret != RUSTLS_RESULT_OK) {
    goto cleanup;
  }

  ret = 0;

cleanup:
  rustls_connection_free(rconn);
  if(sockfd > 0) {
    close(sockfd);
  }
  if(conn != NULL) {
    if(conn->data.data != NULL) {
      free(conn->data.data);
    }
    free(conn);
  }
  return ret;
}

enum rustls_result
verify(void *userdata, const rustls_verify_server_cert_params *params)
{
  size_t i = 0;
  const rustls_slice_slice_bytes *intermediates =
    params->intermediate_certs_der;
  struct rustls_slice_bytes bytes;
  const size_t intermediates_len = rustls_slice_slice_bytes_len(intermediates);
  struct conndata *conn = (struct conndata *)userdata;

  LOG("custom certificate verifier called for %.*s",
      (int)params->server_name.len,
      params->server_name.data);
  LOG("end entity len: %zu", params->end_entity_cert_der.len);
  LOG_SIMPLE("intermediates:");
  for(i = 0; i < intermediates_len; i++) {
    bytes = rustls_slice_slice_bytes_get(intermediates, i);
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

int
main(int argc, const char **argv)
{
  int ret = 1;
  unsigned result = 1;

  if(argc <= 2) {
    fprintf(stderr,
            "usage: %s hostname port path\n\n"
            "Connect to a host via HTTPS on the provided port, make a request "
            "for the\n"
            "given path, and emit response to stdout (three times).\n",
            argv[0]);
    return 1;
  }
  const char *hostname = argv[1];
  const char *port = argv[2];
  const char *path = argv[3];

  /* Set this global variable for logging purposes. */
  programname = "client";

  struct rustls_client_config_builder *config_builder =
    rustls_client_config_builder_new();
  struct rustls_root_cert_store_builder *server_cert_root_store_builder = NULL;
  const struct rustls_root_cert_store *server_cert_root_store = NULL;
  const struct rustls_client_config *client_config = NULL;
  struct rustls_web_pki_server_cert_verifier_builder
    *server_cert_verifier_builder = NULL;
  struct rustls_server_cert_verifier *server_cert_verifier = NULL;
  struct rustls_slice_bytes alpn_http11;
  const struct rustls_certified_key *certified_key = NULL;

  alpn_http11.data = (unsigned char *)"http/1.1";
  alpn_http11.len = 8;

#ifdef _WIN32
  WSADATA wsa;
  WSAStartup(MAKEWORD(1, 1), &wsa);
  setmode(STDOUT_FILENO, O_BINARY);
#endif

  if(getenv("CA_FILE")) {
    server_cert_root_store_builder = rustls_root_cert_store_builder_new();
    result = rustls_root_cert_store_builder_load_roots_from_file(
      server_cert_root_store_builder, getenv("CA_FILE"), true);
    if(result != RUSTLS_RESULT_OK) {
      print_error("loading trusted certificates", result);
      goto cleanup;
    }
    result = rustls_root_cert_store_builder_build(
      server_cert_root_store_builder, &server_cert_root_store);
    if(result != RUSTLS_RESULT_OK) {
      goto cleanup;
    }

    server_cert_verifier_builder =
      rustls_web_pki_server_cert_verifier_builder_new(server_cert_root_store);

    result = rustls_web_pki_server_cert_verifier_builder_build(
      server_cert_verifier_builder, &server_cert_verifier);
    if(result != RUSTLS_RESULT_OK) {
      goto cleanup;
    }
    rustls_client_config_builder_set_server_verifier(config_builder,
                                                     server_cert_verifier);
  }
  else if(getenv("NO_CHECK_CERTIFICATE")) {
    rustls_client_config_builder_dangerous_set_certificate_verifier(
      config_builder, verify);
  }
  else {
    fprintf(
      stderr,
      "client: must set either CA_FILE or NO_CHECK_CERTIFICATE env var\n");
    goto cleanup;
  }

  char *auth_cert = getenv("AUTH_CERT");
  char *auth_key = getenv("AUTH_KEY");
  if((auth_cert && !auth_key) || (!auth_cert && auth_key)) {
    fprintf(
      stderr,
      "client: must set both AUTH_CERT and AUTH_KEY env vars, or neither\n");
    goto cleanup;
  }
  else if(auth_cert && auth_key) {
    certified_key = load_cert_and_key(auth_cert, auth_key);
    if(certified_key == NULL) {
      goto cleanup;
    }
    rustls_client_config_builder_set_certified_key(
      config_builder, &certified_key, 1);
  }

  rustls_client_config_builder_set_alpn_protocols(
    config_builder, &alpn_http11, 1);

  client_config = rustls_client_config_builder_build(config_builder);

  int i;
  for(i = 0; i < 3; i++) {
    result = do_request(client_config, hostname, port, path);
    if(result != 0) {
      goto cleanup;
    }
  }

  // Success!
  ret = 0;

cleanup:
  rustls_root_cert_store_builder_free(server_cert_root_store_builder);
  rustls_root_cert_store_free(server_cert_root_store);
  rustls_web_pki_server_cert_verifier_builder_free(
    server_cert_verifier_builder);
  rustls_server_cert_verifier_free(server_cert_verifier);
  rustls_certified_key_free(certified_key);
  rustls_client_config_free(client_config);

#ifdef _WIN32
  WSACleanup();
#endif

  return ret;
}
