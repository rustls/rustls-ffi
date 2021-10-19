#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h> /* gai_strerror() */
#include <io.h> /* write() */
#include <fcntl.h> /* O_BINARY */
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#endif

#include <sys/types.h>
#include <sys/uio.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#ifdef _WIN32
#define sleep(s) Sleep(1000 * (s))
#define read(s, buf, n) recv(s, buf, n, 0)
#define close(s) closesocket(s)
#define bzero(buf, n) memset(buf, '\0', n)

/* Hacks for 'errno' stuff
 */
#undef EAGAIN
#define EAGAIN WSAEWOULDBLOCK
#undef EWOULDBLOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#undef errno
#define errno WSAGetLastError()
#define perror(str) fprintf(stderr, str ": %d.\n", WSAGetLastError())
#define strerror(e) ws_strerror(e)
#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1 /* MinGW has this */
#endif
#endif

/* crustls.h is autogenerated in the Makefile using cbindgen. */
#include "crustls.h"
#include "common.h"

/*
 * Connect to the given hostname on the given port and return the file
 * descriptor of the socket. On error, print the error and return 1. Caller is
 * responsible for closing socket.
 */
int
make_conn(const char *hostname, const char *port)
{
  int sockfd = 0;
  enum crustls_demo_result result = 0;
  struct addrinfo *getaddrinfo_output = NULL, hints;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM; /* looking for TCP */

  fprintf(stderr, "connecting to %s:%s\n", hostname, port);
  int getaddrinfo_result =
    getaddrinfo(hostname, port, &hints, &getaddrinfo_output);
  if(getaddrinfo_result != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(getaddrinfo_result));
    goto cleanup;
  }

  sockfd = socket(getaddrinfo_output->ai_family,
                  getaddrinfo_output->ai_socktype,
                  getaddrinfo_output->ai_protocol);
  if(sockfd < 0) {
    perror("making socket");
    goto cleanup;
  }

  int connect_result = connect(
    sockfd, getaddrinfo_output->ai_addr, getaddrinfo_output->ai_addrlen);
  if(connect_result < 0) {
    perror("connecting");
    goto cleanup;
  }
  result = nonblock(sockfd);
  if(result != CRUSTLS_DEMO_OK) {
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

/* Read all available bytes from the rustls_connection until EOF.
 * Note that EOF here indicates "no more bytes until
 * process_new_packets", not "stream is closed".
 *
 * Returns CRUSTLS_DEMO_OK for success,
 * CRUSTLS_DEMO_ERROR for error,
 * CRUSTLS_DEMO_EOF for "received close_notify"
 */
int
copy_plaintext_to_stdout(struct rustls_connection *client_conn)
{
  int result;
  char buf[2048];
  size_t n;

  for(;;) {
    bzero(buf, sizeof(buf));
    result =
      rustls_connection_read(client_conn, (uint8_t *)buf, sizeof(buf), &n);
    if(result == RUSTLS_RESULT_PLAINTEXT_EMPTY) {
      /* This is expected. It just means "no more bytes for now." */
      return CRUSTLS_DEMO_OK;
    } else if(result != RUSTLS_RESULT_OK) {
      print_error("Error in rustls_connection_read", result);
      return CRUSTLS_DEMO_ERROR;
    }
    if(n == 0) {
      fprintf(stderr, "Received clean EOF, cleanly ending connection\n");
      return CRUSTLS_DEMO_EOF;
    }

    result = write_all(STDOUT_FILENO, buf, n);
    if(result != 0) {
      return CRUSTLS_DEMO_ERROR;
    }
  }

  fprintf(stderr, "copy_plaintext_to_stdout: fell through loop\n");
  return CRUSTLS_DEMO_ERROR;
}

/*
 * Do one read from the socket, and process all resulting bytes into the
 * rustls_connection, then copy all plaintext bytes from the session to stdout.
 * Returns:
 *  - CRUSTLS_DEMO_OK for success
 *  - CRUSTLS_DEMO_AGAIN if we got an EAGAIN or EWOULDBLOCK reading from the
 *    socket
 *  - CRUSTLS_DEMO_EOF if we got EOF
 *  - CRUSTLS_DEMO_ERROR for other errors.
 */
enum crustls_demo_result
do_read(struct conndata *conn, struct rustls_connection *rconn)
{
  int err = 1;
  int result = 1;
  size_t n = 0;
  ssize_t signed_n = 0;
  char buf[1];

  err = rustls_connection_read_tls(rconn, read_cb, conn, &n);

  if(err == EAGAIN || err == EWOULDBLOCK) {
    fprintf(stderr,
            "reading from socket: EAGAIN or EWOULDBLOCK: %s\n",
            strerror(errno));
    return CRUSTLS_DEMO_AGAIN;
  }
  else if(err != 0) {
    fprintf(stderr, "reading from socket: errno %d\n", err);
    return CRUSTLS_DEMO_ERROR;
  }

  result = rustls_connection_process_new_packets(rconn);
  if(result != RUSTLS_RESULT_OK) {
    print_error("in process_new_packets", result);
    return CRUSTLS_DEMO_ERROR;
  }

  result = copy_plaintext_to_buffer(conn);
  if(result != CRUSTLS_DEMO_EOF) {
    return result;
  }

  /* If we got an EOF on the plaintext stream (peer closed connection cleanly),
   * verify that the sender then closed the TCP connection. */
  signed_n = read(conn->fd, buf, sizeof(buf));
  if(signed_n > 0) {
    fprintf(stderr,
            "read returned %ld bytes after receiving close_notify\n",
            n);
    return CRUSTLS_DEMO_ERROR;
  }
  else if (signed_n < 0 && errno != EWOULDBLOCK) {
    fprintf(stderr,
            "read returned incorrect error after receiving close_notify: %s\n",
            strerror(errno));
    return CRUSTLS_DEMO_ERROR;
  }
  return CRUSTLS_DEMO_EOF;
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
  int result = 1;
  char buf[2048];
  fd_set read_fds;
  fd_set write_fds;
  size_t n = 0;
  const char *body;
  const char *content_length_str;
  const char *content_length_end;
  unsigned long content_length = 0;
  size_t headers_len = 0;

  bzero(buf, sizeof(buf));
  snprintf(buf,
           sizeof(buf),
           "GET %s HTTP/1.1\r\n"
           "Host: %s\r\n"
           "User-Agent: crustls-demo\r\n"
           "Accept: carcinization/inevitable, text/html\r\n"
           "Connection: close\r\n"
           "\r\n",
           path,
           hostname);
  /* First we write the plaintext - the data that we want rustls to encrypt for
   * us- to the rustls connection. */
  result = rustls_connection_write(rconn, (uint8_t *)buf, strlen(buf), &n);
  if(result != RUSTLS_RESULT_OK) {
    fprintf(stderr, "error writing plaintext bytes to rustls_connection\n");
    goto cleanup;
  }
  if(n != strlen(buf)) {
    fprintf(stderr,
            "short write writing plaintext bytes to rustls_connection\n");
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

    result = select(sockfd + 1, &read_fds, &write_fds, NULL, NULL);
    if(result == -1) {
      perror("select");
      goto cleanup;
    }

    if(FD_ISSET(sockfd, &read_fds)) {
      fprintf(
        stderr,
        "rustls_connection wants us to read_tls. First we need to pull some "
        "bytes from the socket\n");

      /* Read all bytes until we get EAGAIN. Then loop again to wind up in
         select awaiting the next bit of data. */
      for(;;) {
        result = do_read(conn, rconn);
        if(result == CRUSTLS_DEMO_AGAIN) {
          break;
        }
        else if(result == CRUSTLS_DEMO_EOF) {
          ret = 0;
          goto cleanup;
        }
        else if(result != CRUSTLS_DEMO_OK) {
          goto cleanup;
        }
        if(headers_len == 0) {
          body = body_beginning(&conn->data);
          if(body != NULL) {
            headers_len = body - conn->data.data;
            fprintf(stderr, "body began at %ld\n", headers_len);
            content_length_str = get_first_header_value(conn->data.data,
                                                        headers_len,
                                                        CONTENT_LENGTH,
                                                        strlen(CONTENT_LENGTH),
                                                        &n);
            if(content_length_str == NULL) {
              fprintf(stderr, "content length header not found\n");
              goto cleanup;
            }
            content_length =
              strtoul(content_length_str, (char **)&content_length_end, 10);
            if(content_length_end == content_length_str) {
              fprintf(stderr,
                      "invalid Content-Length '%.*s'\n",
                      (int)n,
                      content_length_str);
              goto cleanup;
            }
            fprintf(stderr, "content length %ld\n", content_length);
          }
        }
        if(headers_len != 0 &&
           conn->data.len >= headers_len + content_length) {
          /* body is done. */
          if(write(STDERR_FILENO, conn->data.data, conn->data.len) < 0) {
            fprintf(stderr, "error writing to stderr\n");
            goto cleanup;
          }
          ret = 0;
          goto cleanup;
        }
      }
    }
    if(FD_ISSET(sockfd, &write_fds)) {
      fprintf(stderr, "rustls_connection wants us to write_tls.\n");
      for(;;) {
        /* This invokes rustls_connection_write_tls. We pass a callback to
         * that function. Rustls will pass a buffer to that callback with
         * encrypted bytes, that we will write to `conn`. */
        err = write_tls(rconn, conn, &n);
        if(err != 0) {
          fprintf(
            stderr, "Error in rustls_connection_write_tls: errno %d\n", err);
          goto cleanup;
        }
        if(result == CRUSTLS_DEMO_AGAIN) {
          break;
        }
        else if(n == 0) {
          fprintf(stderr, "write 0 from rustls_connection_write_tls\n");
          break;
        }
      }
    }
  }

  fprintf(stderr, "send_request_and_read_response: loop fell through");

cleanup:
  if(sockfd > 0) {
    close(sockfd);
  }
  return ret;
}

void
log_cb(void *userdata, const struct rustls_log_params *params)
{
  struct conndata *conn = (struct conndata*)userdata;
  struct rustls_str level_str = rustls_log_level_str(params->level);
  fprintf(stderr, "rustls[fd %d][%.*s]: %.*s\n", conn->fd,
    (int)level_str.len, level_str.data, (int)params->message.len, params->message.data);
}

int
do_request(const struct rustls_client_config *client_config,
           const char *hostname, const char *port, const char *path)
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

  fprintf(stderr,
          "custom certificate verifier called for %.*s\n",
          (int)params->dns_name.len,
          params->dns_name.data);
  fprintf(stderr, "end entity len: %ld\n", params->end_entity_cert_der.len);
  fprintf(stderr, "intermediates:\n");
  for(i = 0; i < intermediates_len; i++) {
    bytes = rustls_slice_slice_bytes_get(intermediates, i);
    if(bytes.data != NULL) {
      fprintf(stderr, "  intermediate, len = %ld\n", bytes.len);
    }
  }
  fprintf(stderr, "ocsp response len: %ld\n", params->ocsp_response.len);
  if(0 != strcmp(conn->verify_arg, "verify_arg")) {
    fprintf(stderr, "invalid argument to verify: %p\n", userdata);
    return RUSTLS_RESULT_GENERAL;
  }
  return RUSTLS_RESULT_OK;
}

int
main(int argc, const char **argv)
{
  int ret = 1;
  int result = 1;
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

  struct rustls_client_config_builder *config_builder =
    rustls_client_config_builder_new();
  const struct rustls_client_config *client_config = NULL;
  struct rustls_slice_bytes alpn_http11;

  alpn_http11.data = (unsigned char*)"http/1.1";
  alpn_http11.len = 8;

#ifdef _WIN32
  WSADATA wsa;
  WSAStartup(MAKEWORD(1, 1), &wsa);
  setmode(STDOUT_FILENO, O_BINARY);
#endif

  if(getenv("CA_FILE")) {
    result = rustls_client_config_builder_load_roots_from_file(
      config_builder, getenv("CA_FILE"));
    if(result != RUSTLS_RESULT_OK) {
      print_error("loading trusted certificates", result);
      goto cleanup;
    }
  } else if(getenv("NO_CHECK_CERTIFICATE")) {
    rustls_client_config_builder_dangerous_set_certificate_verifier(
      config_builder, verify);
  } else {
    fprintf(stderr, "must set either CA_FILE or NO_CHECK_CERTIFICATE env var\n");
    goto cleanup;
  }

  rustls_client_config_builder_set_alpn_protocols(config_builder, &alpn_http11, 1);

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
  rustls_client_config_free(client_config);

#ifdef _WIN32
  WSACleanup();
#endif

  return ret;
}
