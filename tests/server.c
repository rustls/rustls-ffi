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
#include <arpa/inet.h>
#include <unistd.h>
#endif /* _WIN32 */

#include <sys/types.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

/* rustls.h is autogenerated in the Makefile using cbindgen. */
#include "rustls.h"
#include "common.h"

typedef enum exchange_state
{
  READING_REQUEST,
  SENT_RESPONSE
} exchange_state;

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
  size_t n = 0;
  char buf[1];

  int err = rustls_connection_read_tls(rconn, read_cb, conn, &n);
  if(err == EAGAIN || err == EWOULDBLOCK) {
    LOG("reading from socket: EAGAIN or EWOULDBLOCK: %s", strerror(errno));
    return DEMO_AGAIN;
  }
  else if(err != 0) {
    LOG("reading from socket: errno %d", err);
    return DEMO_ERROR;
  }

  if(n == 0) {
    return DEMO_EOF;
  }
  LOG("read %zu bytes from socket", n);

  unsigned int result = rustls_connection_process_new_packets(rconn);
  if(result != RUSTLS_RESULT_OK) {
    print_error("in process_new_packets", result);
    return DEMO_ERROR;
  }

  result = copy_plaintext_to_buffer(conn);
  if(result != DEMO_EOF) {
    LOG("do_read returning %d", result);
    return result;
  }

  /* If we got an EOF on the plaintext stream (peer closed connection cleanly),
   * verify that the sender then closed the TCP connection. */
  ssize_t signed_n = read(conn->fd, buf, sizeof(buf));
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

enum demo_result
send_response(struct conndata *conn)
{
  struct rustls_connection *rconn = conn->rconn;
  const char *prefix = "HTTP/1.1 200 OK\r\nContent-Length:";
  const int body_size = 10000;
  size_t response_size = strlen(prefix) + 15 + body_size;
  char *response = malloc(response_size);
  size_t n;

  if(response == NULL) {
    LOG_SIMPLE("failed malloc");
    return DEMO_ERROR;
  }

  n = snprintf(response, response_size, "%s %d\r\n\r\n", prefix, body_size);
  memset(response + n, 'a', body_size);
  *(response + n + body_size) = '\n';
  *(response + n + body_size + 1) = '\0';
  response_size = strlen(response);

  rustls_connection_write(rconn, (const uint8_t *)response, response_size, &n);

  free(response);
  if(n != response_size) {
    LOG("failed to write all response bytes. wrote %zu", n);
    return DEMO_ERROR;
  }
  return DEMO_OK;
}

void
handle_conn(struct conndata *conn)
{
  fd_set read_fds;
  fd_set write_fds;
  size_t n = 0;
  struct rustls_connection *rconn = conn->rconn;
  int sockfd = conn->fd;
  struct timeval tv;
  enum exchange_state state = READING_REQUEST;
  rustls_handshake_kind hs_kind;
  int ciphersuite_id, kex_id;
  struct rustls_str ciphersuite_name, kex_name, hs_kind_name;

  LOG("acccepted conn on fd %d", conn->fd);

  for(;;) {
    FD_ZERO(&read_fds);
    if(rustls_connection_wants_read(rconn)) {
      FD_SET(sockfd, &read_fds);
    }
    FD_ZERO(&write_fds);
    if(rustls_connection_wants_write(rconn)) {
      FD_SET(sockfd, &write_fds);
    }

    if(!rustls_connection_wants_read(rconn) &&
       !rustls_connection_wants_write(rconn)) {
      LOG_SIMPLE("rustls wants neither read nor write. closing connection");
      goto cleanup;
    }

    tv.tv_sec = 1;
    tv.tv_usec = 0;

    int result = select(sockfd + 1, &read_fds, &write_fds, NULL, &tv);
    if(result == -1) {
      perror("server: select");
      goto cleanup;
    }
    if(result == 0) {
      LOG_SIMPLE("no fds from select, looping");
      continue;
    }

    if(FD_ISSET(sockfd, &read_fds)) {
      /* Read all bytes until we get EAGAIN. Then loop again to wind up in
         select awaiting the next bit of data. */
      for(;;) {
        result = do_read(conn, rconn);
        if(result == DEMO_AGAIN) {
          break;
        }
        else if(result != DEMO_OK) {
          goto cleanup;
        }
      }
    }
    if(FD_ISSET(sockfd, &write_fds)) {
      int err = write_tls(rconn, conn, &n);
      if(err != 0) {
        LOG("error in write_tls: errno %d", err);
        goto cleanup;
      }
      else if(n == 0) {
        LOG_SIMPLE("write returned 0 from write_tls");
        goto cleanup;
      }
    }

    const uint8_t *negotiated_alpn;
    size_t negotiated_alpn_len;
    if(state == READING_REQUEST && body_beginning(&conn->data) != NULL) {
      state = SENT_RESPONSE;
      LOG_SIMPLE("writing response");
      hs_kind = rustls_connection_handshake_kind(rconn);
      hs_kind_name = rustls_handshake_kind_str(hs_kind);
      LOG("handshake kind: %.*s", (int)hs_kind_name.len, hs_kind_name.data);
      ciphersuite_id = rustls_connection_get_negotiated_ciphersuite(rconn);
      ciphersuite_name =
        rustls_connection_get_negotiated_ciphersuite_name(rconn);
      LOG("negotiated ciphersuite: %.*s (%#x)",
          (int)ciphersuite_name.len,
          ciphersuite_name.data,
          ciphersuite_id);
      kex_id = rustls_connection_get_negotiated_key_exchange_group(rconn);
      kex_name =
        rustls_connection_get_negotiated_key_exchange_group_name(rconn);
      LOG("negotiated key exchange: %.*s (%#x)",
          (int)kex_name.len,
          kex_name.data,
          kex_id);

      rustls_connection_get_alpn_protocol(
        rconn, &negotiated_alpn, &negotiated_alpn_len);
      if(negotiated_alpn != NULL) {
        LOG("negotiated ALPN protocol: '%.*s'",
            (int)negotiated_alpn_len,
            negotiated_alpn);
      }
      else {
        LOG_SIMPLE("no ALPN protocol was negotiated");
      }

      if(send_response(conn) != DEMO_OK) {
        goto cleanup;
      }
    }
  }

cleanup:
  LOG("closing socket %d", sockfd);
  if(sockfd > 0) {
    close(sockfd);
  }
  if(conn->data.data)
    free(conn->data.data);
  free(conn);
}

bool shutting_down = false;

void
handle_signal(int signo)
{
  if(signo == SIGTERM) {
    LOG_SIMPLE("received SIGTERM, shutting down");
    shutting_down = true;
  }
}

int
main(int argc, const char **argv)
{
  int ret = 1;
  int sockfd = 0;

  const struct rustls_crypto_provider *custom_provider = NULL;
  struct rustls_server_config_builder *config_builder = NULL;
  const struct rustls_server_config *server_config = NULL;
  struct rustls_connection *rconn = NULL;
  const struct rustls_certified_key *certified_key = NULL;
  struct rustls_slice_bytes alpn_http11;
  struct rustls_root_cert_store_builder *client_cert_root_store_builder = NULL;
  const struct rustls_root_cert_store *client_cert_root_store = NULL;
  struct rustls_web_pki_client_cert_verifier_builder
    *client_cert_verifier_builder = NULL;
  struct rustls_client_cert_verifier *client_cert_verifier = NULL;
  rustls_result result = RUSTLS_RESULT_OK;

  /* Set this global variable for logging purposes. */
  programname = "server";

  alpn_http11.data = (unsigned char *)"http/1.1";
  alpn_http11.len = 8;

#ifndef _WIN32
  struct sigaction siga = { 0 };
  siga.sa_handler = handle_signal;
  if(sigaction(SIGTERM, &siga, NULL) == -1) {
    perror("server: setting a signal handler");
    return 1;
  }
#endif /* _WIN32 */

  if(argc <= 2) {
    fprintf(stderr,
            "usage: %s cert.pem key.pem\n\n"
            "Listen on port 8443 with the given cert and key.\n",
            argv[0]);
    goto cleanup;
  }

  const char *custom_ciphersuite_name = getenv("RUSTLS_CIPHERSUITE");
  if(custom_ciphersuite_name != NULL) {
    custom_provider =
      default_provider_with_custom_ciphersuite(custom_ciphersuite_name);
    if(custom_provider == NULL) {
      goto cleanup;
    }
    printf("customized to use ciphersuite: %s\n", custom_ciphersuite_name);

    result = rustls_server_config_builder_new_custom(custom_provider,
                                                     default_tls_versions,
                                                     default_tls_versions_len,
                                                     &config_builder);
    if(result != RUSTLS_RESULT_OK) {
      print_error("creating client config builder", result);
      goto cleanup;
    }
  }
  else {
    config_builder = rustls_server_config_builder_new();
  }

  certified_key = load_cert_and_key(argv[1], argv[2]);
  if(certified_key == NULL) {
    goto cleanup;
  }

  rustls_server_config_builder_set_certified_keys(
    config_builder, &certified_key, 1);
  rustls_server_config_builder_set_alpn_protocols(
    config_builder, &alpn_http11, 1);

  char *auth_cert = getenv("AUTH_CERT");
  char *auth_crl = getenv("AUTH_CRL");
  if(auth_cert) {
    char certbuf[10000];
    size_t certbuf_len;
    unsigned result =
      read_file(auth_cert, certbuf, sizeof(certbuf), &certbuf_len);
    if(result != DEMO_OK) {
      goto cleanup;
    }

    client_cert_root_store_builder = rustls_root_cert_store_builder_new();
    result = rustls_root_cert_store_builder_add_pem(
      client_cert_root_store_builder, (uint8_t *)certbuf, certbuf_len, true);
    if(result != RUSTLS_RESULT_OK) {
      goto cleanup;
    }
    result = rustls_root_cert_store_builder_build(
      client_cert_root_store_builder, &client_cert_root_store);
    if(result != RUSTLS_RESULT_OK) {
      goto cleanup;
    }
    client_cert_verifier_builder =
      rustls_web_pki_client_cert_verifier_builder_new(client_cert_root_store);

    char crlbuf[10000];
    size_t crlbuf_len;
    if(auth_crl) {
      result = read_file(auth_crl, crlbuf, sizeof(crlbuf), &crlbuf_len);
      if(result != DEMO_OK) {
        goto cleanup;
      }

      result = rustls_web_pki_client_cert_verifier_builder_add_crl(
        client_cert_verifier_builder, (uint8_t *)crlbuf, crlbuf_len);
      if(result != RUSTLS_RESULT_OK) {
        goto cleanup;
      }
    }

    result = rustls_web_pki_client_cert_verifier_builder_build(
      client_cert_verifier_builder, &client_cert_verifier);
    if(result != RUSTLS_RESULT_OK) {
      goto cleanup;
    }
    rustls_server_config_builder_set_client_verifier(config_builder,
                                                     client_cert_verifier);
  }

  if(getenv("SSLKEYLOGFILE")) {
    result = rustls_server_config_builder_set_key_log_file(config_builder);
    if(result != RUSTLS_RESULT_OK) {
      print_error("enabling keylog", result);
      goto cleanup;
    }
  }
  else if(getenv("STDERRKEYLOG")) {
    result = rustls_server_config_builder_set_key_log(
      config_builder, stderr_key_log_cb, NULL);
    if(result != RUSTLS_RESULT_OK) {
      print_error("enabling keylog", result);
      goto cleanup;
    }
  }

  result = rustls_server_config_builder_build(config_builder, &server_config);
  if(result != RUSTLS_RESULT_OK) {
    print_error("building server config", result);
    goto cleanup;
  }

#ifdef _WIN32
  WSADATA wsa;
  WSAStartup(MAKEWORD(1, 1), &wsa);
#endif

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if(sockfd < 0) {
    LOG("making socket: %s", strerror(errno));
  }

  int enable = 1;
  if(setsockopt(
       sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&enable, sizeof(int)) <
     0) {
    print_error("setsockopt(SO_REUSEADDR) failed", 7001);
  }

  struct sockaddr_in my_addr, peer_addr;
  memset(&my_addr, 0, sizeof(struct sockaddr_in));
  /* Clear structure */
  my_addr.sin_family = AF_INET;
  my_addr.sin_addr.s_addr = INADDR_ANY;
  my_addr.sin_port = htons(8443);
  my_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

  if(bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr_in)) ==
     -1) {
    perror("server: bind");
    goto cleanup;
  }

  if(listen(sockfd, 50) == -1) {
    perror("server: listen");
    goto cleanup;
  }
  LOG("listening on localhost:8443. AUTH_CERT=%s, AUTH_CRL=%s, VECTORED_IO=%s",
      auth_cert,
      auth_crl,
      getenv("VECTORED_IO"));

  while(!shutting_down) {
    socklen_t peer_addr_size;
    peer_addr_size = sizeof(struct sockaddr_in);
    int clientfd =
      accept(sockfd, (struct sockaddr *)&peer_addr, &peer_addr_size);
    if(shutting_down) {
      break;
    }
    if(clientfd < 0) {
      perror("server: accept");
      goto cleanup;
    }

    nonblock(clientfd);

    unsigned int result = rustls_server_connection_new(server_config, &rconn);
    if(result != RUSTLS_RESULT_OK) {
      print_error("making session", result);
      goto cleanup;
    }

    struct conndata *conndata;
    conndata = calloc(1, sizeof(struct conndata));
    conndata->fd = clientfd;
    conndata->rconn = rconn;
    rustls_connection_set_userdata(rconn, conndata);
    rustls_connection_set_log_callback(rconn, log_cb);
    handle_conn(conndata);
    rustls_connection_free(rconn);
    rconn = NULL;
  }

  // Success!
  ret = 0;

cleanup:
  rustls_certified_key_free(certified_key);
  rustls_root_cert_store_builder_free(client_cert_root_store_builder);
  rustls_root_cert_store_free(client_cert_root_store);
  rustls_web_pki_client_cert_verifier_builder_free(
    client_cert_verifier_builder);
  rustls_client_cert_verifier_free(client_cert_verifier);
  rustls_server_config_free(server_config);
  rustls_connection_free(rconn);
  rustls_crypto_provider_free(custom_provider);
  if(sockfd > 0) {
    close(sockfd);
  }

#ifdef _WIN32
  WSACleanup();
#endif

  return ret;
}
