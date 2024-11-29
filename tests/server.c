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

demo_result
send_response(const conndata *conn)
{
  rustls_connection *rconn = conn->rconn;
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
handle_conn(conndata *conn)
{
  fd_set read_fds;
  fd_set write_fds;
  size_t n = 0;
  rustls_connection *rconn = conn->rconn;
  const int sockfd = conn->fd;
  struct timeval tv;
  exchange_state state = READING_REQUEST;

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
      const rustls_io_result err = write_tls(rconn, conn, &n);
      if(err != 0) {
        LOG("error in write_tls: errno %d", err);
        goto cleanup;
      }
      else if(n == 0) {
        LOG_SIMPLE("write returned 0 from write_tls");
        goto cleanup;
      }
    }

    if(state == READING_REQUEST && body_beginning(&conn->data) != NULL) {
      state = SENT_RESPONSE;
      LOG_SIMPLE("writing response");
      log_connection_info(rconn);

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
handle_signal(const int signo)
{
  if(signo == SIGTERM) {
    LOG_SIMPLE("received SIGTERM, shutting down");
    shutting_down = true;
  }
}

int
main(const int argc, const char **argv)
{
  int ret = 1;
  int sockfd = 0;

  const rustls_crypto_provider *custom_provider = NULL;
  rustls_server_config_builder *config_builder = NULL;
  const rustls_server_config *server_config = NULL;
  rustls_connection *rconn = NULL;
  const rustls_certified_key *certified_key = NULL;
  rustls_slice_bytes alpn_http11;
  rustls_root_cert_store_builder *client_cert_root_store_builder = NULL;
  const rustls_root_cert_store *client_cert_root_store = NULL;
  rustls_web_pki_client_cert_verifier_builder *client_cert_verifier_builder =
    NULL;
  rustls_client_cert_verifier *client_cert_verifier = NULL;

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
  const char *certfile = argv[1];
  const char *keyfile = argv[2];

  const char *custom_ciphersuite_name = getenv("RUSTLS_CIPHERSUITE");
  if(custom_ciphersuite_name != NULL) {
    custom_provider =
      default_provider_with_custom_ciphersuite(custom_ciphersuite_name);
    if(custom_provider == NULL) {
      goto cleanup;
    }
    printf("customized to use ciphersuite: %s\n", custom_ciphersuite_name);

    const rustls_result rr =
      rustls_server_config_builder_new_custom(custom_provider,
                                              default_tls_versions,
                                              default_tls_versions_len,
                                              &config_builder);
    if(rr != RUSTLS_RESULT_OK) {
      print_error("creating client config builder", rr);
      goto cleanup;
    }
  }
  else {
    config_builder = rustls_server_config_builder_new();
  }

  certified_key = load_cert_and_key(certfile, keyfile);
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
    demo_result dr =
      read_file(auth_cert, certbuf, sizeof(certbuf), &certbuf_len);
    if(dr != DEMO_OK) {
      goto cleanup;
    }

    client_cert_root_store_builder = rustls_root_cert_store_builder_new();
    rustls_result rr = rustls_root_cert_store_builder_add_pem(
      client_cert_root_store_builder, (uint8_t *)certbuf, certbuf_len, true);
    if(rr != RUSTLS_RESULT_OK) {
      goto cleanup;
    }
    rr = rustls_root_cert_store_builder_build(client_cert_root_store_builder,
                                              &client_cert_root_store);
    if(rr != RUSTLS_RESULT_OK) {
      goto cleanup;
    }
    client_cert_verifier_builder =
      rustls_web_pki_client_cert_verifier_builder_new(client_cert_root_store);

    if(auth_crl) {
      size_t crlbuf_len;
      char crlbuf[10000];
      dr = read_file(auth_crl, crlbuf, sizeof(crlbuf), &crlbuf_len);
      if(dr != DEMO_OK) {
        goto cleanup;
      }

      rr = rustls_web_pki_client_cert_verifier_builder_add_crl(
        client_cert_verifier_builder, (uint8_t *)crlbuf, crlbuf_len);
      if(rr != RUSTLS_RESULT_OK) {
        goto cleanup;
      }
    }

    rr = rustls_web_pki_client_cert_verifier_builder_build(
      client_cert_verifier_builder, &client_cert_verifier);
    if(rr != RUSTLS_RESULT_OK) {
      goto cleanup;
    }
    rustls_server_config_builder_set_client_verifier(config_builder,
                                                     client_cert_verifier);
  }

  if(getenv("SSLKEYLOGFILE")) {
    const rustls_result rr =
      rustls_server_config_builder_set_key_log_file(config_builder);
    if(rr != RUSTLS_RESULT_OK) {
      print_error("enabling keylog", rr);
      goto cleanup;
    }
  }
  else if(getenv("STDERRKEYLOG")) {
    const rustls_result rr = rustls_server_config_builder_set_key_log(
      config_builder, stderr_key_log_cb, NULL);
    if(rr != RUSTLS_RESULT_OK) {
      print_error("enabling keylog", rr);
      goto cleanup;
    }
  }

  rustls_result rr =
    rustls_server_config_builder_build(config_builder, &server_config);
  if(rr != RUSTLS_RESULT_OK) {
    print_error("building server config", rr);
    goto cleanup;
  }

#ifdef _WIN32
  WSADATA wsa;
  WSAStartup(MAKEWORD(1, 1), &wsa);
#endif

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if(sockfd < 0) {
    LOG("making socket: %s", strerror(errno));
    goto cleanup;
  }

  const int enable = 1;
  if(setsockopt(
       sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&enable, sizeof(int)) <
     0) {
    print_error("setsockopt(SO_REUSEADDR) failed", 7001);
  }

  struct sockaddr_in my_addr = { 0 }, peer_addr;
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
    socklen_t peer_addr_size = sizeof(struct sockaddr_in);
    const int clientfd =
      accept(sockfd, (struct sockaddr *)&peer_addr, &peer_addr_size);
    if(shutting_down) {
      break;
    }
    if(clientfd < 0) {
      perror("server: accept");
      goto cleanup;
    }

    nonblock(clientfd);

    rr = rustls_server_connection_new(server_config, &rconn);
    if(rr != RUSTLS_RESULT_OK) {
      print_error("making session", rr);
      goto cleanup;
    }

    conndata *conndata = calloc(1, sizeof(struct conndata));
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
