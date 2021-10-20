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
#endif /* _WIN32 */

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>

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
#endif /* !STDOUT_FILENO */
#endif /* _WIN32 */

/* crustls.h is autogenerated in the Makefile using cbindgen. */
#include "crustls.h"
#include "common.h"

enum crustls_demo_result
read_file(const char *filename, char *buf, size_t buflen, size_t *n)
{
  FILE *f = fopen(filename, "r");
  if(f == NULL) {
    fprintf(stderr, "%s\n", strerror(errno));
    return CRUSTLS_DEMO_ERROR;
  }
  *n = fread(buf, 1, buflen, f);
  if(!feof(f)) {
    fprintf(stderr, "%s\n", strerror(errno));
    fclose(f);
    return CRUSTLS_DEMO_ERROR;
  }
  fclose(f);
  return CRUSTLS_DEMO_OK;
}

typedef enum exchange_state
{
  READING_REQUEST,
  SENT_RESPONSE
} exchange_state;

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

  if(n == 0) {
    return CRUSTLS_DEMO_EOF;
  }
  fprintf(stderr, "read %ld bytes from socket\n", n);

  result = rustls_connection_process_new_packets(rconn);
  if(result != RUSTLS_RESULT_OK) {
    print_error("in process_new_packets", result);
    return CRUSTLS_DEMO_ERROR;
  }

  result = copy_plaintext_to_buffer(conn);
  if(result != CRUSTLS_DEMO_EOF) {
    fprintf(stderr, "do_read returning %d\n", result);
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

enum crustls_demo_result
send_response(struct conndata *conn)
{
  struct rustls_connection *rconn = conn->rconn;
  const char *prefix = "HTTP/1.1 200 OK\r\nContent-Length:";
  const int body_size = 10000;
  const int response_size = strlen(prefix) + 15 + body_size;
  char *response = malloc(response_size);
  size_t n;

  if(response == NULL) {
    fprintf(stderr, "failed malloc\n");
    return CRUSTLS_DEMO_ERROR;
  }

  n = sprintf(response, "%s %d\r\n\r\n", prefix, body_size);
  memset(response + n, 'a', body_size);
  *(response + n + body_size + 1) = '\0';
  fprintf(stderr, "strlen response %ld\n", strlen(response));

  rustls_connection_write(
    rconn, (const uint8_t *)response, strlen(response), &n);
  if(n != strlen(response)) {
    fprintf(stderr, "failed to write all response bytes. wrote %ld\n", n);
    return CRUSTLS_DEMO_ERROR;
  }
  return CRUSTLS_DEMO_OK;
}

void
handle_conn(struct conndata *conn)
{
  int err = 1;
  int result = 1;
  fd_set read_fds;
  fd_set write_fds;
  size_t n = 0;
  struct rustls_connection *rconn = conn->rconn;
  int sockfd = conn->fd;
  struct timeval tv;
  enum exchange_state state = READING_REQUEST;

  fprintf(stderr, "accepted conn on fd %d\n", conn->fd);

  for(;;) {
    FD_ZERO(&read_fds);
    if(rustls_connection_wants_read(rconn)) {
      FD_SET(sockfd, &read_fds);
    }
    FD_ZERO(&write_fds);
    if(rustls_connection_wants_write(rconn)) {
      FD_SET(sockfd, &write_fds);
    }

    if(!rustls_connection_wants_read(rconn) && !rustls_connection_wants_write(rconn)) {
      fprintf(stderr, "rustls wants neither read nor write. closing connection\n");
      goto cleanup;
    }

    tv.tv_sec = 1;
    tv.tv_usec = 0;

    result = select(sockfd + 1, &read_fds, &write_fds, NULL, &tv);
    if(result == -1) {
      perror("select");
      goto cleanup;
    }
    if(result == 0) {
      fprintf(stderr, "no fds from select, looping\n");
      continue;
    }

    if(FD_ISSET(sockfd, &read_fds)) {
      fprintf(stderr,
              "rustls wants us to read_tls. First we need to pull some "
              "bytes from the socket\n");

      /* Read all bytes until we get EAGAIN. Then loop again to wind up in
         select awaiting the next bit of data. */
      for(;;) {
        result = do_read(conn, rconn);
        if(result == CRUSTLS_DEMO_AGAIN) {
          break;
        }
        else if(result == CRUSTLS_DEMO_EOF) {
          goto cleanup;
        }
        else if(result != CRUSTLS_DEMO_OK) {
          goto cleanup;
        }
      }
    }
    if(FD_ISSET(sockfd, &write_fds)) {
      fprintf(stderr, "rustls wants us to write_tls.\n");
      err = write_tls(rconn, conn, &n);
      if(err != 0) {
        fprintf(stderr, "Error in write_tls: errno %d\n", err);
        goto cleanup;
      }
      else if(n == 0) {
        fprintf(stderr, "EOF from write_tls\n");
        goto cleanup;
      }
    }

    if(state == READING_REQUEST && body_beginning(&conn->data) != NULL) {
      state = SENT_RESPONSE;
      fprintf(stderr, "writing response\n");
      if(send_response(conn) != CRUSTLS_DEMO_OK) {
        goto cleanup;
      };
    }
  }

  fprintf(stderr, "handle_conn: loop fell through");

cleanup:
  fprintf(stderr, "closing socket %d\n", sockfd);
  if(sockfd > 0) {
    close(sockfd);
  }
  free(conn);
}

const struct rustls_certified_key *
load_cert_and_key(const char *certfile, const char *keyfile)
{
  char certbuf[10000];
  size_t certbuf_len;
  char keybuf[10000];
  size_t keybuf_len;

  int result = read_file(certfile, certbuf, sizeof(certbuf), &certbuf_len);
  if(result != CRUSTLS_DEMO_OK) {
    return NULL;
  }

  result = read_file(keyfile, keybuf, sizeof(keybuf), &keybuf_len);
  if(result != CRUSTLS_DEMO_OK) {
    return NULL;
  }

  const struct rustls_certified_key *certified_key;
  result = rustls_certified_key_build((uint8_t *)certbuf,
                                      certbuf_len,
                                      (uint8_t *)keybuf,
                                      keybuf_len,
                                      &certified_key);
  if(result != RUSTLS_RESULT_OK) {
    print_error("parsing certificate and key", result);
    return NULL;
  }
  return certified_key;
}

int
main(int argc, const char **argv)
{
  int ret = 1;
  int result = 1;
  int sockfd = 0;
  struct rustls_server_config_builder_wants_verifier *config_builder =
    rustls_server_config_builder_new_with_safe_defaults();
  struct rustls_server_config_builder *config_builder2 = NULL;
  const struct rustls_server_config *server_config = NULL;
  struct rustls_connection *rconn = NULL;

  config_builder2 = rustls_server_config_builder_with_no_client_auth(config_builder);
  if(config_builder2 == NULL) {
    goto cleanup;
  }

  if(argc <= 2) {
    fprintf(stderr,
            "usage: %s cert.pem key.pem\n\n"
            "Listen on port 8443 with the given cert and key.\n",
            argv[0]);
    goto cleanup;
  }

  const struct rustls_certified_key *certified_key =
    load_cert_and_key(argv[1], argv[2]);
  if(certified_key == NULL) {
    goto cleanup;
  }

  rustls_server_config_builder_set_certified_keys(
    config_builder2, &certified_key, 1);
  server_config = rustls_server_config_builder_build(config_builder2);

#ifdef _WIN32
  WSADATA wsa;
  WSAStartup(MAKEWORD(1, 1), &wsa);
#endif

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if(sockfd < 0) {
    fprintf(stderr, "making socket: %s", strerror(errno));
  }

  int enable = 1;
  if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
    print_error("setsockopt(SO_REUSEADDR) failed", 7001);
  }

  struct sockaddr_in my_addr, peer_addr;
  memset(&my_addr, 0, sizeof(struct sockaddr_in));
  /* Clear structure */
  my_addr.sin_family = AF_INET;
  my_addr.sin_addr.s_addr = INADDR_ANY;
  my_addr.sin_port = htons(8443);
  inet_aton("127.0.0.1", &my_addr.sin_addr);

  if(bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr_in)) ==
     -1) {
    perror("bind");
    goto cleanup;
  }

  if(listen(sockfd, 50) == -1) {
    perror("listen");
    goto cleanup;
  }
  fprintf(stderr, "listening on localhost:8443\n");

  while(true) {
    socklen_t peer_addr_size;
    peer_addr_size = sizeof(struct sockaddr_in);
    int clientfd =
      accept(sockfd, (struct sockaddr *)&peer_addr, &peer_addr_size);
    if(clientfd < 0) {
      perror("accept");
      goto cleanup;
    }

    nonblock(clientfd);

    result = rustls_server_connection_new(server_config, &rconn);
    if(result != RUSTLS_RESULT_OK) {
      print_error("making session", result);
      goto cleanup;
    }

    struct conndata *conndata;
    conndata = calloc(1, sizeof(struct conndata));
    conndata->fd = clientfd;
    conndata->rconn = rconn;
    handle_conn(conndata);
  }

  // Success!
  ret = 0;

cleanup:
  rustls_server_config_free(server_config);
  rustls_connection_free(rconn);
  if(sockfd>0) {
    close(sockfd);
  }

#ifdef _WIN32
  WSACleanup();
#endif

  return ret;
}
