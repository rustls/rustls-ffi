#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#include "lib.h"

/*
 * Write n bytes from buf to the provided fd, retrying short writes until
 * we finish or hit an error. Assumes fd is blocking and therefore doesn't
 * handle EAGAIN.
 */
void
write_all(int fd, const char *buf, int n)
{
  int m = 0;
  while(n > 0) {
    m = write(fd, buf, n);
    if(m < 0) {
      perror("writing to stdout");
      exit(1);
    }
    if(m == 0) {
      fprintf(stderr, "early EOF when writing to stdout\n");
      exit(1);
    }
    n -= m;
  }
}

/*
 * Connect to the given hostname on port 443 and return the file descriptor of
 * the socket. On error, print the error and return -1. Caller is responsible
 * for closing socket.
 */
int
make_conn(const char *hostname)
{
  struct addrinfo *getaddrinfo_output, *rp;
  int getaddrinfo_result =
    getaddrinfo(hostname, "443", NULL, &getaddrinfo_output);
  if(getaddrinfo_result != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(getaddrinfo_result));
    return -1;
  }

  int sockfd = socket(getaddrinfo_output->ai_family,
                      getaddrinfo_output->ai_socktype,
                      getaddrinfo_output->ai_protocol);
  if(sockfd < 0) {
    perror("making socket");
    return -1;
  }

  int connect_result = connect(
    sockfd, getaddrinfo_output->ai_addr, getaddrinfo_output->ai_addrlen);
  if(connect_result < 0) {
    perror("connecting");
    return -1;
  }
  freeaddrinfo(getaddrinfo_output);
  return sockfd;
}

/*
 * Given an established TCP connection, and a rustls client_session, send an
 * HTTP request and read the response. On success, return 0. On error, print
 * the message and return 1.
 */
int
send_request_and_read_response(int sockfd, void *client_session,
                               const char *hostname, const char *path)
{
  char buf[2048];

  memset(buf, '0', sizeof(buf));
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
  int n = rustls_client_session_write(client_session, buf, strlen(buf));
  if(n < 0) {
    fprintf(stderr, "error writing plaintext bytes to ClientSession\n");
  }

#define MAX_EVENTS 1
  struct epoll_event ev, events[MAX_EVENTS];
  int conn_sock, nfds, epollfd;

  epollfd = epoll_create1(0);
  if(epollfd == -1) {
    perror("epoll_create1");
    return 1;
  }

  ev.events = EPOLLIN | EPOLLOUT;
  ev.data.fd = sockfd;
  if(epoll_ctl(epollfd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
    perror("epoll_ctl: listen_sock");
    return 1;
  }

  for(;;) {
    nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
    if(nfds == -1) {
      perror("epoll_wait");
      exit(EXIT_FAILURE);
    }

    if(rustls_client_session_wants_read(client_session) &&
       (events[0].events & EPOLLIN) > 0) {
      fprintf(stderr,
              "ClientSession wants us to read_tls. First we need to pull some "
              "bytes from the socket\n");

      memset(buf, 0, sizeof(buf));
      n = read(sockfd, buf, sizeof(buf));
      if(n == 0) {
        fprintf(stderr, "EOF reading from socket\n");
        break;
      }
      else if(n < 0) {
        perror("reading from socket");
        return 1;
      }
      fprintf(stderr, "read %d bytes from socket\n", n);

      /*
       * Now pull those bytes from the buffer into ClientSession.
       * Note that we pass buf, n; not buf, sizeof(buf). We don't
       * want to pull in unitialized memory that we didn't just
       * read from the socket.
       */
      n = rustls_client_session_read_tls(client_session, buf, n);
      if(n == 0) {
        fprintf(stderr, "EOF from ClientSession::read_tls\n");
        // TODO: What to do here?
        break;
      }
      else if(n < 0) {
        fprintf(stderr, "Error in ClientSession::read_tls\n");
        return 1;
      }

      int result = rustls_client_session_process_new_packets(client_session);
      if(result != CRUSTLS_OK) {
        fprintf(stderr, "Error in process_new_packets");
        return 1;
      }

      /* Read all available bytes from the client_session until EOF.
       * Note that EOF here indicates "no more bytes until
       * process_new_packets", not "stream is closed".
       */
      for(;;) {
        memset(buf, 0, sizeof(buf));
        n = rustls_client_session_read(client_session, buf, sizeof(buf));
        if(n == 0) {
          fprintf(stderr, "EOF from ClientSession::read (this is expected)\n");
          break;
        }
        else if(n < 0) {
          fprintf(stderr, "Error in ClientSession::read\n");
          return 1;
        }

        write_all(STDOUT_FILENO, buf, n);
      }
    }
    if(rustls_client_session_wants_write(client_session) &&
       (events[0].events & EPOLLOUT) > 0) {
      fprintf(stderr, "ClientSession wants us to write_tls.\n");
      memset(buf, 0, sizeof(buf));
      n = rustls_client_session_write_tls(client_session, buf, sizeof(buf));
      if(n == 0) {
        fprintf(stderr, "EOF from ClientSession::write_tls\n");
        return 1;
      }
      else if(n < 0) {
        fprintf(stderr, "Error in ClientSession::write_tls\n");
        return 1;
      }

      write_all(sockfd, buf, n);
    }
  }

  return 0;
}

int
main(int argc, const char **argv)
{
  if(argc <= 2) {
    fprintf(stderr,
            "usage: %s hostname path\n\n"
            "Connect to a host via HTTPS on port 443, make a request for the\n"
            "given path, and emit response to stdout.\n",
            argv[0]);
    return 1;
  }
  const char *hostname = argv[1];
  const char *path = argv[2];

  rustls_init();

  int sockfd = make_conn(hostname);
  if(sockfd < 0) {
    // No perror because make_conn printed error already.
    return 1;
  }

  void *client_session = NULL;
  int result = rustls_client_session_new(hostname, &client_session);
  if(result != CRUSTLS_OK) {
    return 1;
  }

  int return_code =
    send_request_and_read_response(sockfd, client_session, hostname, path);
  rustls_client_session_free(client_session);
  return return_code;
}
