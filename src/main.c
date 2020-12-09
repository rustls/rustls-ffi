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

int
main(void)
{
  int sockfd = 0, n = 0, m = 0, result = 0;
  char buf[2048];
  struct sockaddr_in serv_addr;
  const void *client_session = NULL;

  rustls_init();
  result = rustls_client_session_new("localhost", &client_session);
  if(result != CRUSTLS_OK) {
    return 1;
  }

  memset(buf, '0', sizeof(buf));
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if(sockfd < 0) {
    perror("Could not create socket");
    return 1;
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(443);
  //   serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  serv_addr.sin_addr.s_addr = inet_addr("93.184.216.34");

  result = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
  if(result < 0) {
    perror("connecting");
    return 1;
  }

  const char *request = "GET / HTTP/1.1\r\n\r\n";
  n = rustls_client_session_write(client_session, request, strlen(request));
  if(n < 0) {
    fprintf(stderr, "error writing plaintext bytes to ClientSession\n");
  }

  while(1) {
    if(rustls_client_session_wants_read(client_session)) {
      fprintf(stderr,
              "ClientSession wants us to read_tls. First we need to pull some "
              "bytes from the socket\n");

      memset(buf, 0, sizeof(buf));
      n = read(sockfd, buf, sizeof(buf));
      if(n == 0) {
        // EOF
        fprintf(stderr, "EOF reading from socket\n");
        break;
      }
      else if(n < 0) {
        perror("reading from socket");
        return 1;
      }
      fprintf(stderr, "read %d bytes from socket\n", n);

      // Now pull those bytes from the buffer into ClientSession.
      // Note that we pass buf, n; not buf, sizeof(buf). We don't
      // want to pull in unitialized memory that we didn't just
      // read from the socket.
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

      result = rustls_client_session_process_new_packets(client_session);
      if(result != CRUSTLS_OK) {
        fprintf(stderr, "Error in process_new_packets");
        return 1;
      }

      memset(buf, 0, sizeof(buf));
      n = rustls_client_session_read(client_session, buf, sizeof(buf));
      if(n == 0) {
        fprintf(stderr, "EOF from ClientSession::read\n");
        // TODO: What to do?
        break;
      }
      else if(n < 0) {
        fprintf(stderr, "Error in ClientSession::read\n");
        return 1;
      }

      write_all(STDOUT_FILENO, buf, n);
    }
    if(rustls_client_session_wants_write(client_session)) {
      fprintf(stderr, "ClientSession wants us to write_tls.\n");
      memset(buf, 0, sizeof(buf));
      n = rustls_client_session_write_tls(client_session, buf, sizeof(buf));
      if(n == 0) {
        fprintf(stderr, "EOF from ClientSession::write_tls\n");
        // TODO: What to do?
        break;
      }
      else if(n < 0) {
        fprintf(stderr, "Error in ClientSession::write_tls\n");
        return 1;
      }

      write_all(sockfd, buf, n);
    }
  }

  rustls_client_session_drop(client_session);
  return 0;
}
