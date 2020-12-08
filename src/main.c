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

extern int new_client_session(const char *hostname, void **client_session);
extern void drop_client_session(void *client_session);

int
main(void)
{
  int sockfd = 0, n = 0, m = 0, result = 0;
  char buf[1024];
  struct sockaddr_in serv_addr;
  void *client_session = NULL;

  init_rustls();
  printf("gonna make a client session. current value %p\n", client_session);
  result = new_client_session("localhost", &client_session);
  if(result != 0) {
    return 1;
  }
  printf("successfully made a client session. current value %p\n",
         client_session);

  memset(buf, '0', sizeof(buf));
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if(sockfd < 0) {
    perror("Could not create socket");
    return 1;
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(4444);
  serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

  result = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
  if(result < 0) {
    perror("connecting");
    return 1;
  }

  while(1) {
    n = read(sockfd, buf, sizeof(buf) - 1);
    if(n == 0) {
      // EOF
      break;
    }
    else if(n < 0) {
      perror("reading bytes");
      return 1;
    }
    buf[n] = 0;

    while(n > 0) {
      m = write(STDOUT_FILENO, buf, n);
      if(m < 0) {
        perror("writing to stdout");
        return 1;
      }
      if(m == 0) {
        fprintf(stderr, "early EOF when writing to stdout\n");
        return 1;
      }
      n -= m;
    }
  }

  printf("gonna drop it! %p\n", client_session);
  drop_client_session(client_session);
  return 0;
}
