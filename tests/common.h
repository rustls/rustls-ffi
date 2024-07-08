#ifndef COMMON_H
#define COMMON_H

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
const char *ws_strerror(int err);
#define strerror(e) ws_strerror(e)
#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1 /* MinGW has this */
#endif /* !STDOUT_FILENO */
#endif /* _WIN32 */

enum demo_result
{
  DEMO_OK,
  DEMO_ERROR,
  DEMO_AGAIN,
  DEMO_EOF,
};

/* A growable vector of bytes. */
struct bytevec
{
  char *data;
  size_t len;
  size_t capacity;
};

struct conndata
{
  int fd;
  const char *verify_arg;
  struct bytevec data;
  struct rustls_connection *rconn;
};

extern const char *programname;

/* Log a formatted message prefixed with `<programname>[<pid>]: "` */
#define LOG(f_, ...)                                                          \
  fprintf(                                                                    \
    stderr, "%s[%ld]: " f_ "\n", programname, (long)getpid(), __VA_ARGS__)
/* Since the `...` / __VA_ARGS__ technique requires at least one arg,
 * we have a special case for when there are no formatting parameters. */
#define LOG_SIMPLE(s) LOG("%s", s)

void print_error(const char *prefix, rustls_result result);

int write_all(int fd, const char *buf, int n);

/* Make a socket nonblocking. */
enum demo_result nonblock(int sockfd);

/* A callback that reads bytes from the network. */
int read_cb(void *userdata, uint8_t *buf, uintptr_t len, uintptr_t *out_n);

/* Invoke rustls_connection_write_tls with either a vectored or unvectored
   callback, depending on environment variable. */
rustls_io_result write_tls(struct rustls_connection *rconn,
                           struct conndata *conn, size_t *n);

/* A callback that writes bytes to the network. */
int write_cb(void *userdata, const uint8_t *buf, uintptr_t len,
             uintptr_t *out_n);

#ifndef _WIN32
rustls_io_result write_vectored_cb(void *userdata,
                                   const struct rustls_iovec *iov,
                                   size_t count, size_t *out_n);
#endif /* _WIN32 */

/* Number of bytes available for writing. */
size_t bytevec_available(struct bytevec *vec);

/* Pointer to the writeable region. */
char *bytevec_writeable(struct bytevec *vec);

/* Indicate that n bytes have been written, increasing len. */
void bytevec_consume(struct bytevec *vec, size_t n);

/* Ensure there are at least n bytes available between vec->len and
 * vec->capacity. If this requires reallocating, this may return
 * DEMO_ERROR. */
enum demo_result bytevec_ensure_available(struct bytevec *vec, size_t n);

/* Read all available bytes from the rustls_connection until EOF.
 * Note that EOF here indicates "no more bytes until
 * process_new_packets", not "stream is closed".
 *
 * Returns DEMO_OK for success,
 * DEMO_ERROR for error,
 * DEMO_EOF for "connection cleanly terminated by peer"
 */
int copy_plaintext_to_buffer(struct conndata *conn);

/* Polyfill */
void *memmem(const void *haystack, size_t haystacklen, const void *needle,
             size_t needlelen);

/* If headers are done (received \r\n\r\n), return a pointer to the beginning
 * of the body. Otherwise return NULL.
 */
char *body_beginning(struct bytevec *vec);

/* If any header matching the provided name (NUL-terminated) exists, return
 * a pointer to the beginning of the value for the first such occurrence
 * and store the length of the header in n.
 * If no such header exists, return NULL and don't modify n.
 * The returned pointer will be borrowed from `headers`.
 */
const char *get_first_header_value(const char *headers, size_t headers_len,
                                   const char *name, size_t name_len,
                                   size_t *n);

void log_cb(void *userdata, const struct rustls_log_params *params);

enum demo_result read_file(const char *filename, char *buf, size_t buflen,
                           size_t *n);

const struct rustls_certified_key *load_cert_and_key(const char *certfile,
                                                     const char *keyfile);

const struct rustls_crypto_provider *default_provider_with_custom_ciphersuite(
  const char *custom_ciphersuite_name);

extern const uint16_t default_tls_versions[];
extern const size_t default_tls_versions_len;

#endif /* COMMON_H */
