#ifndef COMMON_H
#define COMMON_H

#ifdef _WIN32
#define sleep(s) Sleep(1000 * (s))
#define read(s, buf, n) recv(s, buf, n, 0)
#define close(s) closesocket(s)

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

#if defined(_MSC_VER)
#define STRTOK_R strtok_s
#else
#define STRTOK_R strtok_r
#endif

typedef enum demo_result
{
  DEMO_OK,
  DEMO_ERROR,
  DEMO_AGAIN,
  DEMO_EOF,
} demo_result;

/* A growable vector of bytes. */
typedef struct bytevec
{
  char *data;
  size_t len;
  size_t capacity;
} bytevec;

typedef struct conndata
{
  int fd;
  const char *verify_arg;
  bytevec data;
  rustls_connection *rconn;
} conndata;

extern const char *programname;

/* Log a formatted message prefixed with `<programname>[<pid>]: "` */
#define LOG(f_, ...)                                                          \
  fprintf(                                                                    \
    stderr, "%s[%ld]: " f_ "\n", programname, (long)getpid(), __VA_ARGS__)
/* Since the `...` / __VA_ARGS__ technique requires at least one arg,
 * we have a special case for when there are no formatting parameters. */
#define LOG_SIMPLE(s) LOG("%s", s)

void print_error(const char *prefix, rustls_result rr);

/* Make a socket nonblocking. */
demo_result nonblock(int sockfd);

/* A callback that reads bytes from the network. */
int read_cb(void *userdata, uint8_t *buf, uintptr_t len, uintptr_t *out_n);

/* A callback that writes bytes to the network. */
int write_cb(void *userdata, const uint8_t *buf, uintptr_t len,
             uintptr_t *out_n);

#ifndef _WIN32
rustls_io_result write_vectored_cb(void *userdata, const rustls_iovec *iov,
                                   size_t count, size_t *out_n);
#endif /* _WIN32 */

/* Number of bytes available for writing. */
size_t bytevec_available(const bytevec *vec);

/* Pointer to the writeable region. */
char *bytevec_writeable(const bytevec *vec);

/* Indicate that n bytes have been written, increasing len. */
void bytevec_consume(bytevec *vec, size_t n);

/* Ensure there are at least n bytes available between vec->len and
 * vec->capacity. If this requires reallocating, this may return
 * DEMO_ERROR. */
demo_result bytevec_ensure_available(bytevec *vec, size_t n);

/* Read all available bytes from the rustls_connection until EOF.
 * Note that EOF here indicates "no more bytes until
 * process_new_packets", not "stream is closed".
 *
 * Returns DEMO_OK for success,
 * DEMO_ERROR for error,
 * DEMO_EOF for "connection cleanly terminated by peer"
 */
demo_result copy_plaintext_to_buffer(conndata *conn);

/* Polyfill */
void *memmem(const void *haystack, size_t haystacklen, const void *needle,
             size_t needlelen);

void log_cb(void *userdata, const rustls_log_params *params);

demo_result read_file(const char *filename, char *buf, size_t buflen,
                      size_t *n);

const rustls_certified_key *load_cert_and_key(const char *certfile,
                                              const char *keyfile);

const rustls_crypto_provider *default_provider_with_custom_ciphersuite(
  const char *custom_ciphersuite_name);

void stderr_key_log_cb(rustls_str label, const unsigned char *client_random,
                       size_t client_random_len, const unsigned char *secret,
                       size_t secret_len);

/*
 * Log information about the rustls_connection to stderr.
 *
 * This includes the handshake type (full vs resumed), the negotiated
 * ciphersuite, and the key exchange algorithm.
 */
void log_connection_info(const rustls_connection *rconn);

extern const uint16_t default_tls_versions[];
extern const size_t default_tls_versions_len;

#endif /* COMMON_H */
