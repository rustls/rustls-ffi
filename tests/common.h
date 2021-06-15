#ifndef COMMON_H
#define COMMON_H

enum crustls_demo_result
{
  CRUSTLS_DEMO_OK,
  CRUSTLS_DEMO_ERROR,
  CRUSTLS_DEMO_AGAIN,
  CRUSTLS_DEMO_EOF,
  CRUSTLS_DEMO_CLOSE_NOTIFY,
};

/* A growable vector of bytes. */
typedef struct bytevec {
  char *data;
  size_t len;
  size_t capacity;
} bytevec;

typedef struct conndata_t {
  int fd;
  const char *verify_arg;
  struct bytevec data;
  struct rustls_connection *rconn;
} conndata_t;

void
print_error(char *prefix, rustls_result result);

int
write_all(int fd, const char *buf, int n);

/* Make a socket nonblocking. */
enum crustls_demo_result
nonblock(int sockfd);

/* A callback that reads bytes from the network. */
int
read_cb(void *userdata, uint8_t *buf, uintptr_t len, uintptr_t *out_n);

/* A callback that reads bytes from the network. */
int
write_cb(void *userdata, const uint8_t *buf, uintptr_t len, uintptr_t *out_n);

/* Number of bytes available for writing. */
size_t
bytevec_available(struct bytevec *vec);

/* Pointer to the writeable region. */
char *
bytevec_writeable(struct bytevec *vec);

/* Indicate that n bytes have been written, increasing len. */
void
bytevec_consume(struct bytevec *vec, size_t n);

/* Ensure there are at least n bytes available between vec->len and
 * vec->capacity. If this requires reallocating, this may return
 * CRUSTLS_DEMO_ERROR. */
enum crustls_demo_result
bytevec_ensure_available(struct bytevec *vec, size_t n);

/* Read all available bytes from the rustls_connection until EOF.
 * Note that EOF here indicates "no more bytes until
 * process_new_packets", not "stream is closed".
 *
 * Returns CRUSTLS_DEMO_OK for success,
 * CRUSTLS_DEMO_ERROR for error,
 * CRUSTLS_DEMO_CLOSE_NOTIFY for "received close_notify"
 */
int
copy_plaintext_to_buffer(struct conndata_t *conn);

/* Polyfill */
const void *memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen);

/* If headers are done (received \r\n\r\n), return a pointer to the beginning
 * of the body. Otherwise return NULL.
 */
char *
body_begin(struct bytevec *vec);

/* If any header matching the provided name (NUL-terminated) exists, return
 * a pointer to the beginning of the value for the first such occurrence
 * and store the length of the header in n.
 * If no such header exists, return NULL and don't modify n.
 * The returned pointer will be borrowed from `headers`.
 */
const char *
get_first_header_value(const char *headers, size_t headers_len, const char *name, size_t *n);

#endif /* COMMON_H */
