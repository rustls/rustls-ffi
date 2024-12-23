#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h> /* gai_strerror() */
#include <io.h> /* write() */
#include <fcntl.h> /* O_BINARY */
#define strncasecmp _strnicmp
#else
#include <sys/socket.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "rustls.h"
#include "common.h"

/* Set by client.c's and server.c's main() */
const char *programname;

void
print_error(const char *prefix, const rustls_result rr)
{
  char buf[256];
  size_t n;
  rustls_error(rr, buf, sizeof(buf), &n);
  LOG("%s: %.*s", prefix, (int)n, buf);
}

#ifdef _WIN32
const char *
ws_strerror(int err)
{
  static char ws_err[50];

  if(err >= WSABASEERR) {
    snprintf(ws_err, sizeof(ws_err), "Winsock err: %d", err);
    return ws_err;
  }
  /* Assume a CRT error */
  return (strerror)(err);
}
#endif

/*
 * Set a socket to be nonblocking.
 *
 * Returns DEMO_OK on success, DEMO_ERROR on error.
 */
demo_result
nonblock(int sockfd)
{
#ifdef _WIN32
  u_long nonblock = 1UL;

  if(ioctlsocket(sockfd, FIONBIO, &nonblock) != 0) {
    perror("Error setting socket nonblocking");
    return DEMO_ERROR;
  }
#else
  int flags = fcntl(sockfd, F_GETFL, 0);
  if(flags < 0) {
    perror("getting socket flags");
    return DEMO_ERROR;
  }
  flags = fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
  if(flags < 0) {
    perror("setting socket nonblocking");
    return DEMO_ERROR;
  }
#endif
  return DEMO_OK;
}

int
read_cb(void *userdata, unsigned char *buf, const size_t len, size_t *out_n)
{
  const conndata *conn = (struct conndata *)userdata;
  const ssize_t n = recv(conn->fd, buf, len, 0);
  if(n < 0) {
    return errno;
  }
  if(out_n != NULL) {
    *out_n = n;
  }
  return 0;
}

int
write_cb(void *userdata, const unsigned char *buf, const size_t len,
         size_t *out_n)
{
  const conndata *conn = (struct conndata *)userdata;

  const ssize_t n = send(conn->fd, buf, len, 0);
  if(n < 0) {
    return errno;
  }
  if(out_n != NULL) {
    *out_n = n;
  }
  return 0;
}

#ifndef _WIN32
rustls_io_result
write_vectored_cb(void *userdata, const rustls_iovec *iov, size_t count,
                  size_t *out_n)
{
  const conndata *conn = (struct conndata *)userdata;

  // safety: narrowing conversion from `size_t count` to `int` is safe because
  // writev return -1 and sets errno to EINVAL on out of range input (<0 || >
  // IOV_MAX).
  const ssize_t n = writev(conn->fd, (const struct iovec *)iov, (int)count);
  if(n < 0) {
    return errno;
  }
  *out_n = n;
  return 0;
}
#endif /* _WIN32 */

size_t
bytevec_available(const bytevec *vec)
{
  return vec->capacity - vec->len;
}

char *
bytevec_writeable(const bytevec *vec)
{
  return vec->data + vec->len;
}

void
bytevec_consume(bytevec *vec, const size_t n)
{
  vec->len += n;
}

// Ensure there are at least n bytes available between vec->len and
// vec->capacity. If this requires reallocating, this may return
// DEMO_ERROR.
demo_result
bytevec_ensure_available(bytevec *vec, const size_t n)
{
  const size_t available = vec->capacity - vec->len;
  if(available < n) {
    size_t newsize = vec->len + n;
    if(newsize < vec->capacity * 2) {
      newsize = vec->capacity * 2;
    }
    void *newdata = realloc(vec->data, newsize);
    if(newdata == NULL) {
      LOG("out of memory trying to get %zu bytes", newsize);
      return DEMO_ERROR;
    }
    vec->data = newdata;
    vec->capacity = newsize;
  }
  return DEMO_OK;
}

/**
 * Copy all available plaintext from rustls into our own buffer, growing
 * our buffer as much as needed.
 */
demo_result
copy_plaintext_to_buffer(conndata *conn)
{
  size_t n;
  rustls_connection *rconn = conn->rconn;

  if(bytevec_ensure_available(&conn->data, 1024) != DEMO_OK) {
    return DEMO_ERROR;
  }

  for(;;) {
    char *buf = bytevec_writeable(&conn->data);
    const size_t avail = bytevec_available(&conn->data);
    const rustls_result rr =
      rustls_connection_read(rconn, (uint8_t *)buf, avail, &n);
    if(rr == RUSTLS_RESULT_PLAINTEXT_EMPTY) {
      /* This is expected. It just means "no more bytes for now." */
      return DEMO_OK;
    }
    if(rr != RUSTLS_RESULT_OK) {
      print_error("error in rustls_connection_read", rr);
      return DEMO_ERROR;
    }
    if(n == 0) {
      LOG_SIMPLE("got 0-byte read, cleanly ending connection");
      return DEMO_EOF;
    }
    bytevec_consume(&conn->data, n);
    if(bytevec_ensure_available(&conn->data, 1024) != DEMO_OK) {
      return DEMO_ERROR;
    }
  }
}

/**
 * Since memmem is not cross-platform compatible, we bring our own.
 * Copied from https://www.capitalware.com/rl_blog/?p=5847.
 *
 * Function Name
 *  memmem
 *
 * Description
 *  Like strstr(), but for non-text buffers that are not NULL delimited.
 *
 *  public domain by Bob Stout
 *
 * Input parameters
 *  haystack    - pointer to the buffer to be searched
 *  haystacklen - length of the haystack buffer
 *  needle      - pointer to a buffer that will be searched for
 *  needlelen   - length of the needle buffer
 *
 * Return Value
 *  pointer to the memory address of the match or NULL.
 */
void *
memmem(const void *haystack, size_t haystacklen, const void *needle,
       size_t needlelen)
{
  const char *bf = haystack;
  const char *pt = needle;
  const char *p = bf;

  while(needlelen <= (haystacklen - (p - bf))) {
    p = memchr(p, (int)(*pt), haystacklen - (p - bf));
    if(NULL != p) {
      if(0 == memcmp(p, needle, needlelen)) {
        return (void *)p;
      }
      ++p;
    }
    else {
      break;
    }
  }

  return NULL;
}

void
log_cb(void *userdata, const rustls_log_params *params)
{
  const conndata *conn = (struct conndata *)userdata;
  const rustls_str level_str = rustls_log_level_str(params->level);
  LOG("[fd %d][%.*s]: %.*s",
      conn->fd,
      (int)level_str.len,
      level_str.data,
      (int)params->message.len,
      params->message.data);
}

demo_result
read_file(const char *filename, char *buf, const size_t buflen, size_t *n)
{
  FILE *f = fopen(filename, "r");
  if(f == NULL) {
    LOG("opening %s: %s", filename, strerror(errno));
    return DEMO_ERROR;
  }
  *n = fread(buf, 1, buflen, f);
  if(!feof(f)) {
    LOG("reading %s: %s", filename, strerror(errno));
    fclose(f);
    return DEMO_ERROR;
  }
  fclose(f);
  return DEMO_OK;
}

const rustls_certified_key *
load_cert_and_key(const char *certfile, const char *keyfile)
{
  char certbuf[10000];
  size_t certbuf_len;
  char keybuf[10000];
  size_t keybuf_len;

  demo_result dr = read_file(certfile, certbuf, sizeof(certbuf), &certbuf_len);
  if(dr != DEMO_OK) {
    return NULL;
  }

  dr = read_file(keyfile, keybuf, sizeof(keybuf), &keybuf_len);
  if(dr != DEMO_OK) {
    return NULL;
  }

  const rustls_certified_key *certified_key;
  rustls_result rr = rustls_certified_key_build((uint8_t *)certbuf,
                                                certbuf_len,
                                                (uint8_t *)keybuf,
                                                keybuf_len,
                                                &certified_key);
  if(rr != RUSTLS_RESULT_OK) {
    print_error("parsing certificate and key", rr);
    return NULL;
  }

  rr = rustls_certified_key_keys_match(certified_key);
  if(rr != RUSTLS_RESULT_OK) {
    LOG("private key %s does not match certificate %s public key",
        keyfile,
        certfile);
    print_error("certified key mismatch", rr);
    rustls_certified_key_free(certified_key);
    return NULL;
  }

  return certified_key;
}

const rustls_crypto_provider *
default_provider_with_custom_ciphersuite(const char *custom_ciphersuite_name)
{
  const rustls_supported_ciphersuite *custom_ciphersuite = NULL;
  rustls_crypto_provider_builder *provider_builder = NULL;
  const rustls_crypto_provider *custom_provider = NULL;

  const size_t num_supported =
    rustls_default_crypto_provider_ciphersuites_len();
  for(size_t i = 0; i < num_supported; i++) {
    const rustls_supported_ciphersuite *suite =
      rustls_default_crypto_provider_ciphersuites_get(i);
    if(suite == NULL) {
      LOG("failed to get ciphersuite %zu", i);
      goto cleanup;
    }

    const rustls_str suite_name = rustls_supported_ciphersuite_get_name(suite);
    if(strncmp(suite_name.data, custom_ciphersuite_name, suite_name.len) ==
       0) {
      custom_ciphersuite = suite;
      break;
    }
  }

  if(custom_ciphersuite == NULL) {
    LOG("failed to select custom ciphersuite: %s", custom_ciphersuite_name);
    goto cleanup;
  }

  rustls_result rr =
    rustls_crypto_provider_builder_new_from_default(&provider_builder);
  if(rr != RUSTLS_RESULT_OK) {
    print_error("failed to create provider builder", rr);
    goto cleanup;
  }

  rr = rustls_crypto_provider_builder_set_cipher_suites(
    provider_builder, &custom_ciphersuite, 1);
  if(rr != RUSTLS_RESULT_OK) {
    print_error("failed to set custom ciphersuite", rr);
    goto cleanup;
  }

  rr =
    rustls_crypto_provider_builder_build(provider_builder, &custom_provider);
  if(rr != RUSTLS_RESULT_OK) {
    print_error("failed to build custom provider", rr);
    goto cleanup;
  }

cleanup:
  rustls_crypto_provider_builder_free(provider_builder);
  return custom_provider;
}

// hex encode the given data buffer, returning a new NULL terminated buffer
// with the result, or NULL if memory allocation fails.
//
// Caller owns the returned buffer and must free it.
static char *
hex_encode(const unsigned char *data, const size_t len)
{
  // Two output chars per input char, plus the NULL terminator.
  char *hex_str = malloc((len * 2) + 1);
  if(!hex_str) {
    return NULL;
  }

  for(size_t i = 0; i < len; i++) {
    snprintf(hex_str + (i * 2), 3, "%02x", data[i]);
  }

  hex_str[len * 2] = '\0';
  return hex_str;
}

void
stderr_key_log_cb(const rustls_str label, const unsigned char *client_random,
                  const size_t client_random_len, const unsigned char *secret,
                  const size_t secret_len)
{
  char *client_random_str = NULL;
  char *secret_str = NULL;

  client_random_str = hex_encode(client_random, client_random_len);
  if(client_random_str == NULL) {
    goto cleanup;
  }

  secret_str = hex_encode(secret, secret_len);
  if(secret_str == NULL) {
    goto cleanup;
  }

  LOG("SSLKEYLOG: label=%.*s client_random=%s secret=%s",
      (int)label.len,
      label.data,
      client_random_str,
      secret_str);

cleanup:
  if(client_random_str != NULL) {
    free(client_random_str);
  }
  if(secret_str != NULL) {
    free(secret_str);
  }
}

void
log_connection_info(const rustls_connection *rconn)
{
  const rustls_handshake_kind hs_kind =
    rustls_connection_handshake_kind(rconn);
  const rustls_str hs_kind_name = rustls_handshake_kind_str(hs_kind);
  LOG("handshake kind: %.*s", (int)hs_kind_name.len, hs_kind_name.data);

  const int protocol = rustls_connection_get_protocol_version(rconn);
  const char *protocol_name;
  switch(protocol) {
  case RUSTLS_TLS_VERSION_TLSV1_2:
    protocol_name = "TLSv1.2";
    break;
  case RUSTLS_TLS_VERSION_TLSV1_3:
    protocol_name = "TLSv1.3";
    break;
  default:
    protocol_name = "Unknown";
  }
  LOG("negotiated protocol version: %s (%#x)", protocol_name, protocol);

  const int ciphersuite_id =
    rustls_connection_get_negotiated_ciphersuite(rconn);
  const rustls_str ciphersuite_name =
    rustls_connection_get_negotiated_ciphersuite_name(rconn);
  LOG("negotiated ciphersuite: %.*s (%#x)",
      (int)ciphersuite_name.len,
      ciphersuite_name.data,
      ciphersuite_id);

  const int kex_id =
    rustls_connection_get_negotiated_key_exchange_group(rconn);
  const rustls_str kex_name =
    rustls_connection_get_negotiated_key_exchange_group_name(rconn);
  LOG("negotiated key exchange: %.*s (%#x)",
      (int)kex_name.len,
      kex_name.data,
      kex_id);

  const uint8_t *negotiated_alpn = NULL;
  size_t negotiated_alpn_len;
  rustls_connection_get_alpn_protocol(
    rconn, &negotiated_alpn, &negotiated_alpn_len);
  if(negotiated_alpn != NULL) {
    LOG("negotiated ALPN protocol: '%.*s'",
        (int)negotiated_alpn_len,
        (const char *)negotiated_alpn);
  }
  else {
    LOG_SIMPLE("negotiated ALPN protocol: none");
  }

  // We can unconditionally call this function whether we have a server
  // or client connection, as it will return an empty rustls_str if it was a
  // client connection.
  const rustls_str sni = rustls_server_connection_get_server_name(rconn);
  if(sni.len > 0) {
    LOG("client SNI: '%.*s'", (int)sni.len, sni.data);
  }
}

// TLS 1.2 and TLS 1.3, matching Rustls default.
const uint16_t default_tls_versions[] = { 0x0303, 0x0304 };

// Declare the length of the TLS versions array as a global constant
const size_t default_tls_versions_len =
  sizeof(default_tls_versions) / sizeof(default_tls_versions[0]);
