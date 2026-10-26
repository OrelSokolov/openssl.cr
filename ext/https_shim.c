/* https_shim.c — blocking HTTPS GET via the OpenSSL C API, for raw
 * threads without a Crystal scheduler (every Crystal socket call there
 * dies: NilAssertionError "Thread#scheduler cannot be nil").
 *
 * One call does the whole exchange: DNS (getaddrinfo) -> TCP connect
 * -> TLS handshake -> GET -> read-to-EOF. All syscalls are blocking
 * (SO_RCVTIMEO/SO_SNDTIMEO timeouts); no event loop, no scheduler.
 *
 *   char *resp = slush_https_get(host, port, path, ca_file_or_null,
 *                                ca_dir_or_null, timeout_s)
 *     malloc'd "HTTP/1.1 ..." response (status line + headers + body,
 *     chunked bodies decoded in place), or a malloc'd "ERROR: ..."
 *     description. Caller frees both with slush_https_free. NULL only
 *     on out-of-memory.
 *   slush_https_free(resp)
 *
 * ca_file / ca_dir (either may be NULL or empty) enable certificate
 * verification: ca_file is a PEM bundle (Mozilla store bundled with the
 * app — the Android system store /system/etc/security/cacerts did not
 * verify MyMemory's chain on a MIUI device), ca_dir an OpenSSL
 * hashed-CA directory. Hostname checking via SSL_set1_host. Both NULL
 * disables verification.
 *
 * Desktop: compiled to ext/libhttps_shim.so by ext/build.sh and loaded
 * via dlopen (no link-time dependency). Android: compiled with the NDK
 * against the static openssl and linked into the app .so.
 */

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define RESP_MAX (2 * 1024 * 1024)

/* HTTP/1.1 servers without a known length answer with
 * Transfer-Encoding: chunked (Google's translate_a/t does: the body
 * arrives as "13\r\n[\"Hi, how are you\"]\r\n0\r\n\r\n"). Decode the
 * chunked body in place after the header block so callers always see
 * plain body bytes. */
static void dechunk_if_needed(char *resp, size_t len) {
  char *hdr_end = memmem(resp, len, "\r\n\r\n", 4);
  if (!hdr_end)
    return;
  int chunked = 0;
  for (char *p = resp; p < hdr_end; ) {
    /* header lines are case-insensitive; find "transfer-encoding:" */
    char *line_end = memmem(p, (size_t)(hdr_end - p), "\r\n", 2);
    if (!line_end)
      line_end = hdr_end;
    size_t ll = (size_t)(line_end - p);
    if (ll >= 18 && strncasecmp(p, "transfer-encoding:", 18) == 0 &&
        memmem(p, ll, "chunked", 7))
      chunked = 1;
    p = (line_end == hdr_end) ? hdr_end : line_end + 2;
    if (chunked)
      break;
  }
  if (!chunked)
    return;

  char *src = hdr_end + 4;
  char *dst = src;
  char *end = resp + len;
  while (src < end) {
    char *eol = memmem(src, (size_t)(end - src), "\r\n", 2);
    if (!eol)
      break;
    unsigned long size = strtoul(src, NULL, 16); /* size[;ext] CRLF */
    if (size == 0)
      break; /* last-chunk */
    char *data = eol + 2;
    if (data + size > end)
      size = (unsigned long)(end - data);
    memmove(dst, data, size);
    dst += size;
    src = data + size;
    src += (src + 1 < end && src[0] == '\r' && src[1] == '\n') ? 2 : 0;
  }
  *dst = '\0';
}

static char *errstr(const char *prefix, const char *detail) {
  /* "ERROR: " + ": " + NUL = 10 extra bytes */
  size_t n = strlen(prefix) + strlen(detail) + 10;
  char *s = (char *)malloc(n);
  if (s)
    snprintf(s, n, "ERROR: %s: %s", prefix, detail);
  return s;
}

char *slush_https_get(const char *host, int port, const char *path,
                      const char *ca_file, const char *ca_dir,
                      int timeout_s) {
  char buf[512];
  char servname[16];

  /* ---- DNS + TCP connect (first answer wins) ---- */
  struct addrinfo hints, *res = NULL, *ai;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  snprintf(servname, sizeof(servname), "%d",
           port > 0 && port < 65536 ? port : 443);
  int rc = getaddrinfo(host, servname, &hints, &res);
  if (rc != 0)
    return errstr("dns", gai_strerror(rc));

  int fd = -1;
  for (ai = res; ai; ai = ai->ai_next) {
    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0)
      continue;
    if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
      break;
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  if (fd < 0)
    return errstr("connect", strerror(errno));

  struct timeval tv;
  tv.tv_sec = timeout_s > 0 ? timeout_s : 15;
  tv.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  int one = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

  /* ---- TLS ---- */
  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx) {
    close(fd);
    return errstr("ssl_ctx", "SSL_CTX_new failed");
  }
  int verify = (ca_file && *ca_file) || (ca_dir && *ca_dir);
  if (verify) {
    if (ca_file && *ca_file &&
        SSL_CTX_load_verify_locations(ctx, ca_file, NULL) != 1) {
      ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
      SSL_CTX_free(ctx);
      close(fd);
      return errstr("ca_file", buf);
    }
    if (ca_dir && *ca_dir &&
        SSL_CTX_load_verify_locations(ctx, NULL, ca_dir) != 1) {
      ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
      SSL_CTX_free(ctx);
      close(fd);
      return errstr("ca_dir", buf);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  } else {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  }

  SSL *ssl = SSL_new(ctx);
  SSL_set_fd(ssl, fd);
  SSL_set_tlsext_host_name(ssl, host); /* SNI */
  if (verify && SSL_set1_host(ssl, host) != 1) {
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return errstr("ssl_host", "SSL_set1_host failed");
  }
  {
    int rc;
    for (;;) {
      rc = SSL_connect(ssl);
      if (rc == 1)
        break;
      /* a signal can interrupt the underlying syscall — retry it */
      if (SSL_get_error(ssl, rc) == SSL_ERROR_SYSCALL && errno == EINTR)
        continue;
      break;
    }
    if (rc != 1) {
      ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
      SSL_free(ssl);
      SSL_CTX_free(ctx);
      close(fd);
      return errstr("tls_handshake", buf);
    }
  }

  /* ---- request ---- */
  char req[8192];
  int reqlen = snprintf(req, sizeof(req),
                        "GET %s HTTP/1.1\r\n"
                        "Host: %s\r\n"
                        "User-Agent: perevodilka/0.1\r\n"
                        "Accept: */*\r\n"
                        "Connection: close\r\n\r\n",
                        path, host);
  if (reqlen < 0 || (size_t)reqlen >= sizeof(req)) {
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return errstr("write", "request too long (path bytes exceed buffer)");
  }
  int sent = 0;
  while (sent < reqlen) {
    int n = SSL_write(ssl, req + sent, reqlen - sent);
    if (n > 0) {
      sent += n;
      continue;
    }
    if (SSL_get_error(ssl, n) == SSL_ERROR_SYSCALL && errno == EINTR)
      continue; /* interrupted by a signal — retry */
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return errstr("write", buf);
  }

  /* ---- response ---- */
  size_t cap = 64 * 1024, len = 0;
  char *resp = (char *)malloc(cap + 1);
  if (!resp) {
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return NULL;
  }
  int n = 0;
  int got_any = 0;
  int ssl_err = 0, saved_errno = 0;
  for (;;) {
    if (len == cap) {
      if (cap >= RESP_MAX)
        break;
      cap *= 2;
      if (cap > RESP_MAX)
        cap = RESP_MAX;
      char *bigger = (char *)realloc(resp, cap + 1);
      if (!bigger) {
        free(resp);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        return NULL;
      }
      resp = bigger;
    }
    n = SSL_read(ssl, resp + len, (int)(cap - len));
    if (n > 0) {
      got_any = 1;
      len += (size_t)n;
      continue;
    }
    /* save before anything clobbers errno */
    ssl_err = SSL_get_error(ssl, n);
    saved_errno = errno;
    if (ssl_err == SSL_ERROR_SYSCALL && saved_errno == EINTR)
      continue; /* interrupted by a signal — retry the read */
    break; /* EOF or error — keep what we have */
  }
  if (!got_any) {
    snprintf(buf, sizeof(buf), "пустой ответ (SSL_get_error=%d errno=%d)",
             ssl_err, saved_errno);
    free(resp);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return errstr("read", buf);
  }
  resp[len] = '\0';
  dechunk_if_needed(resp, len);

  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  close(fd);
  return resp;
}

void slush_https_free(char *s) { free(s); }
