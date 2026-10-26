/* test_https_shim.c — desktop tests for https_shim.c (real network).
 *
 * The truncation bug this guards against is platform-independent:
 * the old 1024-byte request buffer let snprintf silently cut the
 * request mid-header. Run with: rake test:net
 *
 * Network cases hit api.mymemory.translated.net (verifies with the
 * system CA store); Google domains are deliberately NOT used — on
 * some networks DPI breaks their TLS chain and the test would be
 * flaky by environment, not by shim.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

char *slush_https_get(const char *host, int port, const char *path,
                      const char *ca_file, const char *ca_dir,
                      int timeout_s);
void slush_https_free(char *s);

static int failures = 0;

static void check(int cond, const char *name, const char *detail) {
  if (cond) {
    printf("ok   %s\n", name);
  } else {
    failures++;
    printf("FAIL %s — %s\n", name, detail ? detail : "");
  }
}

static int is_http_2xx(const char *resp) {
  return strncmp(resp, "HTTP/", 5) == 0 &&
         strncmp(resp + 5, "1.", 2) == 0 &&
         strncmp(strchr(resp, ' ') + 1, "2", 1) == 0;
}

int main(void) {
  /* 1. normal GET, no verification */
  char *r = slush_https_get("api.mymemory.translated.net", 443,
                            "/get?q=%D0%BF%D1%80%D0%B8%D0%B2%D0%B5%D1%82&langpair=ru|en",
                            NULL, NULL, 20);
  check(r && is_http_2xx(r) && strstr(r, "responseData"),
        "GET verify=off → 200 + responseData", r ? r : "(null)");
  slush_https_free(r);

  /* 2. normal GET with system CA directory (crypto verifies) */
  struct stat st;
  if (stat("/etc/ssl/certs", &st) == 0) {
    r = slush_https_get("api.mymemory.translated.net", 443,
                        "/get?q=%D0%BF%D1%80%D0%B8%D0%B2%D0%B5%D1%82&langpair=ru|en",
                        NULL, "/etc/ssl/certs", 20);
    check(r && is_http_2xx(r), "GET verify=on (/etc/ssl/certs) → 2xx",
          r ? r : "(null)");
    slush_https_free(r);
  } else {
    printf("skip GET verify=on (no /etc/ssl/certs)\n");
  }

  /* 3. Google answers Transfer-Encoding: chunked — the shim must
   * decode it (the raw body used to arrive as
   * "13\r\n[\"Hi, how are you\"]\r\n0\r\n\r\n"). verify=off: on some
   * networks the Google chain is DPI-substituted. */
  r = slush_https_get("clients5.google.com", 443,
                      "/translate_a/t?client=dict-chrome-ex&sl=ru&tl=en"
                      "&q=%D0%BF%D1%80%D0%B8%D0%B2%D0%B5%D1%82%20%D0%BA%D0%B0%D0%BA%20%D0%B4%D0%B5%D0%BB%D0%B0",
                      NULL, NULL, 20);
  {
    char *body = r ? strstr(r, "\r\n\r\n") : NULL;
    body = body ? body + 4 : "";
    check(r && is_http_2xx(r) && strstr(body, "[\"Hi, how are you\"]") &&
              body[0] != '\r' && !(body[0] >= '0' && body[0] <= '9'),
          "google chunked → decoded body", r ? body : "(null)");
  }
  slush_https_free(r);

  /* 4. unresolvable host → loud dns error, not a hang or crash */
  r = slush_https_get("nonexistent.perevodilka.invalid", 443, "/", NULL, NULL, 5);
  check(r && strncmp(r, "ERROR: dns:", 11) == 0, "bad host → ERROR: dns",
        r ? r : "(null)");
  slush_https_free(r);

  /* 5. path far beyond the buffer → loud error, NOT silent truncation */
  static char huge[12000];
  strcpy(huge, "/get?q=");
  for (size_t i = 7; i < sizeof(huge) - 1; i++)
    huge[i] = 'a';
  huge[sizeof(huge) - 1] = '\0';
  r = slush_https_get("api.mymemory.translated.net", 443, huge, NULL, NULL, 20);
  check(r && strcmp(r,
         "ERROR: write: request too long (path bytes exceed buffer)") == 0,
        "oversized path → ERROR: request too long", r ? r : "(null)");
  slush_https_free(r);

  /* 6. boundary: request exactly one byte under the buffer must go
   * through to the server (it answers 414/400 — that's fine, the
   * point is the shim does not eat it locally). */
  static char edge[8192];
  int base = snprintf(edge, sizeof(edge),
                      "GET  HTTP/1.1\r\n"
                      "Host: api.mymemory.translated.net\r\n"
                      "User-Agent: perevodilka/0.1\r\n"
                      "Accept: */*\r\n"
                      "Connection: close\r\n\r\n");
  /* base = full fixed part with an empty path; path budget: 8191 - base */
  int path_len = 8191 - base;
  char *path = malloc(path_len + 1);
  snprintf(path, path_len + 1, "/get?q=%.*s", path_len - 7, huge + 7);
  r = slush_https_get("api.mymemory.translated.net", 443, path, NULL, NULL, 20);
  check(r && strncmp(r, "ERROR: write: request too long", 30) != 0 &&
        strncmp(r, "HTTP/", 5) == 0,
        "boundary (reqlen=8191) reaches the server", r ? r : "(null)");
  slush_https_free(r);
  free(path);

  printf(failures ? "\n%d FAIL\n" : "\nall ok\n", failures);
  return failures ? 1 : 0;
}
