# openssl-shim

Blocking HTTPS GET through the OpenSSL C API, for Crystal apps that make
network calls from **raw threads without a Crystal scheduler** — e.g.
Android egui/sokol apps, where every Crystal socket call from a worker
thread dies with `NilAssertionError "Thread#scheduler cannot be nil"`.

One call does the whole exchange: DNS (`getaddrinfo`) → TCP connect →
TLS handshake → GET → read-to-EOF. All syscalls are blocking
(`SO_RCVTIMEO`/`SO_SNDTIMEO` timeouts); no event loop, no scheduler.
Chunked response bodies are decoded in place by the shim.

```crystal
require "openssl-shim"

body = Openssl::HTTPS.get("api.example.com", "/v1/thing",
                          ca_file: "/etc/ssl/certs/ca-certificates.crt")
```

The namespace is `Openssl` (not `OpenSSL`) so it never collides with the
Crystal stdlib OpenSSL module. The shard is named `openssl-shim` (not
`openssl`) because a shard named exactly `openssl` shadows the stdlib
for every transitive bare `require "openssl"` — e.g. stdlib's own
`http/client.cr` — and breaks `HTTP::Client` TLS for the whole app.

## API

```crystal
Openssl::HTTPS.get(host : String, path : String, port : Int32 = 443,
                   ca_file : String? = nil, ca_dir : String? = nil,
                   timeout_s : Int32 = 15) : String
```

Returns the response body; raises `Openssl::Error` on any failure:

* shim errors keep their informative prefixes — `dns:`,
  `tls_handshake:`, `ca_file:`, `read:`, `write:` …;
* non-2xx answers raise `HTTP <code>: <status line>`.

Verification is enabled when `ca_file` (a PEM bundle) or `ca_dir` (an
OpenSSL hashed-CA dir) is given; the hostname is checked via
`SSL_set1_host`. Both empty disables verification — the fallback for
networks where DPI substitutes the certificate chain (callers can retry
without CA on certificate errors).

## Native code loading

The primary target is **static linking into mobile apps (Android/iOS)**:
there is no dlopen there — the shim C file is compiled into the app
binary together with the Crystal code, and the Crystal side binds the
extern symbols directly (same link unit). On desktop, static linking
works exactly the same way if you prefer it; the default there is the
dlopen mode below, which keeps the consumer free of any link-time
dependency.

* **Desktop (default)** — `ext/libhttps_shim.so` is `dlopen`'d at
  runtime; the shard compiles it on first use if missing (path
  dependencies don't run postinstall). No link-time dependency on
  libssl, no `--link-flags` needed. Override the path with
  `OPENSSL_SHIM_SO`.
* **Android/iOS (or desktop with static linking)** — compile
  `ext/https_shim.c` with your cross toolchain against a static OpenSSL
  build and link it into the app binary (same link unit as the Crystal
  code), e.g. for Android:

  ```sh
  "$NDK_CC" --target=aarch64-linux-android33 -O2 -fPIC \
    -I"$OPENSSL_ANDROID/include" \
    -c ext/https_shim.c -o build/https_shim_android.o
  # link: ... build/https_shim_android.o -L"$OPENSSL_ANDROID" -lssl -lcrypto
  ```

  With the `android` compile flag the Crystal side binds the extern
  symbols directly (no dlopen); on desktop static linking works the
  same way via the dlopen path resolution — or just link the object in
  and set `OPENSSL_SHIM_SO` accordingly.

## Tests

```sh
crystal spec    # локальный TLS-оракул: python3 http.server + ssl на 127.0.0.1
rake test:net   # реальный интернет (MyMemory) — опциональная дежурная проверка
```

The oracle specs generate a self-signed certificate on the fly (SAN
`IP:127.0.0.1`) and exercise the real TLS handshake: verification
success/failure, verify-off fallback, chunked decoding, non-2xx,
~1 MB bodies, DNS errors, oversized request paths, and read timeouts.
