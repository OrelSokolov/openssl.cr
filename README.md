# openssl-static

Seamless **stdlib networking from raw threads**: the real stdlib
`HTTP::Client`, `TCPSocket` and `OpenSSL::SSL::Socket::Client` work as-is
from pthreads that Crystal never started — e.g. the egui/sokol frame loop
and its worker threads in Android apps. On such threads
`Fiber::ExecutionContext.current` is nil, so every stdlib IO call dies
(`NilAssertionError "Thread#scheduler cannot be nil"`, or a segfault in
the Boehm GC when stdlib tries to auto-create the missing `::Thread`).

The shard patches the failure points and nothing else:

* **`Crystal::EventLoop.current`** — when the running thread has no
  execution context, returns a stateless blocking implementation of the
  same abstract interface (`poll`/`recv`/`send`/`connect` over libc):
  the thread simply blocks, no fibers involved. Scheduler-equipped
  threads keep their io_uring/epoll loop untouched. `Fiber.syscall`
  (DNS `getaddrinfo` offload) likewise runs inline on raw threads.
* **`Crystal::System::Thread.current_thread`** — hands a raw thread a
  stand-in `::Thread` (pre-created at require time) instead of lazily
  running `::Thread.new`, which dies in `GC_get_my_stackbottom` on a
  thread the GC never registered (`Fiber.current` reaches it from
  everywhere, e.g. `Crystal::FdLock` on every socket close). The main
  thread keeps the stdlib lazy create-and-store behavior.
* **`GC.malloc` / `GC.malloc_atomic` / `GC.realloc`** — a raw thread
  that triggers a Boehm collection aborts the process with
  "Collecting from unknown thread"; the hooks register the running
  pthread (`GC_register_my_thread`, true stack bounds via
  `pthread_getattr_np`) at its first allocation. Per-thread cost is one
  zero-initialized TLS flag read.

The result — no shim API to learn:

```crystal
require "openssl-static"

# from any thread, raw or scheduled:
body = HTTP::Client.get("https://example.com")

ctx = OpenSSL::SSL::Context::Client.new
ctx.ca_certificates = "/etc/ssl/certs/ca-certificates.crt"
HTTP::Client.new("api.example.com", tls: ctx) do |client|
  client.post("/v1/thing", form: {"q" => "hi"})
end
```

## Linking

The shard uses the stdlib OpenSSL bindings — there is no C shim to
compile anymore (the old `OpenSSL::HTTPS` micro-client is gone).
Consumers must link **libssl/libcrypto**:

* **Desktop** — the system shared libraries, nothing to configure.
* **Android/iOS** — a static OpenSSL build linked into the app binary
  together with the Crystal code, e.g. for Android:

  ```sh
  # link: ... -L"$OPENSSL_ANDROID/lib" -lssl -lcrypto
  ```

That static-mobile, seamless-desktop combination is what the shard name
says.

## Tests

```sh
crystal spec    # local TLS oracle: python3 https server on 127.0.0.1
```

The raw-thread spec runs a real `HTTP::Client` + TLS handshake (verified
against a self-signed SAN IP:127.0.0.1 cert) on a genuine
`pthread_create` thread, plus failure cases with a wrong CA.
