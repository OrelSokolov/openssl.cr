# openssl-static — stdlib networking (sockets + OpenSSL + HTTP::Client)
# from RAW THREADS without a Crystal scheduler.
#
# In egui/sokol (and any C-driven) apps the frame loop and worker threads
# are raw pthreads: `Fiber::ExecutionContext.current` is nil there, so
# every `Crystal::EventLoop.current` call — i.e. EVERY socket or file IO
# through the stdlib — dies with `NilAssertionError`. This shard installs
# a fallback: when the running thread has no execution context,
# `Crystal::EventLoop.current` returns a stateless BLOCKING implementation
# of the same abstract interface (poll/recv/send/connect over libc — the
# thread simply blocks, no fibers involved). Scheduler-equipped threads
# keep their io_uring/epoll loop untouched.
#
# The result is seamless: the REAL stdlib stack — TCPSocket,
# OpenSSL::SSL::Socket::Client (real libssl, system CA verification) and
# HTTP::Client (headers, POST, chunked, redirects, timeouts) — works
# as-is from any thread:
#
#   require "openssl-static"
#   body = HTTP::Client.get("https://example.com")   # from a raw thread too
#
# Consumers must link libssl/libcrypto (the stdlib OpenSSL bindings):
# system shared libs on desktop, a static OpenSSL build for mobile —
# hence the shard name.

require "./openssl-static/blocking_event_loop"
require "./openssl-static/raw_thread"
require "./openssl-static/gc_raw_thread"
