#!/usr/bin/env python3
"""TLS oracle server for the openssl shard specs (python3 stdlib only).

Usage: oracle_server.py <port> <certfile> <keyfile>

Endpoints (all over TLS on 127.0.0.1):
  /hello    200, small marker body
  /chunked  200, Transfer-Encoding: chunked body (the shim must decode it)
  /notfound 404
  /big      200, ~1 MB body (exercises the shim's realloc growth)
  /hang     sleeps 30s before answering (client-timeout tests)
"""
import ssl
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MARKER = "hello-oracle-body"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # the shim sends Connection: close

    def do_GET(self):
        if self.path == "/hello":
            body = MARKER.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/chunked":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for part in (b"hello ", b"chunked ", b"world"):
                self.wfile.write(b"%x\r\n" % len(part))
                self.wfile.write(part)
                self.wfile.write(b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        elif self.path == "/notfound":
            body = b"no such thing"
            self.send_response(404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/big":
            body = (b"x" * 1023 + b"\n") * 1024  # ~1 MB
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/hang":
            time.sleep(30)
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, *args):
        pass  # keep spec output clean


def main():
    port, cert, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
