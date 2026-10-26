#!/bin/sh
# Compile the HTTPS shim into a shared library (desktop dev/test target,
# dlopen'd by src/openssl.cr — no link-time dependency for consumers).
#
# Android does NOT use this script: the app's android build compiles
# ext/https_shim.c with the NDK clang against the static openssl and
# links it into the app .so (see README.md).
set -e
cd "$(dirname "$0")"
cc -O2 -fPIC -shared https_shim.c -o libhttps_shim.so -lssl -lcrypto
