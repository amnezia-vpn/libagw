#!/usr/bin/env bash
# Build the C ABI and run the offline smoke tests for every binding style:
# C (static archive), C++ (RAII wrapper), and Dart FFI (shared library, only
# when a dart SDK is on PATH).
set -euo pipefail

cd "$(dirname "$0")/.."

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Match the build arch to the host C compiler (GOARCH may default otherwise).
HOST_ARCH="$(go env GOHOSTARCH)"
HOST_OS="$(go env GOHOSTOS)"

LDFLAGS=()
if [[ "$HOST_OS" == "darwin" ]]; then
    # Go's crypto/x509 uses the system trust store.
    LDFLAGS+=(-framework CoreFoundation -framework Security)
fi

echo "== building c-archive"
CGO_ENABLED=1 GOARCH="$HOST_ARCH" \
    go build -buildmode=c-archive -o "$TMP/libagw.a" ./archive

echo "== C smoke"
cc examples/c_smoke/smoke.c "$TMP/libagw.a" -Icabi "${LDFLAGS[@]}" -o "$TMP/smoke_c"
"$TMP/smoke_c"

echo "== C++ smoke"
c++ -std=c++17 examples/cpp_smoke/smoke.cpp "$TMP/libagw.a" \
    -Icabi -Iexamples/cpp_smoke "${LDFLAGS[@]}" -o "$TMP/smoke_cpp"
"$TMP/smoke_cpp"

if command -v dart >/dev/null 2>&1; then
    echo "== Dart FFI smoke"
    SHARED_EXT=so
    [[ "$HOST_OS" == "darwin" ]] && SHARED_EXT=dylib
    CGO_ENABLED=1 GOARCH="$HOST_ARCH" \
        go build -buildmode=c-shared -o "$TMP/libagw.$SHARED_EXT" ./archive
    dart run examples/dart_smoke/bin/smoke.dart "$TMP/libagw.$SHARED_EXT"
else
    echo "== Dart FFI smoke skipped (no dart on PATH)"
fi

echo "all smoke tests passed"
