#!/usr/bin/env bash
# Build the C ABI for the host platform, or a target passed as GOOS/GOARCH.
# Output goes to build/<goos>_<goarch>/.
#
#   scripts/build_archive.sh                            # static, host
#   AGW_BUILDMODE=c-shared scripts/build_archive.sh     # shared (Dart FFI)
#   GOOS=android GOARCH=arm64 scripts/build_archive.sh
#
# c-archive is what C++/Swift hosts link statically; c-shared produces the
# .dylib/.so/.dll that Dart FFI and JNI load at runtime.
#
# On macOS/iOS the archive must be linked with -framework CoreFoundation
# -framework Security (Go's crypto/x509 uses the system trust store).
set -euo pipefail

cd "$(dirname "$0")/.."

GOOS="${GOOS:-$(go env GOHOSTOS)}"
GOARCH="${GOARCH:-$(go env GOHOSTARCH)}"
BUILDMODE="${AGW_BUILDMODE:-c-archive}"

case "$BUILDMODE" in
    c-archive) EXT=a ;;
    c-shared)
        case "$GOOS" in
            darwin | ios) EXT=dylib ;;
            windows) EXT=dll ;;
            *) EXT=so ;;
        esac
        ;;
    *)
        echo "unsupported AGW_BUILDMODE: $BUILDMODE (want c-archive or c-shared)" >&2
        exit 2
        ;;
esac

OUT="build/${GOOS}_${GOARCH}"
mkdir -p "$OUT"

echo "building $BUILDMODE for ${GOOS}/${GOARCH} -> ${OUT}/libagw.${EXT}"
CGO_ENABLED=1 GOOS="$GOOS" GOARCH="$GOARCH" \
    go build -buildmode="$BUILDMODE" -ldflags="-s -w" -o "$OUT/libagw.${EXT}" ./archive

ls -la "$OUT"
