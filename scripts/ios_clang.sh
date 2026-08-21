#!/usr/bin/env bash
# cgo CC wrapper for Apple mobile builds. Defaults to an iOS device build;
# override via env for other slices:
#
#   AGW_APPLE_SDK   iphoneos (default) | iphonesimulator
#   AGW_APPLE_ARCH  arm64 (default) | x86_64
#   AGW_APPLE_MIN   minimum OS version (default 13.0)
set -euo pipefail

SDK="${AGW_APPLE_SDK:-iphoneos}"
ARCH="${AGW_APPLE_ARCH:-arm64}"
MIN="${AGW_APPLE_MIN:-13.0}"

if [[ "$SDK" == "iphonesimulator" ]]; then
    MIN_FLAG="-mios-simulator-version-min=$MIN"
else
    MIN_FLAG="-miphoneos-version-min=$MIN"
fi

SDK_PATH="$(xcrun --sdk "$SDK" --show-sdk-path)"
exec "$(xcrun --sdk "$SDK" --find clang)" \
    -isysroot "$SDK_PATH" -arch "$ARCH" "$MIN_FLAG" "$@"
