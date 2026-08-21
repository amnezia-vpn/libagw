# scripts

| Script | What it does |
|---|---|
| `build_archive.sh` | Builds the C ABI into `build/<goos>_<goarch>/`. Defaults to a `c-archive` for the host; set `AGW_BUILDMODE=c-shared` for the `.dylib`/`.so`/`.dll` that Dart FFI and JNI load, and `GOOS`/`GOARCH` to cross-compile. |
| `smoke.sh` | Builds the ABI and runs the offline smoke tests: C, C++, and Dart FFI (skipped when no `dart` is on PATH). No network. |
| `ios_clang.sh` | cgo `CC` wrapper for `GOOS=ios GOARCH=arm64` device builds. |

Cross-compiling needs a cgo toolchain for the target:

```bash
# Android (NDK)
NDK=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/<host>/bin
CC=$NDK/aarch64-linux-android24-clang GOOS=android GOARCH=arm64 scripts/build_archive.sh

# iOS device
CC=$(pwd)/scripts/ios_clang.sh GOOS=ios GOARCH=arm64 scripts/build_archive.sh
```

On macOS and iOS the resulting archive must be linked with `-framework
CoreFoundation -framework Security` — Go's `crypto/x509` reads the system
trust store.
