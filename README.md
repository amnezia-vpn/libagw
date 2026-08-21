# amnezia-gateway-sdk

A Qt-free Go port of the amnezia-client `GatewayController`: the reusable
transport for talking to the Amnezia API gateway — request-envelope crypto,
HTTP, and the censorship-bypass (proxy failover) machinery — with a C ABI for
embedding into C++, Swift, Kotlin and Dart hosts.

The library is transport only. It does **not** parse business objects
(services, subscriptions, `vpn://` keys); it hands the caller the decrypted
JSON response and an error code, and the host builds its typed models on top.

## Layout

```
gateway/   pure-Go core (no cgo): Client, Config, envelope, bypass, failover
cabi/      C ABI (agw.h) as an importable package — the //export surface
archive/   main package that builds cabi standalone (c-archive / c-shared)
examples/  offline smoke tests: c_smoke, cpp_smoke (RAII wrapper), dart_smoke (FFI)
scripts/   build_archive.sh, smoke.sh, ios_clang.sh
```

`gateway` is an ordinary Go package — import it directly from Go hosts
(e.g. the b2b SDK / mobileproxy) with no cgo cost.

## What it does

`Client.Post` sends one encrypted request. On a response that looks like proxy
interference (per the ported `shouldBypassProxy` heuristics) it resolves a
proxy pool from the S3 storage objects — falling back to the cached pool —
health-checks it, and retries through every proxy until one is accepted. The
working proxy and proxy lists are cached in memory and can be persisted by the
host via `ExportState` / `ImportState`.

```go
c := gateway.New(gateway.Config{
    GatewayEndpoint:    "https://api.example.com",
    PublicKeyPEM:       pubKeyPEM,
    S3PrimaryEndpoints: []string{"https://s3.example.com/bucket/"},
})
resp, err := c.Post(ctx, "v1/services", payloadJSON,
    gateway.PostOptions{ServiceType: "amnezia-premium", UserCountryCode: "ru"})
```

`Post` blocks for up to the full failover sequence; run it off the UI thread
and cancel via `ctx`.

## Parity with amnezia-client

The wire protocol and failover behaviour are ported faithfully from
`gatewayController.cpp` and `apiUtils::checkNetworkReplyErrors`, including the
quirks the gateway relies on: a 32-byte AES IV of which CBC uses the first 16,
an 8-byte salt that is generated and transmitted but unused, RSA PKCS#1 v1.5,
and the SHA-512(PEM) proxy-list key schedule. Error codes match the client's
1100-series `ErrorCode` enum.

Two deliberate improvements over the Qt client:

- **Full proxy sweep in one path** — the client's async path tried a single
  proxy; here sync and async collapse into one function that walks the whole
  pool.
- **Pull-model state** — instead of writing an encrypted blob into app
  settings, the library exposes the caches via `ExportState`/`ImportState` and
  the host owns storage. The blob holds bypass endpoints; keep it protected.

## Build

Pure Go:

```
go test ./...
```

C ABI (see `cabi/agw.h` for the contract) — static archive for C/C++/Swift,
shared library for Dart FFI and JNI:

```
scripts/build_archive.sh                            # c-archive, host
AGW_BUILDMODE=c-shared scripts/build_archive.sh     # .dylib/.so/.dll
GOOS=android GOARCH=arm64 scripts/build_archive.sh
```

On macOS/iOS link the archive with `-framework CoreFoundation -framework
Security` (Go's `crypto/x509` uses the system trust store). See
`scripts/README.md` for cross-compilation.

Offline smoke tests for every binding style (C, C++, Dart):

```
scripts/smoke.sh
```

## Bindings

The C ABI is the single contract for all non-Go hosts:

- **C++** — include `cabi/agw.h`, link the archive.
  `examples/cpp_smoke/agw.hpp` is a ready RAII wrapper.
- **Dart/Flutter** — `dart:ffi` over the shared library; generate bindings with
  `ffigen` from `agw.h`. Call `agw_post` from a helper isolate so the blocking
  call does not stall the UI isolate — a cancel handle is a plain integer, so
  it can be sent through a `SendPort`. See `examples/dart_smoke`.
- **Swift** — import `agw.h` via a module map / SPM binary target.
- **Kotlin/Android** — a thin JNI wrapper over the `.so`.

`gomobile bind` is intentionally not used to expose *this* library: C++ and Dart
need the C ABI anyway, and the JSON-first surface keeps the hand-written
bindings tiny.

## Delivery: standalone vs merged

A Go runtime cannot be duplicated inside one process — two c-archives fail to
link outright (`duplicate symbol _crosscall2`), and two shared libraries, while
they do load, are an unsupported configuration. So how this library ships
depends on whether the host process already contains Go:

- **No Go in the process** (e.g. the Qt client): build `./archive` as a
  c-archive and link it. This library owns the only runtime.
- **Go already in the process** (e.g. a Flutter app whose sing-box core is
  linked in): do *not* add a second artifact. Instead have that Go binary
  blank-import this package —

  ```go
  import _ "github.com/amnezia-vpn/amnezia-gateway-sdk/cabi"
  ```

  cgo emits the `//export` symbols for an imported package just as it does for
  main, so they land in the artifact that is already being produced (a
  `gomobile bind` framework or AAR included). Hosts then reach them through
  `DynamicLibrary.process()` on Apple or `DynamicLibrary.open()` on Android.
  One runtime, and the marginal size is the gateway code alone rather than
  another ~6 MB of runtime.

Both paths compile the same `cabi` package, so there is no second
implementation to keep in sync.
