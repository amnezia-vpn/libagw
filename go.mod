module github.com/amnezia-vpn/libagw

// Kept at 1.23: the amnezia-client build provisions Go via a conan recipe
// pinned to the 1.23 line.
go 1.23

require github.com/refraction-networking/utls v1.6.7

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/cloudflare/circl v1.3.7 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	golang.org/x/crypto v0.21.0 // indirect
	golang.org/x/sys v0.18.0 // indirect
)
