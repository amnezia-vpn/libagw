// Command archive is the standalone build entry point:
//
//	go build -buildmode=c-archive -o libagw.a ./archive
//
// The ABI itself lives in the cabi package, imported here for its //export
// directives.
package main

import (
	_ "github.com/amnezia-vpn/amnezia-gateway-sdk/cabi"
)

func main() {}
