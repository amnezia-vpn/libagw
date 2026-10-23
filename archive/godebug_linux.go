//go:build linux && !android

// On Linux the pure Go resolver gives each DNS attempt the resolv.conf timeout
// (5 s by default) and drops a reply that arrives later; glibc accepts it.
//
//go:debug netdns=cgo
package main
