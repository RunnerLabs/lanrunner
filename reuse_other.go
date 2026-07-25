//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !windows

package main

import "syscall"

// Platforms without a portable socket-reuse option: bind normally.
func reuseControl(network, address string, c syscall.RawConn) error { return nil }
