//go:build linux || darwin || freebsd || netbsd || openbsd

package main

import "syscall"

// reuseControl lets several Lanrunner instances share the discovery port on
// one machine, which is what makes local two-window testing possible.
func reuseControl(network, address string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
			serr = err
		}
	}); err != nil {
		return err
	}
	return serr
}
