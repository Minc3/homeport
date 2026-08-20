//go:build !linux

package sysx

import "syscall"

// MarkControl is a no-op off Linux so the tree still builds on a development
// machine. Per-path probing only works on the real Debian hosts.
func MarkControl(mark int) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error { return nil }
}

// MarkSupported reports whether per-path socket marking works here.
func MarkSupported() bool { return false }
