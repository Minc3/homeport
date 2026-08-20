//go:build linux

package sysx

import (
	"fmt"
	"syscall"
)

// MarkControl returns a net.ListenConfig/net.Dialer Control hook that stamps
// the socket with an fwmark.
//
// This is how one path gets probed specifically. Only a single route to the
// backend exists in the main table, so an ordinary socket would always follow
// whichever tunnel is currently active. Marking the probe socket sends it into
// that path's own routing table instead, which means every path is tested
// end-to-end continuously, including the standby ones nothing is using.
func MarkControl(mark int) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
		})
		if err != nil {
			return err
		}
		if serr != nil {
			return fmt.Errorf("set SO_MARK %#x: %w", mark, serr)
		}
		return nil
	}
}

// MarkSupported reports whether per-path socket marking works here.
func MarkSupported() bool { return true }
