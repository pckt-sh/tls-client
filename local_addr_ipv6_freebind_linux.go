package tls_client

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// withFreebind returns dialer with IP_FREEBIND set on every socket it opens,
// which lets the socket bind an address that is routed to the host but not
// assigned to any interface. A control function already on the dialer still
// runs.
func withFreebind(dialer net.Dialer) net.Dialer {
	control, controlContext := dialer.Control, dialer.ControlContext

	dialer.Control = nil
	dialer.ControlContext = func(ctx context.Context, network, address string, c syscall.RawConn) error {
		// Best effort: without it the bind works whenever the address is
		// assigned or net.ipv6.ip_nonlocal_bind is on, and fails with a clear
		// error otherwise.
		_ = c.Control(func(fd uintptr) {
			_ = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_FREEBIND, 1)
			_ = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_FREEBIND, 1)
		})

		// A dialer calls ControlContext in preference to Control.
		switch {
		case controlContext != nil:
			return controlContext(ctx, network, address, c)
		case control != nil:
			return control(network, address, c)
		}

		return nil
	}

	return dialer
}
