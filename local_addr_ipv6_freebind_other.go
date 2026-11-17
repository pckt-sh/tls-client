//go:build !linux

package tls_client

import "net"

// withFreebind is a no-op outside Linux, where the address has to be assigned
// to an interface.
func withFreebind(dialer net.Dialer) net.Dialer {
	return dialer
}
