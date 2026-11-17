package tls_client

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"net/netip"
)

// WithLocalAddrFromIPv6CIDRs configures an HTTP client to make every connection
// from a random IPv6 address out of the given CIDRs, "2001:db8:1::/48" for
// example.
//
// For each new connection one of the CIDRs is picked at random, then an
// address in it, a /128, and the connection is bound to that address. No two
// connections share an address, other than by chance in a small CIDR, so a
// target sees every connection of the client come from somewhere else. The
// requests that go over one connection, an HTTP/2 connection for example,
// all leave from that connection's address.
//
// The host has to be able to send from the addresses. On Linux that takes the
// prefix routed to the machine and a local route for it, for example
//
//	ip -6 route add local 2001:db8:1::/48 dev lo
//
// The option sets IP_FREEBIND on the client's sockets on Linux, so
// net.ipv6.ip_nonlocal_bind does not have to be enabled. On other systems the
// addresses have to be assigned to an interface.
//
// Targets without an IPv6 address can not be reached from an IPv6 local
// address, and the client only asks the resolver for IPv6 addresses. The
// option can not be combined with WithLocalAddr, WithDisableIPV6 or
// WithDialContext, and HTTP/3 connections do not use it.
//
// Behind a proxy the address is the one the connection to the proxy is made
// from. It is drawn once for the proxy, not per connection.
func WithLocalAddrFromIPv6CIDRs(cidrs ...string) HttpClientOption {
	return func(config *httpClientConfig) {
		config.localAddrIPv6CIDRs = cidrs
	}
}

// applyLocalAddrFromIPv6CIDRs sets the client up to draw its local addresses
// when WithLocalAddrFromIPv6CIDRs was given.
func applyLocalAddrFromIPv6CIDRs(config *httpClientConfig) error {
	if len(config.localAddrIPv6CIDRs) == 0 {
		return nil
	}

	switch {
	case config.localAddr != nil:
		return fmt.Errorf("invalid config: cannot set both a local address and IPv6 CIDRs to draw the local address from")
	case config.disableIPV6:
		return fmt.Errorf("invalid config: cannot draw the local address from IPv6 CIDRs when IPv6 is disabled")
	case config.dialContext != nil:
		return fmt.Errorf("invalid config: WithDialContext overrides the built-in dialer, so the local address drawn from IPv6 CIDRs would not be used. Bind the address inside the custom dialer instead")
	}

	prefixes, err := parseIPv6CIDRs(config.localAddrIPv6CIDRs)
	if err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	config.localAddrIPv6Prefixes = prefixes
	config.dialer = withFreebind(config.dialer)
	// An IPv6 local address reaches IPv6 targets only. Dialing "tcp6" makes
	// the resolver ask for AAAA records alone, where "tcp" has it ask for A
	// records too and wait for both answers before every new connection.
	config.disableIPV4 = true

	return nil
}

// proxyLocalAddr returns the local address for the connections to a proxy:
// the configured one, or one drawn from the configured IPv6 CIDRs, or nil.
func (config *httpClientConfig) proxyLocalAddr() (*net.TCPAddr, error) {
	if config.localAddr != nil || len(config.localAddrIPv6Prefixes) == 0 {
		return config.localAddr, nil
	}

	addr, err := randomIPv6Addr(config.localAddrIPv6Prefixes)
	if err != nil {
		return nil, err
	}

	return &net.TCPAddr{IP: addr.AsSlice()}, nil
}

func parseIPv6CIDRs(cidrs []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(cidrs))

	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("%q is not a valid CIDR: %w", cidr, err)
		}

		if !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
			return nil, fmt.Errorf("%q is not an IPv6 CIDR", cidr)
		}

		prefixes = append(prefixes, prefix.Masked())
	}

	return prefixes, nil
}

// randomIPv6Addr picks one of prefixes at random and a random address in it.
func randomIPv6Addr(prefixes []netip.Prefix) (netip.Addr, error) {
	if len(prefixes) == 0 {
		return netip.Addr{}, fmt.Errorf("no IPv6 CIDR to draw an address from")
	}

	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(prefixes))))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("failed to pick an IPv6 CIDR: %w", err)
	}
	prefix := prefixes[n.Int64()]

	network := prefix.Addr().As16()
	bits := prefix.Bits()

	for {
		var host [16]byte
		if _, err := rand.Read(host[:]); err != nil {
			return netip.Addr{}, fmt.Errorf("failed to draw an IPv6 address: %w", err)
		}

		addr := network
		for i := range addr {
			// mask has the bits of byte i that belong to the host part.
			mask := byte(0xff)
			switch {
			case bits >= (i+1)*8:
				mask = 0
			case bits > i*8:
				mask = 0xff >> (bits - i*8)
			}

			addr[i] |= host[i] & mask
		}

		// The all-zero host is the subnet-router anycast address of the prefix,
		// not an address to send from. A /127 and a /128 have no other to offer.
		if addr == network && bits < 127 {
			continue
		}

		return netip.AddrFrom16(addr), nil
	}
}
