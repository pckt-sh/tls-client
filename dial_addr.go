package tls_client

import (
	"net"
	"net/netip"
	"strings"
)

// DialAddrRewrite picks the address a connection is made to. It is given the
// "host:port" the client is about to connect to and returns the one to
// connect to in its place; returning "" leaves the address as it is.
type DialAddrRewrite func(addr string) string

// WithDialAddrRewrite configures a client to connect where rewrite says
// instead of where the name of the host resolves to, like curl's --resolve
// and --connect-to. Only the address of the connection changes: the TLS
// server name, the Host header and the certificate check still follow the
// URL of the request. That reaches a host through an address its name does
// not resolve to, a CDN's IPv6 edge for a host that publishes only A records
// for example.
//
// It applies to connections the client makes itself, so not to those a proxy
// makes for it, nor to HTTP/3.
func WithDialAddrRewrite(rewrite DialAddrRewrite) HttpClientOption {
	return func(config *httpClientConfig) {
		config.dialAddrRewrite = rewrite
	}
}

// WithHostAddrs configures a client to connect to the given address for each
// of the given hosts, without resolving their names. The port of the request
// is kept. A key starting with a dot stands for every subdomain of the name
// that follows, and the key "*" for every host no other key matches. See
// WithDialAddrRewrite for what does and does not change.
func WithHostAddrs(hosts map[string]netip.Addr) HttpClientOption {
	table := make(map[string]netip.Addr, len(hosts))
	for host, ip := range hosts {
		table[strings.ToLower(host)] = ip
	}

	return WithDialAddrRewrite(func(addr string) string {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return ""
		}

		ip, ok := lookupHostAddr(table, strings.ToLower(strings.TrimSuffix(host, ".")))
		if !ok {
			return ""
		}

		return net.JoinHostPort(ip.String(), port)
	})
}

// lookupHostAddr finds the entry for host: its own, else that of the closest
// parent domain given with a leading dot, else the "*" one.
func lookupHostAddr(table map[string]netip.Addr, host string) (netip.Addr, bool) {
	if ip, ok := table[host]; ok {
		return ip, true
	}

	for rest := host; ; {
		dot := strings.IndexByte(rest, '.')
		if dot < 0 {
			break
		}

		if ip, ok := table[rest[dot:]]; ok {
			return ip, true
		}

		rest = rest[dot+1:]
	}

	ip, ok := table["*"]

	return ip, ok
}
