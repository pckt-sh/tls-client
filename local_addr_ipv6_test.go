package tls_client

import (
	"context"
	"errors"
	"fmt"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/pckt-sh/tls-client/profiles"
	"golang.org/x/net/proxy"
)

func TestRandomIPv6AddrStaysInsideItsCIDR(t *testing.T) {
	for _, cidr := range []string{"2001:db8::/32", "2001:db8:1::/48", "2001:db8:1:2::/64", "2001:db8::1:0/107", "2001:db8::10/125", "2001:db8::2/127", "2001:db8::7/128", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff/61"} {
		prefixes, err := parseIPv6CIDRs([]string{cidr})
		if err != nil {
			t.Fatalf("%s: %v", cidr, err)
		}
		prefix := prefixes[0]

		seen := make(map[netip.Addr]bool)
		for i := 0; i < 200; i++ {
			addr, err := randomIPv6Addr(prefixes)
			if err != nil {
				t.Fatalf("%s: %v", cidr, err)
			}
			if !prefix.Contains(addr) {
				t.Fatalf("%s: drew %s, which is outside the CIDR", cidr, addr)
			}
			if prefix.Bits() < 127 && addr == prefix.Addr() {
				t.Fatalf("%s: drew the subnet-router anycast address %s", cidr, addr)
			}
			seen[addr] = true
		}

		// 200 draws out of 2^64 or more addresses never repeat by chance.
		if prefix.Bits() <= 64 && len(seen) != 200 {
			t.Errorf("%s: 200 draws gave %d distinct addresses", cidr, len(seen))
		}
		if prefix.Bits() == 128 && len(seen) != 1 {
			t.Errorf("%s: a /128 gave %d distinct addresses", cidr, len(seen))
		}
	}
}

func TestRandomIPv6AddrDrawsFromEveryCIDR(t *testing.T) {
	prefixes, err := parseIPv6CIDRs([]string{"2001:db8:a::/48", "2001:db8:b::/48", "2001:db8:c::/48"})
	if err != nil {
		t.Fatal(err)
	}

	hits := make(map[netip.Prefix]int)
	for i := 0; i < 300; i++ {
		addr, err := randomIPv6Addr(prefixes)
		if err != nil {
			t.Fatal(err)
		}
		for _, prefix := range prefixes {
			if prefix.Contains(addr) {
				hits[prefix]++
			}
		}
	}

	for _, prefix := range prefixes {
		if hits[prefix] == 0 {
			t.Errorf("300 draws never picked %s", prefix)
		}
	}
}

func TestLocalAddrFromIPv6CIDRsRejectsWhatItCanNotUse(t *testing.T) {
	for name, tc := range map[string]struct {
		options []HttpClientOption
		want    string
	}{
		"not a CIDR":      {[]HttpClientOption{WithLocalAddrFromIPv6CIDRs("2001:db8::1")}, "not a valid CIDR"},
		"an IPv4 CIDR":    {[]HttpClientOption{WithLocalAddrFromIPv6CIDRs("10.0.0.0/8")}, "not an IPv6 CIDR"},
		"IPv4 in IPv6":    {[]HttpClientOption{WithLocalAddrFromIPv6CIDRs("::ffff:10.0.0.0/104")}, "not an IPv6 CIDR"},
		"a local address": {[]HttpClientOption{WithLocalAddrFromIPv6CIDRs("2001:db8::/32"), WithLocalAddr(net.TCPAddr{IP: net.ParseIP("::1")})}, "both a local address"},
		"IPv6 disabled":   {[]HttpClientOption{WithLocalAddrFromIPv6CIDRs("2001:db8::/32"), WithDisableIPV6()}, "IPv6 is disabled"},
	} {
		_, err := NewHttpClient(NewNoopLogger(), tc.options...)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got error %v, want one containing %q", name, err, tc.want)
		}
	}
}

// drawnLocalAddrs makes the client's dialer set up n connections and returns
// the local address of each.
func drawnLocalAddrs(t *testing.T, client HttpClient, n int) []netip.Addr {
	t.Helper()

	rt, ok := client.(*httpClient).Transport.(*roundTripper)
	if !ok {
		t.Fatalf("the client's transport is a %T", client.(*httpClient).Transport)
	}
	direct, ok := rt.dialer.(*directDialer)
	if !ok {
		t.Fatalf("the client's dialer is a %T", rt.dialer)
	}

	addrs := make([]netip.Addr, 0, n)
	for i := 0; i < n; i++ {
		dialer, err := direct.dialerForConn()
		if err != nil {
			t.Fatal(err)
		}

		local, ok := dialer.LocalAddr.(*net.TCPAddr)
		if !ok {
			t.Fatalf("connection %d has the local address %v", i, dialer.LocalAddr)
		}
		addr, _ := netip.AddrFromSlice(local.IP)
		addrs = append(addrs, addr)
	}

	return addrs
}

// TestEveryConnectionDrawsItsOwnLocalAddr: one address per connection is the
// point of the option, a target that limits by address must not see two
// connections of a client come from the same one.
func TestEveryConnectionDrawsItsOwnLocalAddr(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/48"), netip.MustParsePrefix("2001:db8:2::/48")}

	client, err := NewHttpClient(NewNoopLogger(), WithLocalAddrFromIPv6CIDRs("2001:db8:1::/48", "2001:db8:2::/48"))
	if err != nil {
		t.Fatal(err)
	}

	check := func(when string) {
		t.Helper()

		seen := make(map[netip.Addr]bool)
		for _, addr := range drawnLocalAddrs(t, client, 50) {
			if !prefixes[0].Contains(addr) && !prefixes[1].Contains(addr) {
				t.Errorf("%s: %s is in neither CIDR", when, addr)
			}
			seen[addr] = true
		}
		if len(seen) != 50 {
			t.Errorf("%s: 50 connections drew %d distinct local addresses", when, len(seen))
		}
	}

	check("a new client")

	// Changing the proxy rebuilds the dialer. Back without one, the client
	// still has to draw.
	if err := client.SetProxy(""); err != nil {
		t.Fatal(err)
	}
	check("after SetProxy")
}

// TestAProxyConnectionLeavesFromADrawnLocalAddr: behind a proxy the address
// is that of the connection to the proxy, drawn when the proxy is set.
func TestAProxyConnectionLeavesFromADrawnLocalAddr(t *testing.T) {
	prefix := netip.MustParsePrefix("2001:db8:1::/48")

	var got []*net.TCPAddr
	factory := func(_ string, _ time.Duration, localAddr *net.TCPAddr, _ http.Header, _ Logger) (proxy.ContextDialer, error) {
		got = append(got, localAddr)

		return proxy.Direct, nil
	}

	client, err := NewHttpClient(NewNoopLogger(), WithLocalAddrFromIPv6CIDRs(prefix.String()), WithProxyDialerFactory(factory))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SetProxy("http://proxy.test:8080"); err != nil {
		t.Fatal(err)
	}

	if len(got) != 2 {
		t.Fatalf("the proxy dialer was built %d times, want 2", len(got))
	}
	for i, localAddr := range got {
		if localAddr == nil {
			t.Fatalf("proxy dialer %d got no local address", i)
		}
		if addr, _ := netip.AddrFromSlice(localAddr.IP); !prefix.Contains(addr) {
			t.Errorf("proxy dialer %d got the local address %s, which is not in %s", i, addr, prefix)
		}
	}
	if got[0].IP.Equal(got[1].IP) {
		t.Errorf("both proxy dialers got the local address %s", got[0].IP)
	}
}

// TestRequestsLeaveFromTheDrawnLocalAddr uses the one IPv6 address every host
// has, as a /128, and checks the server sees the request come from it.
func TestRequestsLeaveFromTheDrawnLocalAddr(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}

	remotes := make(chan string, 1)
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(_ stdhttp.ResponseWriter, r *stdhttp.Request) {
		remotes <- r.RemoteAddr
	}))
	_ = srv.Listener.Close()
	srv.Listener = listener
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	client, err := NewHttpClient(NewNoopLogger(),
		WithClientProfile(profiles.Chrome_133),
		WithInsecureSkipVerify(),
		WithTimeoutSeconds(5),
		WithLocalAddrFromIPv6CIDRs("::1/128"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	host, _, err := net.SplitHostPort(<-remotes)
	if err != nil {
		t.Fatal(err)
	}
	if host != "::1" {
		t.Errorf("the request came from %s, want ::1", host)
	}
}

type networkRecordingDialer struct {
	networks chan string
}

func (d networkRecordingDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d networkRecordingDialer) DialContext(_ context.Context, network, _ string) (net.Conn, error) {
	d.networks <- network

	return nil, errors.New("the recording dialer connects to nothing")
}

// TestLocalAddrFromIPv6CIDRsDialsIPv6Only: with an IPv6 local address only
// AAAA records are of any use, and dialing "tcp6" is what keeps the resolver
// from asking for A records as well before every connection.
func TestLocalAddrFromIPv6CIDRsDialsIPv6Only(t *testing.T) {
	client, err := NewHttpClient(NewNoopLogger(), WithLocalAddrFromIPv6CIDRs("2001:db8:1::/48"))
	if err != nil {
		t.Fatal(err)
	}

	rt, ok := client.(*httpClient).Transport.(*roundTripper)
	if !ok {
		t.Fatalf("the client's transport is a %T", client.(*httpClient).Transport)
	}
	recorder := networkRecordingDialer{networks: make(chan string, 2)}
	rt.dialer = recorder

	for _, url := range []string{"https://example.test/", "http://example.test/"} {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Do(req); err == nil {
			t.Fatalf("%s: the request succeeded through a dialer that connects to nothing", url)
		}

		select {
		case network := <-recorder.networks:
			if network != "tcp6" {
				t.Errorf("%s: dialed network %q, want tcp6", url, network)
			}
		default:
			t.Errorf("%s: the request did not dial", url)
		}
	}
}

// recordingLogger keeps what is logged at debug level.
type recordingLogger struct {
	noopLogger
	mu    sync.Mutex
	lines []string
}

func (l *recordingLogger) Debug(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

// TestDebugLogsTheDrawnLocalAddr: in debug mode every connection says which
// address it left from; otherwise nothing is logged.
func TestDebugLogsTheDrawnLocalAddr(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	prefixes := []netip.Prefix{netip.MustParsePrefix("::1/128")}

	logger := &recordingLogger{}
	d := newDirectDialer(time.Second, nil, net.Dialer{}, prefixes, nil, nil, logger)
	conn, err := d.(*directDialer).DialContext(context.Background(), "tcp6", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	if len(logger.lines) != 1 || !strings.Contains(logger.lines[0], "from [::1]:") {
		t.Errorf("logged %q, want one line naming the local address", logger.lines)
	}

	quiet := &recordingLogger{}
	d = newDirectDialer(time.Second, nil, net.Dialer{}, nil, nil, nil, quiet)
	conn, err = d.(*directDialer).DialContext(context.Background(), "tcp6", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	if len(quiet.lines) != 0 {
		t.Errorf("without drawn local addresses it logged %q", quiet.lines)
	}
}
