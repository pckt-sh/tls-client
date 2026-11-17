package tls_client

import (
	"context"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"

	http "github.com/bogdanfinn/fhttp"
	"github.com/pckt-sh/tls-client/bandwidth"
	"github.com/pckt-sh/tls-client/profiles"
)

func TestHostAddrsLookup(t *testing.T) {
	a := netip.MustParseAddr("2001:db8::1")
	b := netip.MustParseAddr("2001:db8::2")
	c := netip.MustParseAddr("2001:db8::3")

	table := map[string]netip.Addr{"shop.test": a, ".myshopify.com": b, "*": c}

	for host, want := range map[string]netip.Addr{
		"shop.test":         a,
		"x.myshopify.com":   b,
		"a.b.myshopify.com": b,
		"myshopify.com":     c,
		"other.test":        c,
		"notmyshopify.com":  c,
		"www.shop.test":     c,
	} {
		if got, ok := lookupHostAddr(table, host); !ok || got != want {
			t.Errorf("%s: got %v, %v, want %v", host, got, ok, want)
		}
	}

	if _, ok := lookupHostAddr(map[string]netip.Addr{"shop.test": a}, "other.test"); ok {
		t.Error("a host without an entry was given an address")
	}
}

// countingTracker is a tracker of the caller's own, as one feeding a metric
// would be.
type countingTracker struct {
	bandwidth.NopeTracker
	read, written atomic.Int64
	conns         atomic.Int64
}

type countingConn struct {
	net.Conn
	t *countingTracker
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.t.read.Add(int64(n))
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.t.written.Add(int64(n))
	return n, err
}

func (t *countingTracker) TrackConnection(_ context.Context, conn net.Conn) net.Conn {
	t.conns.Add(1)
	return &countingConn{Conn: conn, t: t}
}

// TestDialAddrRewrite: a name that does not resolve is reached through the
// address given for it, with the server name and Host header of the URL.
func TestDialAddrRewrite(t *testing.T) {
	var gotHost, gotSNI atomic.Value

	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(_ stdhttp.ResponseWriter, r *stdhttp.Request) {
		gotHost.Store(r.Host)
		gotSNI.Store(r.TLS.ServerName)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	tracker := &countingTracker{}

	for name, option := range map[string]HttpClientOption{
		"rewrite": WithDialAddrRewrite(func(addr string) string {
			if addr != "shop.invalid:"+port {
				t.Errorf("asked to rewrite %q", addr)
			}
			return srv.Listener.Addr().String()
		}),
		"hosts":    WithHostAddrs(map[string]netip.Addr{"shop.invalid": netip.MustParseAddr("127.0.0.1")}),
		"wildcard": WithHostAddrs(map[string]netip.Addr{".invalid": netip.MustParseAddr("127.0.0.1")}),
		"cached":   WithHostAddrs(map[string]netip.Addr{"*": netip.MustParseAddr("127.0.0.1")}),
	} {
		t.Run(name, func(t *testing.T) {
			options := []HttpClientOption{
				WithClientProfile(profiles.Chrome_133),
				WithInsecureSkipVerify(),
				WithTimeoutSeconds(5),
				WithCustomBandwidthTracker(tracker),
				option,
			}
			if name == "cached" {
				options = append(options, WithDNSCache(NewDNSCache(0, nil)))
			}

			client, err := NewHttpClient(NewNoopLogger(), options...)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()

			req, _ := http.NewRequest(http.MethodGet, "https://shop.invalid:"+port+"/", nil)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()

			if resp.Proto != "HTTP/2.0" {
				t.Errorf("proto %s", resp.Proto)
			}
			if h := gotHost.Load(); h != "shop.invalid:"+port {
				t.Errorf("Host %v", h)
			}
			if s := gotSNI.Load(); s != "shop.invalid" {
				t.Errorf("server name %v", s)
			}
		})
	}

	if tracker.conns.Load() == 0 || tracker.read.Load() == 0 || tracker.written.Load() == 0 {
		t.Errorf("custom tracker saw %d connections, %d bytes read, %d written",
			tracker.conns.Load(), tracker.read.Load(), tracker.written.Load())
	}
}
