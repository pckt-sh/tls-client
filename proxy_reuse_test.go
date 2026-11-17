package tls_client

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/pckt-sh/tls-client/profiles"
	"golang.org/x/net/proxy"
)

// connectProxy is an HTTPS proxy that answers CONNECT, over HTTP/2 if h2 is
// set and HTTP/1.1 otherwise. It counts the tunnels it opened and the
// connections it accepted.
func connectProxy(t *testing.T, h2 bool) (srv *httptest.Server, tunnels, conns *atomic.Int32) {
	t.Helper()

	tunnels, conns = new(atomic.Int32), new(atomic.Int32)

	srv = httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.Method != stdhttp.MethodConnect {
			w.WriteHeader(stdhttp.StatusMethodNotAllowed)
			return
		}

		upstream, err := net.Dial("tcp", r.Host)
		if err != nil {
			w.WriteHeader(stdhttp.StatusBadGateway)
			return
		}
		defer upstream.Close()

		tunnels.Add(1)

		if r.ProtoMajor == 2 {
			w.WriteHeader(stdhttp.StatusOK)
			w.(stdhttp.Flusher).Flush()

			go func() {
				_, _ = io.Copy(upstream, r.Body)
				_ = upstream.Close()
			}()

			buf := make([]byte, 32*1024)
			for {
				n, err := upstream.Read(buf)
				if n > 0 {
					if _, werr := w.Write(buf[:n]); werr != nil {
						return
					}
					w.(stdhttp.Flusher).Flush()
				}
				if err != nil {
					return
				}
			}
		}

		client, _, err := w.(stdhttp.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer client.Close()

		_, _ = client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() { _, _ = io.Copy(upstream, client); _ = upstream.Close() }()
		_, _ = io.Copy(client, upstream)
	}))
	srv.EnableHTTP2 = h2
	srv.Config.ConnState = func(_ net.Conn, state stdhttp.ConnState) {
		if state == stdhttp.StateNew {
			conns.Add(1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return srv, tunnels, conns
}

// proxyClient returns a client that reaches every target through the HTTPS
// proxy at proxyURL without verifying the proxy's test certificate.
func proxyClient(t *testing.T, proxyURL string) HttpClient {
	t.Helper()

	client, err := NewHttpClient(NewNoopLogger(),
		WithClientProfile(profiles.Chrome_133),
		WithInsecureSkipVerify(),
		WithTimeoutSeconds(5),
		WithProxyDialerFactory(func(_ string, timeout time.Duration, localAddr *net.TCPAddr, connectHeaders http.Header, logger Logger) (proxy.ContextDialer, error) {
			d, err := newConnectDialer(proxyURL, timeout, localAddr, net.Dialer{}, connectHeaders, logger)
			if err != nil {
				return nil, err
			}

			cd := d.(*connectDialer)
			cd.DialTLS = func(network, address string) (net.Conn, string, error) {
				conn, err := tls.Dial(network, address, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
				if err != nil {
					return nil, "", err
				}

				return conn, conn.ConnectionState().NegotiatedProtocol, nil
			}

			return cd, nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)

	return client
}

func h2Target(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()

	var conns atomic.Int32

	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv.EnableHTTP2 = true
	srv.Config.ConnState = func(_ net.Conn, state stdhttp.ConnState) {
		if state == stdhttp.StateNew {
			conns.Add(1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return srv, &conns
}

func sequentialGets(t *testing.T, client HttpClient, url string, n int) {
	t.Helper()

	for i := 0; i < n; i++ {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		// Let a reset of the tunnel reach the connection before the next request.
		time.Sleep(50 * time.Millisecond)
	}
}

// TestAnHTTP2ConnectionOutlivesItsFirstRequestThroughAProxy: the connection a
// setup dial makes is the one every later request to that host reuses, so it
// must not be tied to the context of the request that happened to come first.
func TestAnHTTP2ConnectionOutlivesItsFirstRequestThroughAProxy(t *testing.T) {
	for _, tc := range []struct {
		name string
		h2   bool
	}{{"HTTP/1.1 proxy", false}, {"HTTP/2 proxy", true}} {
		t.Run(tc.name, func(t *testing.T) {
			target, conns := h2Target(t)
			proxySrv, tunnels, _ := connectProxy(t, tc.h2)

			client := proxyClient(t, proxySrv.URL)
			sequentialGets(t, client, target.URL, 5)

			t.Logf("5 requests used %d tunnel(s) and %d connection(s) to the target", tunnels.Load(), conns.Load())

			if got := conns.Load(); got != 1 {
				t.Errorf("5 sequential requests opened %d connections to the target, want 1", got)
			}
		})
	}
}

// TestAFailedTunnelDoesNotCloseTheSharedProxyConnection: every tunnel through
// an HTTP/2 proxy shares one connection, and a proxy that could not reach one
// target used to get that connection closed, resetting all the others.
func TestAFailedTunnelDoesNotCloseTheSharedProxyConnection(t *testing.T) {
	target, conns := h2Target(t)
	proxySrv, _, _ := connectProxy(t, true)
	client := proxyClient(t, proxySrv.URL)

	sequentialGets(t, client, target.URL, 1)

	// Nothing listens here, so the proxy answers the CONNECT with a 502.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String()
	_ = dead.Close()

	req, err := http.NewRequest(http.MethodGet, "https://"+deadAddr+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := client.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("the request to the unreachable target succeeded")
	}

	time.Sleep(50 * time.Millisecond)
	sequentialGets(t, client, target.URL, 2)

	if got := conns.Load(); got != 1 {
		t.Errorf("the target saw %d connections, want 1: the failed tunnel took the others down with it", got)
	}
}

// TestConcurrentDialsShareOneConnectionToAnHTTP2Proxy: tunnels to different
// targets dialed at the same moment used to open a connection to the proxy
// each.
func TestConcurrentDialsShareOneConnectionToAnHTTP2Proxy(t *testing.T) {
	for _, tc := range []struct {
		name string
		h2   bool
		want int32
	}{{"HTTP/2 proxy", true, 1}, {"HTTP/1.1 proxy", false, 8}} {
		t.Run(tc.name, func(t *testing.T) {
			proxySrv, tunnels, proxyConns := connectProxy(t, tc.h2)
			client := proxyClient(t, proxySrv.URL)

			urls := make([]string, 8)
			for i := range urls {
				target, _ := h2Target(t)
				urls[i] = target.URL
			}
			concurrentGets(t, client, urls)

			if got := tunnels.Load(); got != 8 {
				t.Errorf("%d tunnels opened, want 8", got)
			}
			if got := proxyConns.Load(); got != tc.want {
				t.Errorf("8 concurrent tunnels used %d connections to the proxy, want %d", got, tc.want)
			}
		})
	}
}
