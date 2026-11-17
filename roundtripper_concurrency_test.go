package tls_client

import (
	"context"
	"fmt"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/pckt-sh/tls-client/profiles"
)

// slowDialClient returns a client whose every dial takes latency before it
// reaches target, the way a dial through a proxy or to a distant host does.
func slowDialClient(t *testing.T, target string, latency time.Duration, extra ...HttpClientOption) HttpClient {
	t.Helper()

	opts := append([]HttpClientOption{
		WithClientProfile(profiles.Chrome_133),
		WithInsecureSkipVerify(),
		WithTimeoutSeconds(10),
		WithDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
			select {
			case <-time.After(latency):
			case <-ctx.Done():
				return nil, ctx.Err()
			}

			var d net.Dialer
			return d.DialContext(ctx, network, target)
		}),
	}, extra...)

	client, err := NewHttpClient(NewNoopLogger(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)

	return client
}

func concurrentGets(t *testing.T, client HttpClient, urls []string) time.Duration {
	t.Helper()

	var wg sync.WaitGroup
	errs := make(chan error, len(urls))
	start := time.Now()

	for _, u := range urls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()

			req, err := http.NewRequest(http.MethodGet, u, nil)
			if err != nil {
				errs <- err
				return
			}

			resp, err := client.Do(req)
			if err != nil {
				errs <- err
				return
			}
			_ = resp.Body.Close()
		}(u)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Fatalf("request failed: %v", err)
	}

	return time.Since(start)
}

// TestFirstDialsToDifferentHostsRunInParallel: the setup dial for a host used
// to run with cachedTransportsLck held, so the first request to every other
// host, and every request to a host already connected, waited for it.
func TestFirstDialsToDifferentHostsRunInParallel(t *testing.T) {
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	const latency = 100 * time.Millisecond
	const hosts = 10

	client := slowDialClient(t, srv.Listener.Addr().String(), latency)

	urls := make([]string, hosts)
	for i := range urls {
		urls[i] = fmt.Sprintf("https://host%d.test/", i)
	}

	took := concurrentGets(t, client, urls)
	t.Logf("%d first requests to different hosts took %s", hosts, took)

	if took > hosts/2*latency {
		t.Errorf("%d first requests to different hosts took %s, the dials ran one after the other", hosts, took)
	}
}

// TestConcurrentHTTP1DialsRunInParallel: every new connection used to be
// dialed and handshaken with rt's lock held, so concurrent HTTP/1 requests,
// which need a connection each, connected one at a time.
func TestConcurrentHTTP1DialsRunInParallel(t *testing.T) {
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		// Long enough that no connection frees up for another request to reuse.
		time.Sleep(200 * time.Millisecond)
	}))
	srv.StartTLS()
	defer srv.Close()

	const latency = 100 * time.Millisecond
	const requests = 10

	client := slowDialClient(t, srv.Listener.Addr().String(), latency, WithForceHttp1())

	// The first request builds the transport, so the ones after it only measure
	// the transport's own dials.
	concurrentGets(t, client, []string{"https://host.test/"})

	urls := make([]string, requests)
	for i := range urls {
		urls[i] = "https://host.test/"
	}

	took := concurrentGets(t, client, urls)
	t.Logf("%d concurrent HTTP/1 requests took %s", requests, took)

	if took > 6*latency {
		t.Errorf("%d concurrent HTTP/1 requests took %s, the dials ran one after the other", requests, took)
	}
}

// TestConcurrentFirstRequestsToOneHostShareOneSetupDial: concurrent first
// requests to a host wait for one setup dial instead of each building and
// throwing away a transport.
func TestConcurrentFirstRequestsToOneHostShareOneSetupDial(t *testing.T) {
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	var mu sync.Mutex
	dials := 0
	target := srv.Listener.Addr().String()

	client, err := NewHttpClient(NewNoopLogger(),
		WithClientProfile(profiles.Chrome_133),
		WithInsecureSkipVerify(),
		WithTimeoutSeconds(10),
		WithDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
			mu.Lock()
			dials++
			mu.Unlock()

			time.Sleep(50 * time.Millisecond)

			var d net.Dialer
			return d.DialContext(ctx, network, target)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	urls := make([]string, 10)
	for i := range urls {
		urls[i] = "https://host.test/"
	}
	concurrentGets(t, client, urls)

	mu.Lock()
	defer mu.Unlock()
	if dials != 1 {
		t.Errorf("10 concurrent HTTP/2 requests to one host dialed %d times, want 1", dials)
	}
}
