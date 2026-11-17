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
	"sync/atomic"
	"testing"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/pckt-sh/tls-client/profiles"
)

// fakeResolver answers lookups from a table and counts them.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][]netip.Addr // by "network host"
	calls   atomic.Int32
	// gate, if not nil, holds every lookup until it is closed.
	gate chan struct{}
}

func (r *fakeResolver) lookup(ctx context.Context, network, host string) ([]netip.Addr, error) {
	r.calls.Add(1)

	if r.gate != nil {
		select {
		case <-r.gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	addrs, ok := r.answers[network+" "+host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	return append([]netip.Addr(nil), addrs...), nil
}

func (r *fakeResolver) set(key string, addrs ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.answers == nil {
		r.answers = make(map[string][]netip.Addr)
	}
	r.answers[key] = nil
	for _, addr := range addrs {
		r.answers[key] = append(r.answers[key], netip.MustParseAddr(addr))
	}
}

func newFakeDNSCache(ttl time.Duration) (*DNSCache, *fakeResolver) {
	resolver := &fakeResolver{}
	cache := NewDNSCache(ttl, nil)
	cache.lookupNetIP = resolver.lookup

	return cache, resolver
}

func lookupAddrs(t *testing.T, cache *DNSCache, network, host string) []netip.Addr {
	t.Helper()

	_, addrs, _, err := cache.lookup(context.Background(), network, host)
	if err != nil {
		t.Fatalf("lookup %s %s: %v", network, host, err)
	}

	return addrs
}

func TestDNSCacheAsksOncePerTTL(t *testing.T) {
	cache, resolver := newFakeDNSCache(50 * time.Millisecond)
	resolver.set("ip6 example.test", "2001:db8::1")
	resolver.set("ip4 example.test", "192.0.2.1")

	for i := 0; i < 10; i++ {
		if got := lookupAddrs(t, cache, "ip6", "example.test"); len(got) != 1 || got[0].String() != "2001:db8::1" {
			t.Fatalf("got %v", got)
		}
	}
	// A host name is the same host however it is capitalised.
	lookupAddrs(t, cache, "ip6", "Example.TEST")
	if n := resolver.calls.Load(); n != 1 {
		t.Fatalf("11 lookups of one host asked the resolver %d times, want 1", n)
	}

	// What a host resolves to depends on the family that is asked for.
	if got := lookupAddrs(t, cache, "ip4", "example.test"); got[0].String() != "192.0.2.1" {
		t.Fatalf("the ip4 lookup got %v", got)
	}
	if n := resolver.calls.Load(); n != 2 {
		t.Fatalf("the resolver was asked %d times, want 2", n)
	}

	resolver.set("ip6 example.test", "2001:db8::2")
	time.Sleep(60 * time.Millisecond)

	if got := lookupAddrs(t, cache, "ip6", "example.test"); got[0].String() != "2001:db8::2" {
		t.Fatalf("after the ttl the lookup got %v, want the new address", got)
	}
	if n := resolver.calls.Load(); n != 3 {
		t.Fatalf("the resolver was asked %d times, want 3", n)
	}
}

func TestDNSCacheSharesOneLookupBetweenConcurrentCallers(t *testing.T) {
	cache, resolver := newFakeDNSCache(time.Minute)
	resolver.set("ip6 example.test", "2001:db8::1")
	resolver.gate = make(chan struct{})

	const callers = 50

	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _, err := cache.lookup(context.Background(), "ip6", "example.test")
			errs <- err
		}()
	}

	// One caller gives up while the lookup is in flight. That must neither
	// fail the lookup for the others nor keep the one that gave up waiting.
	ctx, cancel := context.WithCancel(context.Background())
	gaveUp := make(chan error, 1)
	go func() {
		_, _, _, err := cache.lookup(ctx, "ip6", "example.test")
		gaveUp <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	if err := <-gaveUp; !errors.Is(err, context.Canceled) {
		t.Fatalf("the caller that gave up got %v, want context.Canceled", err)
	}

	close(resolver.gate)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("a caller got %v", err)
		}
	}
	if n := resolver.calls.Load(); n != 1 {
		t.Fatalf("%d concurrent lookups asked the resolver %d times, want 1", callers, n)
	}
}

// TestDNSCacheLookupOutlivesTheCallerThatStartedIt: the caller whose request
// starts a lookup may be the first to give up on it.
func TestDNSCacheLookupOutlivesTheCallerThatStartedIt(t *testing.T) {
	cache, resolver := newFakeDNSCache(time.Minute)
	resolver.set("ip6 example.test", "2001:db8::1")
	resolver.gate = make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan error, 1)
	go func() {
		_, _, _, err := cache.lookup(ctx, "ip6", "example.test")
		started <- err
	}()
	time.Sleep(20 * time.Millisecond)

	waiting := make(chan error, 1)
	go func() {
		_, _, _, err := cache.lookup(context.Background(), "ip6", "example.test")
		waiting <- err
	}()
	time.Sleep(20 * time.Millisecond)

	cancel()
	if err := <-started; !errors.Is(err, context.Canceled) {
		t.Fatalf("the caller that gave up got %v, want context.Canceled", err)
	}

	close(resolver.gate)
	if err := <-waiting; err != nil {
		t.Fatalf("the caller that kept waiting got %v", err)
	}
	if n := resolver.calls.Load(); n != 1 {
		t.Fatalf("the resolver was asked %d times, want 1", n)
	}
}

func TestDNSCacheDoesNotRememberAFailure(t *testing.T) {
	cache, resolver := newFakeDNSCache(time.Minute)

	_, _, _, err := cache.lookup(context.Background(), "ip6", "example.test")
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("got %v, want the resolver's not found error", err)
	}

	resolver.set("ip6 example.test", "2001:db8::1")
	if got := lookupAddrs(t, cache, "ip6", "example.test"); len(got) != 1 {
		t.Fatalf("got %v", got)
	}
	if n := resolver.calls.Load(); n != 2 {
		t.Fatalf("the resolver was asked %d times, want 2", n)
	}

	cache.Purge()
	lookupAddrs(t, cache, "ip6", "example.test")
	if n := resolver.calls.Load(); n != 3 {
		t.Fatalf("after Purge the resolver was asked %d times in all, want 3", n)
	}
}

func TestDNSCacheTakesTurnsBetweenAddressesOfOneFamily(t *testing.T) {
	cache, resolver := newFakeDNSCache(time.Minute)
	resolver.set("ip6 example.test", "2001:db8::1", "2001:db8::2", "2001:db8::3")
	resolver.set("ip mixed.test", "2001:db8::1", "192.0.2.1", "2001:db8::2")

	var firsts []int
	for i := 0; i < 6; i++ {
		_, _, first, err := cache.lookup(context.Background(), "ip6", "example.test")
		if err != nil {
			t.Fatal(err)
		}
		firsts = append(firsts, first)
	}
	if fmt.Sprint(firsts) != "[0 1 2 0 1 2]" {
		t.Errorf("six lookups started at %v, want [0 1 2 0 1 2]", firsts)
	}

	// The order of an answer with both families says which one to prefer.
	for i := 0; i < 4; i++ {
		_, _, first, err := cache.lookup(context.Background(), "ip", "mixed.test")
		if err != nil {
			t.Fatal(err)
		}
		if first != 0 {
			t.Errorf("lookup %d of a host with both families started at %d, want 0", i, first)
		}
	}
}

func TestDNSCacheStaysBounded(t *testing.T) {
	cache, resolver := newFakeDNSCache(time.Minute)

	for i := 0; i < dnsCacheMaxEntries+500; i++ {
		host := fmt.Sprintf("host%d.test", i)
		resolver.set("ip6 "+host, "2001:db8::1")
		lookupAddrs(t, cache, "ip6", host)
	}

	cache.mu.Lock()
	n := len(cache.entries)
	cache.mu.Unlock()
	if n > dnsCacheMaxEntries {
		t.Errorf("the cache holds %d entries, more than its bound of %d", n, dnsCacheMaxEntries)
	}
}

// listenLoopback returns a listener on 127.0.0.1 that accepts and holds
// connections, and its port.
func listenLoopback(t *testing.T) (net.Listener, string) {
	t.Helper()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()

	_, port, _ := net.SplitHostPort(listener.Addr().String())

	return listener, port
}

func TestDialCachedConnectsToTheCachedAddress(t *testing.T) {
	_, port := listenLoopback(t)

	cache, resolver := newFakeDNSCache(time.Minute)
	resolver.set("ip4 example.test", "127.0.0.1")

	dialer := &net.Dialer{Timeout: 5 * time.Second}

	for i := 0; i < 3; i++ {
		conn, err := dialCached(context.Background(), dialer, cache, "tcp4", net.JoinHostPort("example.test", port))
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}
	if n := resolver.calls.Load(); n != 1 {
		t.Errorf("three connections asked the resolver %d times, want 1", n)
	}

	// An address needs no lookup.
	conn, err := dialCached(context.Background(), dialer, cache, "tcp4", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if n := resolver.calls.Load(); n != 1 {
		t.Errorf("dialing an address asked the resolver, %d lookups in all", n)
	}
}

func TestDialCachedFallsBackToTheNextAddress(t *testing.T) {
	_, port := listenLoopback(t)

	cache, resolver := newFakeDNSCache(time.Minute)
	// The listener is on 127.0.0.1 alone, so the connection to ::1 is
	// refused, or can not be made at all on a host without IPv6.
	resolver.set("ip example.test", "::1", "127.0.0.1")

	dialer := &net.Dialer{Timeout: 5 * time.Second}

	for i := 0; i < 4; i++ {
		conn, err := dialCached(context.Background(), dialer, cache, "tcp", net.JoinHostPort("example.test", port))
		if err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
		if got := conn.RemoteAddr().(*net.TCPAddr).IP.String(); got != "127.0.0.1" {
			t.Errorf("connection %d went to %s", i, got)
		}
		_ = conn.Close()
	}
	if n := resolver.calls.Load(); n != 1 {
		t.Errorf("the resolver was asked %d times, want 1", n)
	}
}

// TestDialCachedForgetsAddressesThatDoNotAnswer: a host that has moved must
// not stay unreachable for the rest of the ttl.
func TestDialCachedForgetsAddressesThatDoNotAnswer(t *testing.T) {
	listener, port := listenLoopback(t)
	_ = listener.Close()

	cache, resolver := newFakeDNSCache(time.Minute)
	resolver.set("ip4 example.test", "127.0.0.1")

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	addr := net.JoinHostPort("example.test", port)

	if _, err := dialCached(context.Background(), dialer, cache, "tcp4", addr); err == nil {
		t.Fatal("connected to a closed port")
	}

	_, _ = dialCached(context.Background(), dialer, cache, "tcp4", addr)
	if n := resolver.calls.Load(); n != 2 {
		t.Errorf("after a connection that failed the resolver was asked %d times in all, want 2", n)
	}
}

// TestClientsShareADNSCache: the end to end case the cache is for, clients
// that each make one connection to the same host.
func TestClientsShareADNSCache(t *testing.T) {
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(_ stdhttp.ResponseWriter, _ *stdhttp.Request) {}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	cache, resolver := newFakeDNSCache(time.Minute)
	resolver.set("ip target.test", "127.0.0.1")

	for i := 0; i < 5; i++ {
		client, err := NewHttpClient(NewNoopLogger(),
			WithClientProfile(profiles.Chrome_133),
			WithInsecureSkipVerify(),
			WithTimeoutSeconds(5),
			WithDNSCache(cache),
		)
		if err != nil {
			t.Fatal(err)
		}

		for _, scheme := range []string{"https", "https"} {
			req, err := http.NewRequest(http.MethodGet, scheme+"://target.test:"+port+"/", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
		}

		client.Close()
	}

	if n := resolver.calls.Load(); n != 1 {
		t.Errorf("five clients asked the resolver %d times, want 1", n)
	}

	// Without the option nothing goes through the cache.
	client, err := NewHttpClient(NewNoopLogger(), WithInsecureSkipVerify(), WithTimeoutSeconds(2))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	req, _ := http.NewRequest(http.MethodGet, "https://target.test:"+port+"/", nil)
	if _, err := client.Do(req); err == nil || strings.Contains(err.Error(), "context") {
		t.Logf("a client without the cache got %v for a name only the fake resolver knows", err)
	}
	if n := resolver.calls.Load(); n != 1 {
		t.Errorf("a client without the option used the cache: %d lookups in all", n)
	}
}
