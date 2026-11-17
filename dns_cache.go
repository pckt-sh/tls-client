package tls_client

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultDNSCacheTTL is how long DefaultDNSCache keeps an answer.
	DefaultDNSCacheTTL = 5 * time.Minute

	// dnsCacheMaxEntries bounds a cache that is fed an endless supply of
	// host names.
	dnsCacheMaxEntries = 8192

	// dnsCacheLookupTimeout bounds a lookup, which runs detached from the
	// request that started it.
	dnsCacheLookupTimeout = 30 * time.Second
)

// DefaultDNSCache is a process-wide DNS cache that keeps an answer for
// DefaultDNSCacheTTL. Pass it to WithDNSCache to share one cache between all
// clients.
var DefaultDNSCache = NewDNSCache(DefaultDNSCacheTTL, nil)

// DNSCache remembers the addresses of host names, so that only the first
// connection to a host in every ttl pays for a DNS lookup. It is safe for
// concurrent use and meant to be shared between clients: a client that opens
// a single connection gains nothing from a cache of its own.
//
// Concurrent lookups of one host share a single query. A failed lookup is not
// remembered. An answer is also dropped ahead of its time when a connection
// could not be made to any of its addresses.
type DNSCache struct {
	ttl time.Duration
	// lookupNetIP is the resolver's LookupNetIP.
	lookupNetIP func(ctx context.Context, network, host string) ([]netip.Addr, error)

	mu      sync.Mutex
	entries map[dnsCacheKey]*dnsCacheEntry
}

type dnsCacheKey struct {
	network string // "ip", "ip4" or "ip6"
	host    string
}

type dnsCacheEntry struct {
	// done is closed once addrs, err and expires are set. They are not
	// written after that.
	done    chan struct{}
	addrs   []netip.Addr
	err     error
	expires time.Time

	// next spreads connections over the addresses of a host.
	next atomic.Uint32
}

// NewDNSCache returns a DNS cache that keeps an answer for ttl and resolves
// with resolver, or with net.DefaultResolver if resolver is nil.
func NewDNSCache(ttl time.Duration, resolver *net.Resolver) *DNSCache {
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	return &DNSCache{
		ttl:         ttl,
		lookupNetIP: resolver.LookupNetIP,
		entries:     make(map[dnsCacheKey]*dnsCacheEntry),
	}
}

// Purge forgets every answer.
func (c *DNSCache) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()

	clear(c.entries)
}

// lookup returns the addresses of host for network, which is "ip", "ip4" or
// "ip6", and the index of the one to try first. The slice is shared with
// other callers and must not be modified.
func (c *DNSCache) lookup(ctx context.Context, network, host string) (*dnsCacheEntry, []netip.Addr, int, error) {
	key := dnsCacheKey{network: network, host: strings.ToLower(host)}

	c.mu.Lock()
	entry := c.entries[key]
	if entry != nil && entry.resolved() && !time.Now().Before(entry.expires) {
		entry = nil
	}
	if entry == nil {
		entry = &dnsCacheEntry{done: make(chan struct{})}
		c.evictLocked()
		c.entries[key] = entry

		// The lookup serves every caller that waits for it, so it must
		// not end because the one that happened to start it gave up.
		go c.resolve(context.WithoutCancel(ctx), key, entry)
	}
	c.mu.Unlock()

	select {
	case <-entry.done:
	case <-ctx.Done():
		return nil, nil, 0, ctx.Err()
	}

	if entry.err != nil {
		return nil, nil, 0, entry.err
	}

	return entry, entry.addrs, entry.first(), nil
}

func (c *DNSCache) resolve(ctx context.Context, key dnsCacheKey, entry *dnsCacheEntry) {
	ctx, cancel := context.WithTimeout(ctx, dnsCacheLookupTimeout)
	defer cancel()

	addrs, err := c.lookupNetIP(ctx, key.network, key.host)
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}

	if err == nil && len(addrs) == 0 {
		err = &net.DNSError{Err: "no such host", Name: key.host, IsNotFound: true}
	}

	entry.addrs, entry.err = addrs, err
	entry.expires = time.Now().Add(c.ttl)

	if err != nil {
		// Whoever is waiting gets the error. The next caller asks again.
		c.forget(key, entry)
	}

	close(entry.done)
}

// forget drops entry, unless the cache has moved on to another one for key.
func (c *DNSCache) forget(key dnsCacheKey, entry *dnsCacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.entries[key] == entry {
		delete(c.entries, key)
	}
}

// forgetHost is forget for a caller that has the host as it passed it to
// lookup.
func (c *DNSCache) forgetHost(network, host string, entry *dnsCacheEntry) {
	c.forget(dnsCacheKey{network: network, host: strings.ToLower(host)}, entry)
}

// evictLocked makes room for one more entry.
func (c *DNSCache) evictLocked() {
	if len(c.entries) < dnsCacheMaxEntries {
		return
	}

	now := time.Now()
	for key, entry := range c.entries {
		if entry.resolved() && !now.Before(entry.expires) {
			delete(c.entries, key)
		}
	}

	// Nothing much has expired: drop answers, whichever, rather than grow.
	// An eighth of them go at once, so that a full cache is not walked for
	// every new host. Lookups in flight stay, their callers are waiting.
	const target = dnsCacheMaxEntries - dnsCacheMaxEntries/8
	for key, entry := range c.entries {
		if len(c.entries) <= target {
			break
		}
		if entry.resolved() {
			delete(c.entries, key)
		}
	}
}

func (e *dnsCacheEntry) resolved() bool {
	select {
	case <-e.done:
		return true
	default:
		return false
	}
}

// first returns the index of the address to connect to first. A resolver
// hands out the addresses of a host in a different order every time, which a
// cache would freeze for a whole ttl, so the cache takes turns instead. It
// only does so between addresses of one family: an answer with both is
// sorted by which family the host can reach best, and that order is kept.
func (e *dnsCacheEntry) first() int {
	if len(e.addrs) < 2 {
		return 0
	}

	for _, addr := range e.addrs[1:] {
		if addr.Is4() != e.addrs[0].Is4() {
			return 0
		}
	}

	return int((e.next.Add(1) - 1) % uint32(len(e.addrs)))
}

// dnsNetwork returns the network to resolve a host with for a dial on
// network.
func dnsNetwork(network string) string {
	switch network {
	case "tcp4", "udp4":
		return "ip4"
	case "tcp6", "udp6":
		return "ip6"
	default:
		return "ip"
	}
}

// dialCached is dialer.DialContext with the addresses of the host taken from
// cache. They are tried one after the other, the way a dialer does, until one
// connects.
func dialCached(ctx context.Context, dialer *net.Dialer, cache *DNSCache, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return dialer.DialContext(ctx, network, addr)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		// Already an address, there is nothing to look up.
		return dialer.DialContext(ctx, network, addr)
	}

	ipNetwork := dnsNetwork(network)

	entry, addrs, first, err := cache.lookup(ctx, ipNetwork, host)
	if err != nil {
		return nil, err
	}

	// A dialer spreads the time it has over the addresses it tries, so that
	// one that does not answer leaves time for the next.
	var deadline time.Time
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	}
	if dialer.Timeout > 0 {
		if d := time.Now().Add(dialer.Timeout); deadline.IsZero() || d.Before(deadline) {
			deadline = d
		}
	}

	var firstErr error

	for i := range addrs {
		target := net.JoinHostPort(addrs[(first+i)%len(addrs)].String(), port)

		dialCtx, cancel := ctx, context.CancelFunc(func() {})
		if !deadline.IsZero() {
			dialCtx, cancel = context.WithDeadline(ctx, partialDeadline(time.Now(), deadline, len(addrs)-i))
		}

		conn, err := dialer.DialContext(dialCtx, network, target)
		cancel()
		if err == nil {
			return conn, nil
		}
		if firstErr == nil {
			firstErr = err
		}

		if ctx.Err() != nil || (!deadline.IsZero() && !time.Now().Before(deadline)) {
			break
		}
	}

	// None of the addresses took a connection. They may be out of date.
	cache.forgetHost(ipNetwork, host, entry)

	return nil, firstErr
}

// partialDeadline returns the deadline for one address when addrsRemaining
// are left to try before deadline, as net.Dialer does: an even share of the
// time left, but no less than two seconds unless less than that is left.
func partialDeadline(now, deadline time.Time, addrsRemaining int) time.Time {
	timeRemaining := deadline.Sub(now)
	if timeRemaining <= 0 {
		return deadline
	}

	timeout := timeRemaining / time.Duration(addrsRemaining)

	const saneMinimum = 2 * time.Second
	if timeout < saneMinimum {
		timeout = min(timeRemaining, saneMinimum)
	}

	return now.Add(timeout)
}

// WithDNSCache configures an HTTP client to take the addresses of the hosts
// it connects to from cache, tls_client.DefaultDNSCache for example, instead
// of resolving the host for every new connection.
//
// The cache is used for connections the client makes itself. Behind a proxy
// it is the proxy that resolves the target, and the proxy's own host name is
// resolved without the cache, as are HTTP/3 connections and anything dialed
// through WithDialContext.
func WithDNSCache(cache *DNSCache) HttpClientOption {
	return func(config *httpClientConfig) {
		config.dnsCache = cache
	}
}
