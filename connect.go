package tls_client

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	_ "github.com/bdandy/go-socks4" // due to that proxy.FromURL() does support socks4
	http "github.com/bogdanfinn/fhttp"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bogdanfinn/fhttp/http2"
	"github.com/bogdanfinn/fhttp/httptrace"
)

// directDialer connects straight to the target, without a proxy.
type directDialer struct {
	dialer net.Dialer

	// localPrefixes, if not empty, are the IPv6 networks every connection
	// draws a local address of its own from.
	localPrefixes []netip.Prefix

	// dnsCache, if not nil, is where the addresses of a host come from.
	dnsCache *DNSCache

	// rewrite, if not nil, picks the address to connect to. See
	// WithDialAddrRewrite.
	rewrite DialAddrRewrite
}

func newDirectDialer(timeout time.Duration, localAddr *net.TCPAddr, _dialer net.Dialer, localPrefixes []netip.Prefix, dnsCache *DNSCache, rewrite DialAddrRewrite) proxy.ContextDialer {
	_dialer.Timeout = timeout
	if nil != localAddr {
		_dialer.LocalAddr = localAddr
	}

	return &directDialer{
		dialer:        _dialer,
		localPrefixes: localPrefixes,
		dnsCache:      dnsCache,
		rewrite:       rewrite,
	}
}

func (d *directDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *directDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer, err := d.dialerForConn()
	if err != nil {
		return nil, err
	}

	if d.rewrite != nil {
		if to := d.rewrite(addr); to != "" {
			addr = to
		}
	}

	if d.dnsCache != nil {
		return dialCached(ctx, dialer, d.dnsCache, network, addr)
	}

	return dialer.DialContext(ctx, network, addr)
}

// dialerForConn returns the dialer to make one connection with. It is d's
// own, unless the connection is to leave from a local address drawn for it.
func (d *directDialer) dialerForConn() (*net.Dialer, error) {
	if len(d.localPrefixes) == 0 {
		return &d.dialer, nil
	}

	local, err := randomIPv6Addr(d.localPrefixes)
	if err != nil {
		return nil, err
	}

	dialer := d.dialer
	dialer.LocalAddr = &net.TCPAddr{IP: local.AsSlice()}

	return &dialer, nil
}

type socksContextDialer struct {
	socksDialer proxy.Dialer
}

func newSocksContextDialer(socksDialer proxy.Dialer) socksContextDialer {
	return socksContextDialer{
		socksDialer: socksDialer,
	}
}

func (s *socksContextDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d, ok := s.socksDialer.(proxy.ContextDialer); ok {
		return d.DialContext(ctx, network, address)
	}

	// SOCKS4 has no DialContext: stop waiting once ctx is done.
	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result, 1)
	go func() {
		conn, err := s.socksDialer.Dial(network, address)
		done <- result{conn, err}
	}()

	select {
	case r := <-done:
		return r.conn, r.err
	case <-ctx.Done():
		go func() {
			if r := <-done; r.conn != nil {
				_ = r.conn.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// stolen from https://github.com/caddyserver/forwardproxy/blob/master/httpclient/httpclient.go

// http2ConnectRejectionGrace is how long after the first byte of the response
// to a CONNECT over HTTP/2 the round trip may still be running before it is
// taken to have been rejected. See connectHttp2.
const http2ConnectRejectionGrace = time.Second

// proxyStatusError is a CONNECT the proxy answered with something other than
// 200. The proxy was reached and has decided, so there is no point in asking
// again over another connection.
type proxyStatusError struct {
	status string
}

func (e *proxyStatusError) Error() string {
	return "Proxy responded with non 200 code: " + e.status
}

// connectDialer allows to configure one-time use HTTP CONNECT client
type connectDialer struct {
	logger          Logger
	cachedH2RawConn net.Conn
	DefaultHeader   http.Header

	// overridden DialTLS allows user to control establishment of TLS connection
	// MUST return connection with completed Handshake, and NegotiatedProtocol
	DialTLS            func(network string, address string) (net.Conn, string, error)
	cachedH2ClientConn *http2.ClientConn
	ProxyUrl           url.URL

	Dialer net.Dialer // overridden dialer allow to control establishment of TCP connection

	Timeout           time.Duration
	cacheH2Mu         sync.Mutex
	EnableH2ConnReuse bool

	// h2DialSlot is held by the one dial that may open a connection to an
	// HTTP/2 proxy, so concurrent dials share that connection instead of each
	// opening their own. A channel rather than a mutex, so a dial whose context
	// ends can stop waiting for it.
	h2DialSlot chan struct{}
	// proxyIsHTTP1 is set once the proxy has negotiated HTTP/1.1. Its
	// connections carry one tunnel each, so there is nothing to share and dials
	// no longer queue for the slot.
	proxyIsHTTP1 atomic.Bool

	// tlsConfig is the configuration for the connection to an https proxy. It
	// is built once so its session cache lets later connections resume.
	tlsConfig *tls.Config
}

// newConnectDialer creates a dialer to issue CONNECT requests and tunnel traffic via HTTP/S proxy.
// proxyUrlStr must provide Scheme and Host, may provide credentials and port.
// Example: https://username:password@golang.org:443
func newConnectDialer(proxyUrlStr string, timeout time.Duration, localAddr *net.TCPAddr, configDialer net.Dialer, connectHeaders http.Header, logger Logger) (proxy.ContextDialer, error) {
	proxyUrl, err := url.Parse(proxyUrlStr)
	if err != nil {
		return nil, err
	}

	if proxyUrl.Host == "" {
		return nil, errors.New("invalid url `" + proxyUrlStr +
			"`, make sure to specify full url like https://username:password@hostname.com:443/")
	}

	_dialer := configDialer
	_dialer.Timeout = timeout
	if nil != localAddr {
		_dialer.LocalAddr = localAddr
	}

	switch proxyUrl.Scheme {
	case "http":
		if proxyUrl.Port() == "" {
			proxyUrl.Host = net.JoinHostPort(proxyUrl.Host, "80")
		}
	case "https":
		if proxyUrl.Port() == "" {
			proxyUrl.Host = net.JoinHostPort(proxyUrl.Host, "443")
		}
	case "socks4", "socks4a":
		return handleSocks4ProxyDialer(proxyUrl, _dialer)
	case "socks5", "socks5h":
		return handleSocks5ProxyDialer(proxyUrl, _dialer)
	case "":
		return nil, errors.New("specify scheme explicitly (https://)")
	default:
		return nil, errors.New("scheme " + proxyUrl.Scheme + " is not supported")
	}

	dialer := &connectDialer{
		logger:            logger,
		ProxyUrl:          *proxyUrl,
		Dialer:            _dialer,
		Timeout:           timeout,
		DefaultHeader:     connectHeaders.Clone(),
		EnableH2ConnReuse: true,
		h2DialSlot:        make(chan struct{}, 1),
		tlsConfig: &tls.Config{
			NextProtos:         []string{"h2", "http/1.1"},
			ServerName:         proxyUrl.Hostname(),
			ClientSessionCache: tls.NewLRUClientSessionCache(0),
		},
	}

	if proxyUrl.User != nil {
		if proxyUrl.User.Username() != "" {
			// example format (with credentials): http://root:xxx@127.0.0.1:12312
			password, _ := proxyUrl.User.Password()
			dialer.DefaultHeader.Set("Proxy-Authorization", "Basic "+
				base64.StdEncoding.EncodeToString([]byte(proxyUrl.User.Username()+":"+password)))

		}
	}
	return dialer, nil
}

func handleSocks5ProxyDialer(proxyUrl *url.URL, dialer net.Dialer) (proxy.ContextDialer, error) {
	var proxyAuth *proxy.Auth
	if proxyUrl.User != nil {
		password, _ := proxyUrl.User.Password()
		proxyAuth = &proxy.Auth{
			User:     proxyUrl.User.Username(),
			Password: password,
		}
	} else {
		proxyAuth = nil
	}

	socksDialer, err := proxy.SOCKS5("tcp", proxyUrl.Host, proxyAuth, &dialer)
	if err != nil {
		return nil, fmt.Errorf("failed to create socks5 proxy: %w", err)
	}

	scd := newSocksContextDialer(socksDialer)

	return &scd, nil
}

func handleSocks4ProxyDialer(proxyUrl *url.URL, dialer net.Dialer) (proxy.ContextDialer, error) {
	socks4Dialer, err := proxy.FromURL(proxyUrl, &dialer)
	if err != nil {
		return nil, fmt.Errorf("failed to create socks4 proxy dialer: %w", err)
	}

	scd := newSocksContextDialer(socks4Dialer)
	return &scd, nil
}

func (c *connectDialer) Dial(network, address string) (net.Conn, error) {
	return c.DialContext(context.Background(), network, address)
}

// Users of context.WithValue should define their own types for keys
type ContextKeyHeader struct{}

// ctx.Value will be inspected for optional ContextKeyHeader{} key, with `http.Header` value,
// which will be added to outgoing request headers, overriding any colliding c.DefaultHeader
func (c *connectDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	req := (&http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Host: address},
		Header: make(http.Header),
		Host:   address,
	}).WithContext(ctx)

	for k, v := range c.DefaultHeader {
		req.Header[k] = v
	}

	if ctxHeader, ctxHasHeader := ctx.Value(ContextKeyHeader{}).(http.Header); ctxHasHeader {
		for k, v := range ctxHeader {
			req.Header[k] = v
		}
	}

	// The order is looked up by lower-cased name, as for every other request,
	// so a capitalised order would silently fall back to alphabetical.
	if order, ok := req.Header[http.HeaderOrderKey]; ok {
		req.Header[http.HeaderOrderKey] = allToLower(order)
	}

	connectHttp2 := func(rawConn net.Conn, h2clientConn *http2.ClientConn) (net.Conn, error) {
		req.Proto = "HTTP/2.0"
		req.ProtoMajor = 2
		req.ProtoMinor = 0
		pr, pw := io.Pipe()
		req.Body = pr

		// A failure here is the failure of this one tunnel. The connection is
		// shared with every other tunnel through the proxy, so it stays open:
		// closing it for a proxy that could not reach one target reset the
		// connections to all the others.
		//
		// The HTTP/2 transport does not return a response that rejects the
		// request before the request body, the tunnel's outgoing half, has
		// stopped being written, and nothing would ever stop it: a proxy that
		// answered 407 or 502 hung the dial forever. A successful CONNECT
		// returns right after the first byte of the response, so a round trip
		// that is still running a moment later was rejected, and closing the
		// pipe lets it return the response. The same goes for a context that
		// ends first.
		firstByte := make(chan struct{})
		var firstByteOnce sync.Once
		tracedReq := req.WithContext(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
			GotFirstResponseByte: func() { firstByteOnce.Do(func() { close(firstByte) }) },
		}))

		returned := make(chan struct{})
		go func() {
			select {
			case <-returned:
				return
			case <-ctx.Done():
				_ = pw.CloseWithError(ctx.Err())
				return
			case <-firstByte:
			}

			grace := time.NewTimer(http2ConnectRejectionGrace)
			defer grace.Stop()

			select {
			case <-returned:
			case <-ctx.Done():
				_ = pw.CloseWithError(ctx.Err())
			case <-grace.C:
				_ = pw.CloseWithError(errors.New("tls-client: the proxy rejected the CONNECT"))
			}
		}()

		resp, err := h2clientConn.RoundTrip(tracedReq)
		close(returned)
		if err != nil {
			_ = pw.Close()
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			_ = pw.Close()
			_ = resp.Body.Close()
			return nil, &proxyStatusError{status: resp.Status}
		}

		return newHttp2Conn(rawConn, pw, resp.Body), nil
	}

	connectHttp1 := func(rawConn net.Conn) (net.Conn, error) {
		req.Proto = "HTTP/1.1"
		req.ProtoMajor = 1
		req.ProtoMinor = 1

		// Use the earlier of the client timeout (0 means none) and the ctx deadline.
		var deadline time.Time
		if c.Timeout > 0 {
			deadline = time.Now().Add(c.Timeout)
		}
		if d, ok := ctx.Deadline(); ok && (deadline.IsZero() || d.Before(deadline)) {
			deadline = d
		}
		if err := rawConn.SetDeadline(deadline); err != nil {
			_ = rawConn.Close()
			return nil, err
		}

		// Abort when ctx is cancelled.
		stop := context.AfterFunc(ctx, func() { _ = rawConn.SetDeadline(time.Now()) })
		fail := func(err error) (net.Conn, error) {
			stop()
			_ = rawConn.Close()
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			return nil, err
		}

		err := req.Write(rawConn)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				c.logger.Error("deadline exceeded while trying to write proxy connection")
			}

			return fail(err)
		}

		resp, err := http.ReadResponse(bufio.NewReader(rawConn), req)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				c.logger.Error("deadline exceeded while trying to read proxy connection")
			}

			return fail(err)
		}

		if resp.StatusCode != http.StatusOK {
			return fail(errors.New("Proxy responded with non 200 code: " + resp.Status))
		}

		if !stop() {
			_ = rawConn.Close()
			return nil, ctx.Err()
		}

		rawConn.SetDeadline(time.Time{})

		return rawConn, nil
	}

	proxyConn, tried, err := c.tunnelOverCachedH2(connectHttp2)
	if proxyConn != nil {
		return proxyConn, nil
	}

	var rejected *proxyStatusError
	if errors.As(err, &rejected) {
		return nil, err
	}

	// Until the proxy is known to speak HTTP/1.1, one dial at a time connects
	// to it. If it turns out to speak HTTP/2, the dials that waited find the
	// connection cached and open their tunnel on it.
	if c.EnableH2ConnReuse && c.h2DialSlot != nil && c.ProxyUrl.Scheme == "https" && !c.proxyIsHTTP1.Load() {
		select {
		case c.h2DialSlot <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}

		released := false
		release := func() {
			if !released {
				released = true
				<-c.h2DialSlot
			}
		}
		defer release()

		// A connection may have been cached while this dial waited. One that
		// already refused this tunnel is not asked again.
		if !tried {
			proxyConn, _, err := c.tunnelOverCachedH2(connectHttp2)
			if proxyConn != nil {
				return proxyConn, nil
			}
			if errors.As(err, &rejected) {
				return nil, err
			}
		}

		// The dial this one waited for may have found the proxy to speak
		// HTTP/1.1, and then this one has nothing to wait for either.
		if !c.proxyIsHTTP1.Load() {
			rawConn, negotiatedProtocol, err := c.dialProxy(ctx, network)
			if err != nil {
				return nil, err
			}

			if negotiatedProtocol != "h2" {
				c.proxyIsHTTP1.Store(true)
				release()

				return c.tunnelOverNewConn(rawConn, negotiatedProtocol, connectHttp1, connectHttp2)
			}

			t := http2.Transport{}
			h2clientConn, err := t.NewClientConn(rawConn)
			if err != nil {
				_ = rawConn.Close()
				return nil, err
			}

			c.cacheH2Mu.Lock()
			c.cachedH2ClientConn = h2clientConn
			c.cachedH2RawConn = rawConn
			c.cacheH2Mu.Unlock()

			// The connection is there for the others now. The tunnel itself
			// needs no slot, and if it fails the connection stays: the dials
			// that waited may already have tunnels of their own on it.
			release()

			return connectHttp2(rawConn, h2clientConn)
		}

		release()
	}

	rawConn, negotiatedProtocol, err := c.dialProxy(ctx, network)
	if err != nil {
		return nil, err
	}

	return c.tunnelOverNewConn(rawConn, negotiatedProtocol, connectHttp1, connectHttp2)
}

// tunnelOverCachedH2 opens a tunnel on the cached connection to an HTTP/2
// proxy. It returns nil if there is none that takes a new request, or if the
// tunnel failed, in which case the caller dials the proxy afresh unless err is
// a proxyStatusError. tried says whether a tunnel was attempted at all.
func (c *connectDialer) tunnelOverCachedH2(connectHttp2 func(net.Conn, *http2.ClientConn) (net.Conn, error)) (proxyConn net.Conn, tried bool, err error) {
	if !c.EnableH2ConnReuse {
		return nil, false, nil
	}

	c.cacheH2Mu.Lock()
	rc, cc := c.cachedH2RawConn, c.cachedH2ClientConn
	c.cacheH2Mu.Unlock()

	if rc == nil || cc == nil || !cc.CanTakeNewRequest() {
		return nil, false, nil
	}

	proxyConn, err = connectHttp2(rc, cc)
	if err != nil {
		return nil, true, err
	}

	return proxyConn, true, nil
}

// dialProxy connects to the proxy and reports the protocol negotiated with it,
// empty for a plain http proxy.
func (c *connectDialer) dialProxy(ctx context.Context, network string) (net.Conn, string, error) {
	switch c.ProxyUrl.Scheme {
	case "http":
		rawConn, err := c.Dialer.DialContext(ctx, network, c.ProxyUrl.Host)
		if err != nil {
			return nil, "", err
		}

		return rawConn, "", nil
	case "https":
		if c.DialTLS != nil {
			return c.DialTLS(network, c.ProxyUrl.Host)
		}

		tlsDialer := tls.Dialer{
			NetDialer: &c.Dialer,
			Config:    c.proxyTLSConfig(),
		}
		conn, err := tlsDialer.DialContext(ctx, network, c.ProxyUrl.Host)
		if err != nil {
			return nil, "", err
		}
		tlsConn := conn.(*tls.Conn)

		return tlsConn, tlsConn.ConnectionState().NegotiatedProtocol, nil
	default:
		return nil, "", errors.New("scheme " + c.ProxyUrl.Scheme + " is not supported")
	}
}

// proxyTLSConfig is the configuration for the connection to an https proxy. A
// dialer built by hand, without newConnectDialer, gets one per dial as before.
func (c *connectDialer) proxyTLSConfig() *tls.Config {
	if c.tlsConfig != nil {
		return c.tlsConfig
	}

	return &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
		ServerName: c.ProxyUrl.Hostname(),
	}
}

// tunnelOverNewConn opens the tunnel on a connection just made to the proxy.
func (c *connectDialer) tunnelOverNewConn(rawConn net.Conn, negotiatedProtocol string, connectHttp1 func(net.Conn) (net.Conn, error), connectHttp2 func(net.Conn, *http2.ClientConn) (net.Conn, error)) (net.Conn, error) {
	switch negotiatedProtocol {
	case "", "http/1.1":
		return connectHttp1(rawConn)
	case "h2":
		t := http2.Transport{}
		h2clientConn, err := t.NewClientConn(rawConn)
		if err != nil {
			_ = rawConn.Close()
			return nil, err
		}

		proxyConn, err := connectHttp2(rawConn, h2clientConn)
		if err != nil {
			_ = rawConn.Close()
			return nil, err
		}

		if c.EnableH2ConnReuse {
			c.cacheH2Mu.Lock()
			c.cachedH2ClientConn = h2clientConn
			c.cachedH2RawConn = rawConn
			c.cacheH2Mu.Unlock()
		}

		return proxyConn, nil
	default:
		_ = rawConn.Close()
		return nil, errors.New("negotiated unsupported application layer protocol: " +
			negotiatedProtocol)
	}
}

func newHttp2Conn(c net.Conn, pipedReqBody *io.PipeWriter, respBody io.ReadCloser) net.Conn {
	return &http2Conn{Conn: c, in: pipedReqBody, out: respBody}
}

type http2Conn struct {
	net.Conn
	in  *io.PipeWriter
	out io.ReadCloser
}

func (h *http2Conn) Read(p []byte) (n int, err error) {
	return h.out.Read(p)
}

func (h *http2Conn) Write(p []byte) (n int, err error) {
	return h.in.Write(p)
}

// The deadline setters do not reach the embedded connection. It is the one
// connection to the proxy, shared by every tunnel, and a deadline set through
// one tunnel would apply to all of them: closing a TLS connection ends by
// setting a write deadline of now, which made every later write to the proxy
// fail, for every tunnel. A tunnel is interrupted by closing it instead.

func (h *http2Conn) SetDeadline(time.Time) error { return nil }

func (h *http2Conn) SetReadDeadline(time.Time) error { return nil }

func (h *http2Conn) SetWriteDeadline(time.Time) error { return nil }

func (h *http2Conn) Close() error {
	return errors.Join(h.in.Close(), h.out.Close())
}

func (h *http2Conn) CloseConn() error {
	return h.Conn.Close()
}

func (h *http2Conn) CloseWrite() error {
	return h.in.Close()
}

func (h *http2Conn) CloseRead() error {
	return h.out.Close()
}
