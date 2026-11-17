package tls_client

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// oldCookieHostKey is the split and join version buildCookieHostKey replaced.
func oldCookieHostKey(host string) string {
	hostParts := strings.Split(host, ".")

	switch len(hostParts) {
	case 3, 2:
		return fmt.Sprintf("%s.%s", hostParts[len(hostParts)-2], hostParts[len(hostParts)-1])
	default:
		return host
	}
}

func TestCookieHostKeyMatchesTheSplitAndJoinVersion(t *testing.T) {
	jar := &cookieJar{}

	hosts := []string{
		"", ".", "..", "...", "localhost", "localhost:8080", "example.com", "example.com:443",
		"www.example.com", "www.example.com:443", "a.b.c.d", "a.b.c.d.e", ".example.com",
		"example.com.", "a..b", "127.0.0.1", "127.0.0.1:80", "[::1]:443", "xn--bcher-kva.example",
	}

	for _, host := range hosts {
		got := jar.buildCookieHostKey(&url.URL{Host: host})
		if want := oldCookieHostKey(host); got != want {
			t.Errorf("host %q: got key %q, want %q", host, got, want)
		}
	}
}
