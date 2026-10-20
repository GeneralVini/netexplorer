package safehttp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testClient(t *testing.T, handler http.HandlerFunc) (*Client, string, *atomic.Int32) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := New("192.0.2.1/24")
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	client.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "192.0.2.10:80" {
			t.Errorf("connection not pinned: %s", address)
		}
		calls.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(server.URL, "http://"))
	}
	client.lookup = func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("192.0.2.10")}, nil
	}
	return client, "http://192.0.2.10/root.xml", &calls
}

func TestFetchPinnedPeer(t *testing.T) {
	client, url, calls := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "192.0.2.10" {
			t.Error(r.Host)
		}
		w.Write([]byte("description"))
	})
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	body, finalURL, err := client.Fetch(context.Background(), url, "192.0.2.10")
	if err != nil || string(body) != "description" || finalURL != url || calls.Load() != 1 {
		t.Fatalf("%s %s %v", body, finalURL, err)
	}
}

func TestRejectedTargets(t *testing.T) {
	client, url, calls := testClient(t, func(w http.ResponseWriter, r *http.Request) { t.Error("unexpected request") })
	for _, raw := range []string{"file:///tmp/test", "ftp://192.0.2.10/file", "http://user:pass@192.0.2.10/", "http://192.0.2.10:0/", "http://192.0.2.10:65536/", url + "#fragment", "http://127.0.0.1/", "http://192.0.2.11/", "http://169.254.169.254/", "http://[::1]/", "http://192.0.2.10:/"} {
		if _, _, err := client.Fetch(context.Background(), raw, "192.0.2.10"); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	for _, peer := range []string{"192.0.2.1", "192.0.2.0", "192.0.2.255", "198.51.100.1", "127.0.0.1", "224.0.0.1", "169.254.1.1", "bad"} {
		if _, _, err := client.Fetch(context.Background(), url, peer); err == nil {
			t.Errorf("accepted peer %s", peer)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("rejected URL dialed")
	}
}

func TestDNSRebinding(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		t.Run(map[bool]string{false: "rebinding", true: "mixed"}[mixed], func(t *testing.T) {
			client, _, calls := testClient(t, func(w http.ResponseWriter, r *http.Request) { t.Error("unsafe DNS request") })
			count := 0
			client.lookup = func(context.Context, string, string) ([]net.IP, error) {
				count++
				if mixed {
					return []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("198.51.100.1")}, nil
				}
				if count == 1 {
					return []net.IP{net.ParseIP("192.0.2.10")}, nil
				}
				return []net.IP{net.ParseIP("198.51.100.1")}, nil
			}
			if _, _, err := client.Fetch(context.Background(), "http://device.test/root.xml", "192.0.2.10"); err == nil {
				t.Fatal("accepted unsafe DNS")
			}
			if calls.Load() != 0 {
				t.Fatal("connected after unsafe DNS")
			}
		})
	}
}

func TestRedirectPolicy(t *testing.T) {
	for _, target := range []string{"http://198.51.100.1/", "http://127.0.0.1/", "http://192.0.2.11/", "/loop", "/final"} {
		t.Run(target, func(t *testing.T) {
			client, url, calls := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/final" {
					w.Write([]byte("ok"))
					return
				}
				http.Redirect(w, r, target, http.StatusFound)
			})
			body, _, err := client.Fetch(context.Background(), url, "192.0.2.10")
			if target == "/final" {
				if err != nil || string(body) != "ok" {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("accepted unsafe redirect")
			}
			if target != "/loop" && target != "/final" && calls.Load() != 1 {
				t.Fatal("redirect target was dialed")
			}
			if target == "/loop" && calls.Load() > 4 {
				t.Fatal("too many redirects")
			}
		})
	}
}

func TestResponseLimitsAndCancel(t *testing.T) {
	for _, mode := range []string{"size", "encoding", "status", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			client, url, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "size":
					w.Write([]byte(strings.Repeat("x", MaxBodySize+1)))
				case "encoding":
					w.Header().Set("Content-Encoding", "gzip")
					w.Write([]byte("compressed"))
				case "status":
					w.WriteHeader(500)
				case "cancel":
					<-r.Context().Done()
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			_, _, err := client.Fetch(ctx, url, "192.0.2.10")
			if err == nil {
				t.Fatal("accepted invalid response")
			}
			if mode == "cancel" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal(err)
			}
		})
	}
}

func TestPolicyConstruction(t *testing.T) {
	for _, cidr := range []string{"bad", "127.0.0.1/8", "169.254.1.1/16", "::1/128", "0.0.0.0/0"} {
		if _, err := New(cidr); err == nil {
			t.Fatal(cidr)
		}
	}
	client, _ := New("192.0.2.1/24")
	if err := client.validatePeer(netip.MustParseAddr("192.0.2.10")); err != nil {
		t.Fatal(err)
	}
}

func TestTLSVerificationRemainsEnabled(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted TLS request reached handler") }))
	defer server.Close()
	client, _ := New("192.0.2.1/24")
	client.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(server.URL, "https://"))
	}
	if _, _, err := client.Fetch(context.Background(), "https://192.0.2.10/root.xml", "192.0.2.10"); err == nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
}

func TestOtherLocalAddressesAreBlocked(t *testing.T) {
	client, _ := New("192.0.2.1/24")
	client.localAddresses[netip.MustParseAddr("192.0.2.10")] = true
	if err := client.validatePeer(netip.MustParseAddr("192.0.2.10")); err == nil {
		t.Fatal("other local interface address accepted")
	}
}
