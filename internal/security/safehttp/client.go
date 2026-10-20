// Package safehttp fetches discovered documents under a strict IPv4 peer policy.
package safehttp

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// MaxBodySize is the maximum accepted description size in bytes.
const MaxBodySize = 1 << 20

// Client restricts requests to a selected subnet and the announcing peer.
// Use New to construct a client. Its policy is immutable and safe for concurrent use.
type Client struct {
	subnet         netip.Prefix
	local          netip.Addr
	localAddresses map[netip.Addr]bool
	lookup         func(context.Context, string, string) ([]net.IP, error)
	dial           func(context.Context, string, string) (net.Conn, error)
}

// New creates a policy from the selected interface IPv4 CIDR. The prefix must
// describe a unicast LAN address; loopback, link-local, and unspecified addresses
// are rejected. No network requests are performed during construction.
func New(cidr string) (*Client, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !allowedAddress(prefix.Addr()) {
		return nil, fmt.Errorf("invalid LAN IPv4 CIDR")
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.IP(prefix.Addr().AsSlice())}}
	locals := map[netip.Addr]bool{prefix.Addr(): true}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("enumerate local addresses: %w", err)
	}
	for _, address := range addresses {
		if value, err := netip.ParsePrefix(address.String()); err == nil {
			locals[value.Addr().Unmap()] = true
		}
	}
	return &Client{subnet: prefix.Masked(), local: prefix.Addr(), localAddresses: locals, lookup: net.DefaultResolver.LookupIP, dial: dialer.DialContext}, nil
}

// allowedAddress excludes targets that cannot represent remote IPv4 LAN peers.
func allowedAddress(ip netip.Addr) bool {
	return ip.Is4() && ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && ip != netip.MustParseAddr("255.255.255.255")
}

// validatePeer requires a remote, unicast address within the selected subnet.
func (c *Client) validatePeer(peer netip.Addr) error {
	if !allowedAddress(peer) || !c.subnet.Contains(peer) || (peer == c.local || c.localAddresses[peer]) {
		return fmt.Errorf("peer is not a remote address in the selected LAN")
	}
	// Conventional network and directed-broadcast addresses are not remote hosts.
	bits := c.subnet.Bits()
	if bits <= 30 {
		base := c.subnet.Addr().As4()
		value := peer.As4()
		hostMask := uint32(0xffffffff) >> bits
		toInt := func(b [4]byte) uint32 { return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]) }
		if toInt(value) == toInt(base) || toInt(value) == toInt(base)|hostMask {
			return fmt.Errorf("network or broadcast peer rejected")
		}
	}
	return nil
}

// validateURL rejects unsupported schemes, credentials, fragments, and invalid ports.
func validateURL(raw string) (*url.URL, error) {
	if len(raw) > 4096 {
		return nil, fmt.Errorf("description URL too long")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.Opaque != "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("invalid description URL")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid URL port")
		}
	}
	if strings.HasSuffix(u.Host, ":") {
		return nil, fmt.Errorf("empty URL port")
	}
	return u, nil
}

// resolve verifies that a literal host or every DNS result matches the announcing peer.
// A second lookup can never change the connected address.
func (c *Client) resolve(ctx context.Context, host string, peer netip.Addr) error {
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip != peer {
			return fmt.Errorf("URL target differs from announcing peer")
		}
		return nil
	}
	addresses, err := c.lookup(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("resolve description host: %w", err)
	}
	if len(addresses) == 0 {
		return fmt.Errorf("description host has no addresses")
	}
	for _, ip := range addresses {
		address, ok := netip.AddrFromSlice(ip)
		if !ok || address.Unmap() != peer {
			return fmt.Errorf("DNS result differs from announcing peer")
		}
	}
	return nil
}

// Fetch downloads one bounded document and returns its final URL after redirects.
// Only HTTP/HTTPS requests to peerIP within the selected subnet are allowed.
// Each DNS result and redirect must match the announcing peer; connections use
// its literal address, bypass environment proxies, and bind to the local IPv4.
// TLS certificate verification remains enabled. The request has a five-second
// total timeout, at most three redirects, and no automatic decompression.
func (c *Client) Fetch(ctx context.Context, raw, peerIP string) ([]byte, string, error) {
	peer, err := netip.ParseAddr(peerIP)
	if err != nil {
		return nil, "", fmt.Errorf("invalid announcing IP")
	}
	if err := c.validatePeer(peer); err != nil {
		return nil, "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	u, err := validateURL(raw)
	if err != nil {
		return nil, "", err
	}
	if err := c.resolve(ctx, u.Hostname(), peer); err != nil {
		return nil, "", err
	}
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true, DisableKeepAlives: true,
		ResponseHeaderTimeout: 3 * time.Second, TLSHandshakeTimeout: 3 * time.Second,
		MaxResponseHeaderBytes: 32 * 1024,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			if err := c.resolve(ctx, host, peer); err != nil {
				return nil, err
			}
			return c.dial(ctx, "tcp4", net.JoinHostPort(peer.String(), port))
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return fmt.Errorf("redirect limit exceeded")
		}
		if _, err := validateURL(req.URL.String()); err != nil {
			return err
		}
		if via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https" {
			return fmt.Errorf("TLS downgrade rejected")
		}
		return c.resolve(req.Context(), req.URL.Hostname(), peer)
	}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("description HTTP status %d", response.StatusCode)
	}
	if response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		return nil, "", fmt.Errorf("encoded response rejected")
	}
	if response.ContentLength > MaxBodySize {
		return nil, "", fmt.Errorf("description exceeds size limit")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxBodySize+1))
	if err != nil {
		return nil, "", err
	}
	if len(body) > MaxBodySize {
		return nil, "", fmt.Errorf("description exceeds size limit")
	}
	return body, response.Request.URL.String(), nil
}
