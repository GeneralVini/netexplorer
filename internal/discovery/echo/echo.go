// Package echo checks IPv4 liveness with unprivileged ICMP datagram sockets.
package echo

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// packetConn permits controlled tests without sending packets to the LAN.
type packetConn interface {
	WriteTo([]byte, net.Addr) (int, error)
	ReadFrom([]byte) (int, net.Addr, error)
	SetDeadline(time.Time) error
	Close() error
}

// Probe sends at most two echo requests to a caller-validated LAN target.
// Linux ping sockets need no elevation when permitted by the kernel. Unsupported
// sockets or blocked replies simply add no evidence; they never imply a live host.
func Probe(ctx context.Context, local, target netip.Addr) bool {
	return probe(ctx, local, target, func(address string) (packetConn, error) { return icmp.ListenPacket("udp4", address) })
}

// probe correlates source, sequence, and a random payload; kernel-assigned IDs vary.
func probe(ctx context.Context, local, target netip.Addr, open func(string) (packetConn, error)) bool {
	if ctx.Err() != nil || !local.Is4() || !target.Is4() {
		return false
	}
	conn, err := open(local.String())
	if err != nil {
		return false
	}
	defer closePacket(conn)
	stop := context.AfterFunc(ctx, func() { closePacket(conn) })
	defer stop()
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return false
	}
	for seq := 1; seq <= 2 && ctx.Err() == nil; seq++ {
		deadline := time.Now().Add(time.Second)
		if bound, ok := ctx.Deadline(); ok && bound.Before(deadline) {
			deadline = bound
		}
		if conn.SetDeadline(deadline) != nil {
			return false
		}
		message := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{Seq: seq, Data: nonce}}
		data, err := message.Marshal(nil)
		if err != nil {
			return false
		}
		if _, err = conn.WriteTo(data, &net.UDPAddr{IP: net.IP(target.AsSlice())}); err != nil {
			return false
		}
		buffer := make([]byte, 512)
		for ctx.Err() == nil {
			n, peer, err := conn.ReadFrom(buffer)
			if err != nil {
				break
			}
			if matches(buffer[:n], peer, target, seq, nonce) {
				return true
			}
		}
	}
	return false
}

// matches accepts only an echo reply from the requested IP with this probe's nonce.
func matches(data []byte, peer net.Addr, target netip.Addr, seq int, nonce []byte) bool {
	addr, ok := peer.(*net.UDPAddr)
	if !ok {
		return false
	}
	ip, ok := netip.AddrFromSlice(addr.IP)
	if !ok || ip.Unmap() != target {
		return false
	}
	message, err := icmp.ParseMessage(1, data)
	if err != nil || message.Type != ipv4.ICMPTypeEchoReply || message.Code != 0 {
		return false
	}
	reply, ok := message.Body.(*icmp.Echo)
	return ok && reply.Seq == seq && bytes.Equal(reply.Data, nonce)
}

// closePacket ignores an already closed socket during cancellation cleanup.
func closePacket(conn packetConn) {
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		slog.Debug("ICMP socket close failed", "error", err)
	}
}
