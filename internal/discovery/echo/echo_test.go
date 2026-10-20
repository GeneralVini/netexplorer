package echo

import (
	"context"
	"errors"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// fixtureConn returns controlled echo replies, timeouts, or waits for cancellation.
type fixtureConn struct {
	reply  []byte
	writes int
	block  bool
	done   chan struct{}
	once   sync.Once
}

func (f *fixtureConn) WriteTo(data []byte, _ net.Addr) (int, error) {
	f.writes++
	m, _ := icmp.ParseMessage(1, data)
	m.Type = ipv4.ICMPTypeEchoReply
	f.reply, _ = m.Marshal(nil)
	return len(data), nil
}
func (f *fixtureConn) ReadFrom(data []byte) (int, net.Addr, error) {
	if f.block {
		<-f.done
		return 0, nil, net.ErrClosed
	}
	if f.writes == 1 {
		return 0, nil, errors.New("fixture timeout")
	}
	return copy(data, f.reply), &net.UDPAddr{IP: net.ParseIP("192.0.2.20")}, nil
}
func (*fixtureConn) SetDeadline(time.Time) error { return nil }
func (f *fixtureConn) Close() error              { f.once.Do(func() { close(f.done) }); return nil }
func TestProbeRetriesAndCancellation(t *testing.T) {
	local, target := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.20")
	f := &fixtureConn{done: make(chan struct{})}
	open := func(address string) (packetConn, error) {
		if address != local.String() {
			t.Errorf("incorrect binding %s", address)
		}
		return f, nil
	}
	if !probe(context.Background(), local, target, open) || f.writes != 2 {
		t.Fatal("controlled retry failed")
	}
	f = &fixtureConn{done: make(chan struct{}), block: true}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if probe(ctx, local, target, open) {
		t.Fatal("cancelled probe reported live")
	}
	if probe(ctx, local, target, func(string) (packetConn, error) { t.Fatal("cancelled context opened socket"); return nil, nil }) {
		t.Fatal("cancelled context succeeded")
	}
	if probe(context.Background(), local, target, func(string) (packetConn, error) { return nil, errors.New("permission denied") }) {
		t.Fatal("unsupported socket reported live")
	}
}
func TestReplyCorrelation(t *testing.T) {
	target := netip.MustParseAddr("192.0.2.20")
	nonce := []byte("fixture nonce")
	data, _ := (&icmp.Message{Type: ipv4.ICMPTypeEchoReply, Body: &icmp.Echo{ID: 888, Seq: 2, Data: nonce}}).Marshal(nil)
	peer := &net.UDPAddr{IP: net.IP(target.AsSlice())}
	if !matches(data, peer, target, 2, nonce) {
		t.Fatal("kernel-assigned ID rejected")
	}
	for _, test := range []struct {
		data  []byte
		peer  net.Addr
		seq   int
		nonce []byte
	}{{data, &net.UDPAddr{IP: net.ParseIP("192.0.2.21")}, 2, nonce}, {data, peer, 1, nonce}, {data, peer, 2, []byte("wrong nonce")}, {[]byte("malformed"), peer, 2, nonce}, {data, &net.IPAddr{IP: net.ParseIP("192.0.2.20")}, 2, nonce}} {
		if matches(test.data, test.peer, target, test.seq, test.nonce) {
			t.Fatal("unrelated reply accepted")
		}
	}
	request, _ := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{Seq: 2, Data: nonce}}).Marshal(nil)
	if matches(request, peer, target, 2, nonce) {
		t.Fatal("request accepted as reply")
	}
}
