// Package mdns collects bounded, unauthenticated service advertisements as identity hints.
package mdns

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
)

// Observation retains only records announced by an allowed remote LAN peer.
type Observation struct {
	// IP identifies the packet sender; announced addresses cannot redirect discovery.
	IP string
	// Details contains bounded, unverified service, hostname and TXT hints.
	Details []string
}

// Discover requests common DNS-SD services using unicast-response questions.
// The source socket binds to the selected interface address; work lasts at most 3s.
func Discover(ctx context.Context, source netip.Addr, interfaceName string, allows func(netip.Addr) bool) []Observation {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(source.AsSlice())})
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil
	}
	socket := ipv4.NewPacketConn(conn)
	if socket.SetMulticastInterface(iface) != nil || socket.SetMulticastTTL(255) != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	msg := dnsmessage.Message{}
	for _, service := range []string{"_http._tcp.local.", "_https._tcp.local.", "_smb._tcp.local.", "_workstation._tcp.local.", "_device-info._tcp.local.", "_airplay._tcp.local.", "_googlecast._tcp.local.", "_ipp._tcp.local."} {
		name, e := dnsmessage.NewName(service)
		if e != nil {
			continue
		}
		msg.Questions = append(msg.Questions, dnsmessage.Question{Name: name, Type: dnsmessage.TypePTR, Class: dnsmessage.Class(0x8001)})
	}
	packet, err := msg.Pack()
	if err != nil {
		return nil
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = conn.WriteToUDP(packet, &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}); err != nil {
		return nil
	}
	byIP := map[string][]string{}
	buffer := make([]byte, 9000)
	for packets := 0; packets < 256; packets++ {
		n, peer, e := conn.ReadFromUDP(buffer)
		if e != nil {
			break
		}
		ip, ok := netip.AddrFromSlice(peer.IP)
		if !ok || peer.Port != 5353 || !allows(ip.Unmap()) {
			continue
		}
		ip = ip.Unmap()
		for _, detail := range Parse(buffer[:n]) {
			if len(byIP[ip.String()]) >= 16 {
				break
			}
			found := false
			for _, old := range byIP[ip.String()] {
				if old == detail {
					found = true
				}
			}
			if !found {
				byIP[ip.String()] = append(byIP[ip.String()], detail)
			}
		}
	}
	result := []Observation{}
	for ip, details := range byIP {
		if len(details) > 0 {
			result = append(result, Observation{IP: ip, Details: details})
		}
	}
	return result
}

// Parse bounds DNS records and retains textual evidence without deriving vendor or OS.
func Parse(packet []byte) []string {
	if len(packet) > 9000 {
		return nil
	}
	var msg dnsmessage.Message
	if msg.Unpack(packet) != nil || !msg.Header.Response {
		return nil
	}
	records := append(msg.Answers, msg.Additionals...)
	if len(records) > 128 {
		return nil
	}
	result := []string{}
	for _, record := range records {
		if record.Header.TTL == 0 {
			continue
		}
		var value string
		switch body := record.Body.(type) {
		case *dnsmessage.PTRResource:
			value = body.PTR.String()
		case *dnsmessage.SRVResource:
			value = body.Target.String()
		case *dnsmessage.TXTResource:
			for _, txt := range body.TXT {
				if strings.HasPrefix(txt, "model=") || strings.HasPrefix(txt, "manufacturer=") || strings.HasPrefix(txt, "md=") {
					value = txt
					break
				}
			}
		}
		if len(value) > 0 && len(value) <= 256 && !strings.ContainsAny(value, "\x00\r\n") {
			result = append(result, value)
		}
		if len(result) == 16 {
			break
		}
	}
	return result
}
