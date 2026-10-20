package ssdp

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/net/ipv4"
	"log/slog"
	"net"
	"netexplorer/internal/discovery/network"
	"sort"
	"time"
)

// searchMessage requests all SSDP announcements with a three-second response window.
const searchMessage = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 3\r\nST: ssdp:all\r\n\r\n"

// maxResponses bounds the number of distinct announcements retained per scan.
const maxResponses = 4096

// Discover sends one SSDP M-SEARCH on selected and collects announcements for duration.
// The interface must be active, non-loopback, and multicast-capable with an IPv4
// address; duration must be between one second and one minute. Discovery uses
// the first IPv4 subnet, multicast TTL 1, and at most maxResponses announcements.
// Repeated IP/USN/ST/LOCATION tuples are discarded. A completed scan returns
// sorted results, including an empty slice when no devices respond. Cancellation
// or collection errors may return partial results with an error. Local IPv4
// addresses on all interfaces are excluded. No URLs are fetched.
func Discover(ctx context.Context, selected network.Interface, duration time.Duration) ([]Response, error) {
	return DiscoverWithProgress(ctx, selected, duration, nil)
}

// DiscoverWithProgress calls observe synchronously for each accepted announcement.
// The observer must return promptly and must not retain mutable shared state.
func DiscoverWithProgress(ctx context.Context, selected network.Interface, duration time.Duration, observe func(Response)) ([]Response, error) {
	if duration < time.Second || duration > time.Minute {
		return nil, fmt.Errorf("scan duration must be between 1s and 1m")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !selected.Up || selected.Loopback || !selected.Multicast || len(selected.IPv4) == 0 {
		return nil, fmt.Errorf("SSDP requires an active multicast IPv4 interface")
	}
	ip, subnet, err := net.ParseCIDR(selected.IPv4[0])
	if err != nil || ip.To4() == nil {
		return nil, fmt.Errorf("invalid interface IPv4 CIDR")
	}
	// Exclude every local alias before publishing evidence or attempting enrichment.
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("enumerate local addresses: %w", err)
	}
	excluded := map[string]bool{ip.String(): true}
	for _, address := range addresses {
		local, _, parseErr := net.ParseCIDR(address.String())
		if parseErr == nil && local.To4() != nil {
			excluded[local.String()] = true
		}
	}
	iface, err := net.InterfaceByName(selected.Name)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	packet := ipv4.NewPacketConn(conn)
	if err := packet.SetMulticastInterface(iface); err != nil {
		return nil, fmt.Errorf("select multicast interface: %w", err)
	}
	// Keep discovery on the local link, including on routed LANs.
	if err := packet.SetMulticastTTL(1); err != nil {
		return nil, err
	}
	slog.Info("SSDP discovery started", "interface", selected.Name, "duration", duration)
	results, err := exchangeProgress(ctx, conn, &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}, subnet, duration, observe, excluded)
	slog.Info("SSDP discovery finished", "responses", len(results))
	return results, err
}

// exchange sends a search through conn and collects in-subnet responses until
// duration elapses or ctx ends. The caller owns conn; cancellation closes it to
// interrupt socket I/O. Normal window expiry is successful, while context expiry
// returns an error with any partial results. Invalid datagrams are ignored.
func exchange(ctx context.Context, conn *net.UDPConn, destination *net.UDPAddr, subnet *net.IPNet, duration time.Duration) ([]Response, error) {
	return exchangeProgress(ctx, conn, destination, subnet, duration, nil, nil)
}

// exchangeProgress filters excluded source IPs before invoking its observer.
func exchangeProgress(ctx context.Context, conn *net.UDPConn, destination *net.UDPAddr, subnet *net.IPNet, duration time.Duration, observe func(Response), excluded map[string]bool) ([]Response, error) {
	deadline := time.Now().Add(duration)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			slog.Warn("unable to close canceled SSDP socket", "error", err)
		}
	})
	defer stop()
	if _, err := conn.WriteToUDP([]byte(searchMessage), destination); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	results := make([]Response, 0)
	// Preserve individual announcements; equipment-level merge belongs to the registry.
	type identity struct{ ip, usn, st, location string }
	seen := make(map[identity]bool)
	buffer := make([]byte, MaxPacketSize+1)
	for {
		n, source, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return results, ctx.Err()
			}
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				// The socket deadline may race with context's deadline notification.
				if limit, ok := ctx.Deadline(); ok && !time.Now().Before(limit) {
					return results, context.DeadlineExceeded
				}
				break
			}
			return results, err
		}
		if !subnet.Contains(source.IP) || excluded[source.IP.String()] {
			continue
		}
		response, err := Parse(buffer[:n])
		if err != nil {
			continue
		}
		response.IP = source.IP.String()
		response.SeenAt = time.Now().UTC()
		key := identity{response.IP, response.USN, response.ST, response.Location}
		if seen[key] {
			continue
		}
		if len(results) >= maxResponses {
			return results, fmt.Errorf("SSDP response limit reached (%d)", maxResponses)
		}
		seen[key] = true
		results = append(results, response)
		if observe != nil {
			observe(response)
		}
	}
	sort.Slice(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if a.IP != b.IP {
			return a.IP < b.IP
		}
		if a.USN != b.USN {
			return a.USN < b.USN
		}
		if a.ST != b.ST {
			return a.ST < b.ST
		}
		return a.Location < b.Location
	})
	return results, nil
}
