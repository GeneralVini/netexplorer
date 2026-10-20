// Package network enumerates local IPv4 interfaces and selects discovery interfaces.
// Default gateway detection currently uses the Linux proc filesystem.
package network

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Interface is a snapshot of a local interface and its IPv4 configuration.
// It is not a live view; callers must enumerate again to observe network changes.
type Interface struct {
	// Name is the operating system interface name.
	Name string `json:"name"`
	// Index identifies the interface for socket configuration.
	Index int `json:"index"`
	// MAC is the hardware address, or empty when unavailable.
	MAC string `json:"mac,omitempty"`
	// IPv4 contains local IPv4 addresses in CIDR notation.
	IPv4 []string `json:"ipv4"`
	// Up reports the operating system administrative up flag.
	Up bool `json:"up"`
	// Loopback reports whether the interface is a loopback interface.
	Loopback bool `json:"loopback"`
	// Multicast reports multicast support, not successful discovery connectivity.
	Multicast bool `json:"multicast"`
	// Gateway is the selected default IPv4 gateway, or empty when unknown.
	Gateway string `json:"gateway,omitempty"`
}

// List returns interface snapshots sorted by operating system index.
// It includes inactive and loopback interfaces, but records only IPv4 addresses.
// Enumeration errors are returned; missing default-route information is optional.
func List() ([]Interface, error) {
	native, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	routeName, gateway := DefaultRoute()
	result := make([]Interface, 0, len(native))
	for _, n := range native {
		addrs, err := n.Addrs()
		if err != nil {
			return nil, fmt.Errorf("interface %s: %w", n.Name, err)
		}
		item := Interface{Name: n.Name, Index: n.Index, MAC: n.HardwareAddr.String(), IPv4: []string{}, Up: n.Flags&net.FlagUp != 0, Loopback: n.Flags&net.FlagLoopback != 0, Multicast: n.Flags&net.FlagMulticast != 0}
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err == nil && ip.To4() != nil {
				item.IPv4 = append(item.IPv4, addr.String())
			}
		}
		if n.Name == routeName {
			item.Gateway = gateway
		}
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Index < result[j].Index })
	return result, nil
}

// usable reports whether an interface is eligible for IPv4 LAN selection.
func usable(i Interface) bool { return i.Up && !i.Loopback && len(i.IPv4) > 0 }

// Select chooses an active, non-loopback IPv4 interface from items.
// A nonempty requested name is mandatory and never falls back. Otherwise, Select
// prefers preferred, then multicast support, then the first eligible item.
// It returns an error when no eligible interface matches.
func Select(items []Interface, requested, preferred string) (Interface, error) {
	if requested != "" {
		for _, item := range items {
			if item.Name == requested {
				if !usable(item) {
					return Interface{}, fmt.Errorf("interface %s is not an active non-loopback IPv4 interface", requested)
				}
				return item, nil
			}
		}
		return Interface{}, fmt.Errorf("interface %s not found", requested)
	}
	for _, item := range items {
		if usable(item) && item.Name == preferred {
			return item, nil
		}
	}
	// Prefer multicast-capable interfaces for future SSDP discovery.
	for _, item := range items {
		if usable(item) && item.Multicast {
			return item, nil
		}
	}
	for _, item := range items {
		if usable(item) {
			return item, nil
		}
	}
	return Interface{}, fmt.Errorf("no active non-loopback IPv4 interface available")
}

// ParseRoutes reads Linux /proc/net/route data and returns the lowest-metric
// active default route with a gateway as an interface name and IPv4 address.
// Gateway values use little-endian hexadecimal encoding. Invalid records are
// ignored; absent routes or unreadable input yield empty strings unless a route
// was already parsed.
func ParseRoutes(r io.Reader) (string, string) {
	scanner := bufio.NewScanner(r)
	bestMetric := uint64(^uint64(0))
	name, gateway := "", ""
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 || fields[1] != "00000000" || fields[7] != "00000000" {
			continue
		}
		flags, e1 := strconv.ParseUint(fields[3], 16, 32)
		value, e2 := strconv.ParseUint(fields[2], 16, 32)
		metric, e3 := strconv.ParseUint(fields[6], 10, 64)
		if e1 != nil || e2 != nil || e3 != nil || flags&3 != 3 || metric >= bestMetric {
			continue
		}
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, uint32(value))
		name, gateway, bestMetric = fields[0], ip.String(), metric
	}
	return name, gateway
}

// DefaultRoute returns the interface name and gateway for the Linux default route.
// It returns empty strings when /proc/net/route is unavailable or has no matching
// route, allowing callers to use an interface-selection fallback.
func DefaultRoute() (string, string) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", ""
	}
	defer f.Close()
	return ParseRoutes(f)
}
