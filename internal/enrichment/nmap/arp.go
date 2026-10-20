package nmap

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"netexplorer/internal/discovery/network"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// DiscoveryAvailable permits ARP-only discovery while TCP inspection still needs Nmap.
func (p *Provider) DiscoveryAvailable() bool {
	if p.Available() {
		return true
	}
	_, err := p.lookup("arp-scan")
	return p.arp != nil && err == nil
}

// discoverARP uses validated LAN targets; optional sudo runs only the fixed restricted helper.
func (p *Provider) discoverARP(ctx context.Context, selected scope, targets []netip.Addr) ([]Host, error) {
	if _, err := p.lookup("arp-scan"); err != nil {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	args := []string{"--interface=" + selected.iface, "--numeric", "--plain", "--ignoredups", "--retry=2", "--timeout=500", "--interval=5", "--format=${ip}\\t${mac}\\t${vendor}"}

	// Explicit paths prevent vendor files in the working directory overriding system data.
	// Vendor lookup occurs without root privileges after collection.
	args = append(args, "--ouifile="+os.DevNull, "--macfile="+os.DevNull)

	for _, ip := range targets {
		args = append(args, ip.String())
	}
	// #nosec G204 -- Fixed arp-scan executable and flags; interface and literal LAN targets validated by scopeFor/allows, no shell, sudo, user paths or packet spoofing options.
	command := exec.CommandContext(ctx, "arp-scan", args...)
	helperMode := os.Getenv("NETEXPLORER_ARP_SUDO_HELPER") == "1" && os.Geteuid() != 0
	if helperMode {
		// #nosec G204 -- Explicit opt-in, fixed sudo -n and root-owned helper; only validated interface name, no user executable/flags. Helper independently revalidates current /22–/30 LAN; sudoers restricts the installed interface.
		command = exec.CommandContext(ctx, "/usr/bin/sudo", "-n", "--", "/usr/local/libexec/netexplorer-arp", selected.iface)
		command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	}
	command.WaitDelay = 2 * time.Second
	output, stderr := &boundedBuffer{limit: 2 << 20}, &boundedBuffer{limit: 16 << 10}
	command.Stdout, command.Stderr = output, stderr
	runErr := command.Run()
	if output.overflow || stderr.overflow {
		return nil, fmt.Errorf("arp-scan output exceeds limit")
	}
	hosts, err := parseARP(output.Bytes(), selected)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return hosts, ctx.Err()
	}
	if runErr != nil {
		if helperMode {
			return hosts, fmt.Errorf("restricted ARP helper failed; verify the netexplorer sudoers rule and allowed interface")
		}
		reason := strings.ToLower(stderr.String())
		if strings.Contains(reason, "permission") || strings.Contains(reason, "operation not permitted") || strings.Contains(reason, "cap_net_raw") {
			return hosts, fmt.Errorf("ARP permission unavailable in direct mode. Start the dedicated account with make run; other discovery methods remain active")
		}
		return hosts, fmt.Errorf("arp-scan failed; verify interface and raw-socket permissions")
	}
	return hosts, nil
}

// parseARP accepts only canonical in-scope IPv4 and unicast six-byte MAC evidence.
func parseARP(data []byte, selected scope) ([]Host, error) {
	if len(data) > 2<<20 {
		return nil, fmt.Errorf("arp-scan output exceeds limit")
	}
	result := []Host{}
	seen := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 4096)
	for scanner.Scan() {
		fields := strings.SplitN(scanner.Text(), "\t", 3)
		if len(fields) != 3 {
			return nil, fmt.Errorf("invalid arp-scan row")
		}
		ip, err := netip.ParseAddr(fields[0])
		if err != nil || ip.String() != fields[0] || !selected.allows(ip) {
			return nil, fmt.Errorf("arp-scan returned an unexpected host")
		}
		mac, err := net.ParseMAC(fields[1])
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
			return nil, fmt.Errorf("invalid arp-scan MAC")
		}
		vendor := strings.TrimSpace(fields[2])
		if len(vendor) > 1024 || strings.ContainsAny(vendor, "\x00\r\t") {
			return nil, fmt.Errorf("invalid arp-scan vendor")
		}
		if old, ok := seen[ip.String()]; ok {
			if old != mac.String() {
				return result, fmt.Errorf("conflicting ARP MAC responses; first observation retained")
			}
			continue
		}
		if len(result) >= 1024 {
			return nil, fmt.Errorf("arp-scan host limit exceeded")
		}
		seen[ip.String()] = mac.String()
		if mac[0]&2 != 0 || strings.HasPrefix(vendor, "(Unknown") || vendor == "Unknown" {
			vendor = ""
		}
		result = append(result, Host{IP: ip.String(), MAC: mac.String(), Vendor: vendor, Sources: []string{"arp"}, Ports: []Port{}})
	}
	return result, scanner.Err()
}

// mergeDiscovery combines live observations without erasing richer MAC evidence.
func mergeDiscovery(groups ...[]Host) []Host {
	result := []Host{}
	indexes := map[string]int{}
	for _, group := range groups {
		for _, host := range group {
			if i, ok := indexes[host.IP]; ok {
				target := &result[i]
				if len(host.MDNS) > 0 {
					target.MDNS = append([]string{}, host.MDNS...)
				}
				if target.MAC == "" {
					target.MAC = host.MAC
				}
				if target.Vendor == "" && target.MAC == host.MAC {
					target.Vendor = host.Vendor
				}
				if target.TTL == 0 {
					target.TTL = host.TTL
				}
				for _, source := range host.Sources {
					found := false
					for _, old := range target.Sources {
						if old == source {
							found = true
						}
					}
					if !found {
						target.Sources = append(target.Sources, source)
					}
				}
			} else {
				indexes[host.IP] = len(result)
				result = append(result, host)
			}
		}
	}
	return result
}

// discoveryErrors preserves partial evidence when an optional discovery method fails.
func discoveryErrors(nmapErr, arpErr error) error {
	if nmapErr == nil && arpErr != nil && !errors.Is(arpErr, context.Canceled) && !errors.Is(arpErr, context.DeadlineExceeded) {
		return &DiscoveryWarning{cause: arpErr}
	}
	return errors.Join(nmapErr, arpErr)
}

// DiscoveryWarning reports an optional method failure with other evidence retained.
type DiscoveryWarning struct{ cause error }

func (warning *DiscoveryWarning) Error() string { return warning.cause.Error() }
func (warning *DiscoveryWarning) Unwrap() error { return warning.cause }

// ARPOnly validates current interface scope before running the restricted ARP action.
// This entry point is used by the root-owned helper, never accepts arbitrary flags.
func (p *Provider) ARPOnly(ctx context.Context, selected network.Interface) ([]Host, error) {
	s, err := p.scopeFor(selected)
	if err != nil {
		return nil, err
	}
	if s.prefix.Bits() < 22 || s.prefix.Bits() > 30 {
		return nil, fmt.Errorf("ARP helper requires a /22–/30 IPv4 LAN")
	}
	targets := []netip.Addr{}
	for ip := s.prefix.Addr(); ip.IsValid() && s.prefix.Contains(ip); ip = ip.Next() {
		if s.allows(ip) {
			targets = append(targets, ip)
		}
	}
	return p.discoverARP(ctx, s, targets)
}
