// Package nmap provides optional, bounded LAN discovery and single-IP TCP enrichment.
package nmap

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"netexplorer/internal/discovery/echo"
	"netexplorer/internal/discovery/mdns"
	"netexplorer/internal/enrichment/macvendor"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unicode"

	"netexplorer/internal/discovery/network"
)

// ErrUnavailable means the optional executable could not be located safely.
var ErrUnavailable = errors.New("nmap is unavailable on PATH")

// Port describes a host-level TCP service, not an advertised UPnP service.
type Port struct {
	// Number is the TCP port number.
	Number int `json:"number"`
	// Protocol identifies the transport.
	Protocol string `json:"protocol"`
	// State is the observed port state.
	State string `json:"state"`
	// Service is the detected service name.
	Service string `json:"service,omitempty"`
	// OSType is the operating-system family inferred by service detection.
	OSType string `json:"os_type,omitempty"`
	// Product is the detected product name.
	Product string `json:"product,omitempty"`
	// Tunnel records detected TLS wrapping.
	Tunnel string `json:"tunnel,omitempty"`
	// CPEs contains product identifiers reported by version detection.
	CPEs []string `json:"cpes,omitempty"`
	// Scripts retains bounded port-level NSE evidence.
	Scripts []Script `json:"scripts,omitempty"`
	// Version is the detected product version.
	Version string `json:"version,omitempty"`
}

// Host contains the remote IP and optional host-level metadata from Nmap XML.
type Host struct {
	// IP is the observed IPv4 address.
	IP string `json:"ip"`
	// MDNS contains unverified DNS-SD announcements from this peer.
	MDNS []string `json:"mdns,omitempty"`
	// TTL is the response TTL when supplied by Nmap, never an OS verdict.
	TTL int `json:"ttl,omitempty"`
	// MAC is an optional link-layer address.
	MAC string `json:"mac,omitempty"`
	// Vendor is the optional MAC vendor reported by Nmap, not a verified manufacturer.
	Vendor string `json:"vendor,omitempty"`
	// Sources records discovery methods without treating cached addresses as live.
	Sources []string `json:"sources,omitempty"`
	// Coverage records the requested TCP range after successful completion.
	Coverage string `json:"coverage,omitempty"`
	// Scripts retains bounded host-level NSE evidence.
	Scripts []Script `json:"scripts,omitempty"`
	// NmapVersion records the XML run version when available.
	NmapVersion string `json:"nmap_version,omitempty"`
	// Ports contains bounded TCP observations from manual enrichment.
	Ports []Port `json:"ports"`
}

// Provider locates Nmap for each explicit action; it never installs or elevates it.
type Provider struct {
	vendor func(string) string
	lookup func(string) (string, error)
	run    func(context.Context, []string) ([]byte, error)
	locals func() ([]net.Addr, error)
	echo   func(context.Context, netip.Addr, netip.Addr) bool
	mdns   func(context.Context, netip.Addr, string, func(netip.Addr) bool) []mdns.Observation
	arp    func(context.Context, scope, []netip.Addr) ([]Host, error)
}

// New returns a provider with native process execution and local-address snapshots.
func New() *Provider {
	p := &Provider{lookup: exec.LookPath, run: execute, locals: net.InterfaceAddrs, echo: echo.Probe}
	p.arp = p.discoverARP
	p.mdns = mdns.Discover
	p.vendor = macvendor.Default.Lookup
	return p
}

// Available reports executable lookup without running a scan or version command.
func (p *Provider) Available() bool { _, err := p.lookup("nmap"); return err == nil }

// scope freezes the selected IPv4 subnet and excludes every local address.
type scope struct {
	prefix netip.Prefix
	local  map[netip.Addr]bool
	iface  string
	source netip.Addr
}

// scopeFor validates interface arguments and fails closed on address enumeration errors.
func (p *Provider) scopeFor(selected network.Interface) (scope, error) {
	if !selected.Up || selected.Loopback || len(selected.IPv4) == 0 || selected.Name == "" || len(selected.Name) > 64 || strings.HasPrefix(selected.Name, "-") {
		return scope{}, fmt.Errorf("select an active IPv4 LAN interface")
	}
	for _, r := range selected.Name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("_.:-", r) {
			return scope{}, fmt.Errorf("invalid interface name")
		}
	}
	prefix, err := netip.ParsePrefix(selected.IPv4[0])
	if err != nil || !remoteAddress(prefix.Addr()) {
		return scope{}, fmt.Errorf("invalid interface IPv4 subnet")
	}
	addresses, err := p.locals()
	if err != nil {
		return scope{}, fmt.Errorf("enumerate local addresses: %w", err)
	}
	locals := map[netip.Addr]bool{prefix.Addr(): true}
	for _, cidr := range selected.IPv4 {
		if value, err := netip.ParsePrefix(cidr); err == nil {
			locals[value.Addr().Unmap()] = true
		}
	}
	for _, address := range addresses {
		if value, err := netip.ParsePrefix(address.String()); err == nil {
			locals[value.Addr().Unmap()] = true
		}
	}
	return scope{prefix: prefix.Masked(), local: locals, iface: selected.Name, source: prefix.Addr()}, nil
}

// remoteAddress excludes special addresses regardless of the selected prefix.
func remoteAddress(ip netip.Addr) bool {
	return ip.Is4() && ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

// allows rejects local, out-of-subnet, network, and broadcast targets.
func (s scope) allows(ip netip.Addr) bool {
	if !remoteAddress(ip) || !s.prefix.Contains(ip) || s.local[ip] {
		return false
	}
	if s.prefix.Bits() <= 30 {
		if ip == s.prefix.Addr() {
			return false
		}
		value := s.prefix.Addr().As4()
		mask := uint32(0xffffffff) >> s.prefix.Bits()
		base := uint32(value[0])<<24 | uint32(value[1])<<16 | uint32(value[2])<<8 | uint32(value[3])
		end := base | mask
		var last [4]byte
		binary.BigEndian.PutUint32(last[:], end)
		broadcast := netip.AddrFrom4(last)
		if ip == broadcast {
			return false
		}
	}
	return true
}

// Discover runs only host discovery on at most 1024 addresses in the selected subnet.
// It uses no port scan, scripts, DNS lookups, or privilege elevation. Callers must
// obtain explicit LAN authorization. Unresponsive/filtered hosts may be missed.
func (p *Provider) Discover(ctx context.Context, selected network.Interface) ([]Host, error) {
	s, err := p.scopeFor(selected)
	if err != nil {
		return nil, err
	}
	if s.prefix.Bits() < 22 {
		return nil, fmt.Errorf("LAN host discovery supports subnets of at most 1024 addresses (/22 or narrower)")
	}
	args := []string{"-sn", "-n", "-e", s.iface, "-PS22,80,443,445", "--max-retries", "1", "-T4", "--min-parallelism", "8", "--max-parallelism", "16", "--initial-rtt-timeout", "250ms", "--max-rtt-timeout", "1s", "-oX", "-"}
	targets := []netip.Addr{}
	count := 0
	for ip := s.prefix.Addr(); ip.IsValid() && s.prefix.Contains(ip); ip = ip.Next() {
		if s.allows(ip) {
			targets = append(targets, ip)
			count++
		}
	}
	if count == 0 {
		return []Host{}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	// ICMP and Nmap run within one shared deadline; fixtures can omit ICMP entirely.
	echoDone := make(chan []Host, 1)
	go func() { echoDone <- p.discoverEcho(ctx, s.source, targets) }()

	type arpResult struct {
		hosts []Host
		err   error
	}
	arpDone := make(chan arpResult, 1)
	go func() {
		if p.arp == nil {
			arpDone <- arpResult{}
			return
		}
		hosts, err := p.arp(ctx, s, targets)
		arpDone <- arpResult{hosts, err}
	}()
	mdnsDone := make(chan []mdns.Observation, 1)
	go func() {
		if p.mdns == nil {
			mdnsDone <- nil
			return
		}
		mdnsDone <- p.mdns(ctx, s.source, s.iface, s.allows)
	}()
	hosts, err := p.discoverBatches(ctx, args, targets)
	echoHosts := <-echoDone
	arp := <-arpDone
	result := []Host{}
	for _, host := range hosts {
		ip, parseErr := netip.ParseAddr(host.IP)
		if parseErr != nil || !s.allows(ip) {
			return nil, fmt.Errorf("nmap returned an unexpected host")
		}
		host.Ports = []Port{}
		host.Sources = []string{"nmap"}
		result = append(result, host)
	}
	if errors.Is(err, ErrUnavailable) && p.arp != nil {
		if _, lookupErr := p.lookup("arp-scan"); lookupErr == nil {
			err = nil
		}
	}
	// ARP's dedicated vendor registries take precedence over Nmap's optional mapping.
	announced := []Host{}
	for _, item := range <-mdnsDone {
		announced = append(announced, Host{IP: item.IP, MDNS: item.Details, Sources: []string{"mdns"}, Ports: []Port{}})
	}
	hosts = mergeDiscovery(arp.hosts, result, echoHosts, announced)
	for i := range hosts {
		if macvendor.Local(hosts[i].MAC) {
			hosts[i].Vendor = ""
		} else if p.vendor != nil {
			if vendor := p.vendor(hosts[i].MAC); vendor != "" {
				hosts[i].Vendor = vendor
			}
		}
	}
	return hosts, discoveryErrors(err, arp.err)
}

// discoverEcho bounds ICMP work to 64 sockets and two requests per remote IP.
func (p *Provider) discoverEcho(ctx context.Context, local netip.Addr, targets []netip.Addr) []Host {
	if p.echo == nil {
		return nil
	}
	jobs := make(chan netip.Addr)
	var mu sync.Mutex
	result := []Host{}
	var workers sync.WaitGroup
	for i := 0; i < 64; i++ {
		workers.Go(func() {
			for target := range jobs {
				if ctx.Err() != nil {
					return
				}
				if p.echo(ctx, local, target) {
					mu.Lock()
					result = append(result, Host{IP: target.String(), Sources: []string{"icmp"}, Ports: []Port{}})
					mu.Unlock()
				}
			}
		})
	}
	for _, target := range targets {
		select {
		case jobs <- target:
		case <-ctx.Done():
			close(jobs)
			workers.Wait()
			return result
		}
	}
	close(jobs)
	workers.Wait()
	return result
}

// Scan enriches one validated remote IPv4 using the common profile.
// Version-light probes are explicit; no custom NSE or vulnerability profiles,
// OS detection, UDP scans, or shell execution are requested. Results belong to the host IP, not to every embedded device.
func (p *Provider) Scan(ctx context.Context, selected network.Interface, target string) (Host, error) {
	return p.ScanProfile(ctx, selected, target, "common")
}

// ProfileTimeout returns the fixed deadline for an allowed inspection profile.
func ProfileTimeout(profile string) (time.Duration, error) {
	switch profile {
	case "", "common":
		return 2 * time.Minute, nil
	case "full":
		return 5 * time.Minute, nil
	default:
		return 0, fmt.Errorf("unknown TCP profile")
	}
}

// ScanProfile inspects one remote IP, with fixed common or full TCP coverage.
// No default/custom NSE profiles, OS detection, traceroute or vulnerability checks
// are requested. Nmap may run its own version-category probes under -sV.
func (p *Provider) ScanProfile(ctx context.Context, selected network.Interface, target, profile string) (Host, error) {
	timeout, err := ProfileTimeout(profile)
	if err != nil {
		return Host{}, err
	}
	s, err := p.scopeFor(selected)
	if err != nil {
		return Host{}, err
	}
	ip, err := netip.ParseAddr(target)
	if err != nil || !s.allows(ip) {
		return Host{}, fmt.Errorf("target is not a remote IPv4 in the selected LAN")
	}
	// Common coverage includes low ports, principal high-port services and reviewed historical associations.
	ports := "1-1024,1080,1243,1433,1521,1723,1883,2049,2375-2376,3306,3389,5000-5001,5357,5432,5900-5903,5985-5986,6200,6379,8000,8008,8080-8081,8443,8883,9000,9090,9100,9200,11211,12345-12346,20034,27017,27374,31337,54320-54321"
	if profile == "full" {
		ports = "1-65535"
	}
	args := []string{"-sT", "-Pn", "-sV", "--version-light", "-T4", "-p", ports, "-n", "-e", s.iface, "--max-retries", "1", "--max-parallelism", "16", "--host-timeout", fmt.Sprint(int(timeout/time.Second)) + "s", "-oX", "-", ip.String()}
	hosts, err := p.invoke(ctx, args, timeout+5*time.Second)
	if err != nil {
		return Host{}, err
	}
	if len(hosts) != 1 || hosts[0].IP != ip.String() {
		return Host{}, fmt.Errorf("nmap did not return the requested host")
	}
	hosts[0].Coverage = ports
	return hosts[0], nil
}

// invoke bounds total process runtime and validates XML even when exit is successful.
func (p *Provider) invoke(ctx context.Context, args []string, timeout time.Duration) ([]Host, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	_, err := p.lookup("nmap")
	if err != nil {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	data, err := p.run(ctx, args)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// boundedBuffer drains output while retaining a fixed maximum to avoid pipe deadlocks.
type boundedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

// Len returns the retained size, rather than all bytes drained from a process.
func (b *boundedBuffer) Len() int { return b.buffer.Len() }

// Bytes returns retained output after the subprocess has finished writing.
func (b *boundedBuffer) Bytes() []byte { return b.buffer.Bytes() }

// String returns bounded diagnostic output.
func (b *boundedBuffer) String() string { return b.buffer.String() }

// Write drains excess data. Do not embed bytes.Buffer: its promoted ReadFrom
// would let io.Copy bypass this limit when os/exec copies subprocess pipes.
func (b *boundedBuffer) Write(data []byte) (int, error) {
	n := len(data)
	available := b.limit - b.Len()
	if len(data) > available {
		b.overflow = true
		data = data[:available]
	}
	_, err := b.buffer.Write(data)
	return n, err
}

// execute uses validated fixed arguments without a shell and drains bounded output.
func execute(ctx context.Context, args []string) ([]byte, error) {
	// #nosec G204 -- Fixed nmap executable; only Discover/Scan/Check build args from validated interface names and literal in-subnet IPs. No shell or caller-supplied flags.
	command := exec.CommandContext(ctx, "nmap", args...)
	command.WaitDelay = 2 * time.Second
	out, stderr := &boundedBuffer{limit: 32 << 20}, &boundedBuffer{limit: 16 << 10}
	command.Stdout, command.Stderr = out, stderr
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		slog.Warn("Nmap process failed", "error", err, "stderr", stderr.String())
		return nil, fmt.Errorf("nmap execution failed; check server logs and interface permissions")
	}
	if out.overflow || stderr.overflow {
		return nil, fmt.Errorf("nmap output exceeds size limit")
	}
	return out.Bytes(), nil
}

// xmlRun decodes bounded service and NSE metadata; interpretation uses reviewed adapters.
type xmlRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Version string   `xml:"version,attr"`
	Hosts   []struct {
		TimedOut string   `xml:"timedout,attr"`
		Scripts  []Script `xml:"hostscript>script"`
		Status   struct {
			State string `xml:"state,attr"`
			TTL   int    `xml:"reason_ttl,attr"`
		} `xml:"status"`
		Addresses []struct {
			Addr   string `xml:"addr,attr"`
			Type   string `xml:"addrtype,attr"`
			Vendor string `xml:"vendor,attr"`
		} `xml:"address"`
		Ports []struct {
			Scripts  []Script `xml:"script"`
			Number   int      `xml:"portid,attr"`
			Protocol string   `xml:"protocol,attr"`
			State    struct {
				Value string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				OSType  string   `xml:"ostype,attr"`
				Name    string   `xml:"name,attr"`
				Product string   `xml:"product,attr"`
				Version string   `xml:"version,attr"`
				Tunnel  string   `xml:"tunnel,attr"`
				CPEs    []string `xml:"cpe"`
			} `xml:"service"`
		} `xml:"ports>port"`
	} `xml:"host"`
	Finished struct {
		Exit string `xml:"exit,attr"`
	} `xml:"runstats>finished"`
}

// Parse accepts bounded Nmap XML and requires a successful finished marker.
// Nmap's bare DOCTYPE is allowed; entity declarations, other directives, multiple
// roots, excessive depth/elements, and ambiguous address/port claims are rejected.
func Parse(data []byte) ([]Host, error) {
	if len(data) > 32<<20 {
		return nil, fmt.Errorf("nmap XML exceeds size limit")
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	depth, elements, roots := 0, 0, 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("nmap XML: %w", err)
		}
		switch value := token.(type) {
		case xml.StartElement:
			if depth == 0 {
				roots++
			}
			depth++
			elements++
			if depth > 32 || elements > 400000 || roots > 1 {
				return nil, fmt.Errorf("nmap XML structural limit exceeded")
			}
		case xml.EndElement:
			depth--
		case xml.Directive:
			if strings.TrimSpace(string(value)) != "DOCTYPE nmaprun" {
				return nil, fmt.Errorf("nmap XML directive rejected")
			}
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(value)) != "" {
				return nil, fmt.Errorf("text outside Nmap XML root")
			}
		}
	}
	if depth != 0 || roots != 1 {
		return nil, fmt.Errorf("incomplete Nmap XML")
	}
	var run xmlRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, err
	}
	if run.Finished.Exit != "success" || len(run.Hosts) > 1024 {
		return nil, fmt.Errorf("nmap XML is incomplete, failed, or exceeds host limit")
	}
	result := []Host{}
	seen := map[string]bool{}
	for _, item := range run.Hosts {
		if item.TimedOut == "true" {
			return nil, fmt.Errorf("nmap host scan timed out: %w", context.DeadlineExceeded)
		}
		if item.Status.State != "up" {
			continue
		}
		if len(run.Version) > 128 {
			return nil, fmt.Errorf("nmap version exceeds limit")
		}
		if err := validateScripts(item.Scripts); err != nil {
			return nil, err
		}
		if item.Status.TTL < 0 || item.Status.TTL > 255 {
			return nil, fmt.Errorf("invalid response TTL")
		}
		host := Host{TTL: item.Status.TTL, Ports: []Port{}, Scripts: item.Scripts, NmapVersion: run.Version}
		macCount := 0
		for _, a := range item.Addresses {
			switch a.Type {
			case "ipv4":
				if host.IP != "" {
					return nil, fmt.Errorf("duplicate Nmap IPv4 address")
				}
				ip, err := netip.ParseAddr(a.Addr)
				if err != nil || !ip.Is4() {
					return nil, fmt.Errorf("invalid Nmap IPv4 address")
				}
				host.IP = ip.String()
			case "mac":
				macCount++
				mac, err := net.ParseMAC(a.Addr)
				if err != nil || len(mac) != 6 || macCount > 1 {
					return nil, fmt.Errorf("invalid or duplicate Nmap MAC address")
				}
				host.MAC = mac.String()
				host.Vendor = a.Vendor
			}
		}
		if host.IP == "" || seen[host.IP] || len(item.Ports) > 65535 {
			return nil, fmt.Errorf("missing/duplicate host or excessive Nmap ports")
		}
		seen[host.IP] = true
		ports := map[int]bool{}
		for _, port := range item.Ports {
			if port.Number < 1 || port.Number > 65535 || port.Protocol != "tcp" || ports[port.Number] {
				return nil, fmt.Errorf("invalid or duplicate Nmap port")
			}
			if len(port.State.Value) > 64 || len(port.Service.Name) > 128 || len(port.Service.OSType)+len(port.Service.Product) > 1024 || len(port.Service.Version) > 256 || len(port.Service.CPEs) > 16 {
				return nil, fmt.Errorf("nmap service metadata exceeds limit")
			}
			for _, cpe := range port.Service.CPEs {
				if len(cpe) > 1024 {
					return nil, fmt.Errorf("nmap CPE exceeds limit")
				}
			}
			if err := validateScripts(port.Scripts); err != nil {
				return nil, err
			}
			ports[port.Number] = true
			host.Ports = append(host.Ports, Port{OSType: port.Service.OSType, Number: port.Number, Protocol: port.Protocol, State: port.State.Value, Service: port.Service.Name, Product: port.Service.Product, Version: port.Service.Version, Tunnel: port.Service.Tunnel, CPEs: port.Service.CPEs, Scripts: port.Scripts})
		}
		result = append(result, host)
	}
	return result, nil
}

// discoverBatches retains completed XML documents when another bounded discovery batch expires.
// Four workers with at most sixteen probes each keep aggregate Nmap parallelism bounded.
func (p *Provider) discoverBatches(ctx context.Context, flags []string, targets []netip.Addr) ([]Host, error) {
	const size = 32
	type outcome struct {
		hosts []Host
		err   error
	}
	count := (len(targets) + size - 1) / size
	results := make([]outcome, count)
	jobs := make(chan int, count)
	for i := 0; i < count; i++ {
		jobs <- i
	}
	close(jobs)
	var workers sync.WaitGroup
	for worker := 0; worker < 4 && worker < count; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				if ctx.Err() != nil {
					results[index].err = ctx.Err()
					continue
				}
				end := (index + 1) * size
				if end > len(targets) {
					end = len(targets)
				}
				args := append([]string{}, flags...)
				for _, target := range targets[index*size : end] {
					args = append(args, target.String())
				}
				results[index].hosts, results[index].err = p.invoke(ctx, args, 20*time.Second)
			}
		}()
	}
	workers.Wait()
	hosts := []Host{}
	failed := 0
	var cause error
	for _, result := range results {
		hosts = mergeDiscovery(hosts, result.hosts)
		if result.err != nil {
			failed++
			if cause == nil || errors.Is(result.err, context.DeadlineExceeded) {
				cause = result.err
			}
		}
	}
	if failed > 0 {
		return hosts, fmt.Errorf("nmap discovery: %d/%d batches incomplete: %w", failed, count, cause)
	}
	return hosts, nil
}
