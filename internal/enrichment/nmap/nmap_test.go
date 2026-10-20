package nmap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"netexplorer/internal/discovery/network"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func syntheticInterface() network.Interface {
	return network.Interface{Name: "fixture0", Up: true, IPv4: []string{"192.0.2.10/24", "192.0.2.11/24"}}
}
func fixtureProvider(t *testing.T, body []byte, captured *[]string) *Provider {
	t.Helper()
	var captureMu sync.Mutex
	return &Provider{lookup: func(string) (string, error) { return "/fixture/nmap", nil }, locals: func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.12"), Mask: net.CIDRMask(24, 32)}}, nil
	}, run: func(_ context.Context, args []string) ([]byte, error) {

		captureMu.Lock()
		*captured = append([]string{}, args...)
		captureMu.Unlock()
		return body, nil
	}}
}

func TestNmapXML(t *testing.T) {
	hosts, err := Parse(fixture(t, "nmap-hosts.xml"))
	if err != nil || len(hosts) != 2 || hosts[0].MAC != "00:11:22:33:44:55" || hosts[0].Vendor != "Fixture Company" {
		t.Fatal(hosts, err)
	}
	services, err := Parse(fixture(t, "nmap-services.xml"))
	if err != nil || len(services) != 1 || len(services[0].Ports) != 2 || services[0].Ports[0].Product != "Fixture HTTP" {
		t.Fatal(services, err)
	}
	valid := string(fixture(t, "nmap-services.xml"))
	for _, bad := range []string{"", valid + valid, valid + "trailing", strings.Replace(valid, "<host>", `<host timedout="true">`, 1), strings.Replace(valid, "DOCTYPE nmaprun", "DOCTYPE nmaprun [<!ENTITY attack SYSTEM 'file:///etc/passwd'>]", 1), strings.Replace(valid, "Fixture HTTP", "&unknown;", 1), strings.Replace(valid, `exit="success"`, `exit="error"`, 1), strings.Replace(valid, `addr="192.0.2.20"`, `addr="invalid"`, 1), strings.Replace(valid, `portid="443"`, `portid="80"`, 1), strings.Replace(valid, `protocol="tcp"`, `protocol="udp"`, 1), strings.Repeat("x", (32<<20)+1), strings.Repeat("<root>", 33) + strings.Repeat("</root>", 33)} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Fatal("unsafe Nmap XML accepted")
		}
	}
}

func TestProfilesAndLANValidation(t *testing.T) {
	var args []string
	p := fixtureProvider(t, fixture(t, "nmap-hosts.xml"), &args)
	hosts, err := p.Discover(context.Background(), syntheticInterface())
	if err != nil || len(hosts) != 2 {
		t.Fatal(hosts, err)
	}
	command := " " + strings.Join(args, " ") + " "
	if !strings.Contains(command, " -sn ") || strings.Contains(command, " -sV ") || strings.Contains(command, " -sT ") {
		t.Fatal("discovery used a port scan", args)
	}
	for _, excluded := range []string{"192.0.2.0", "192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.255"} {
		if strings.Contains(command, " "+excluded+" ") {
			t.Fatal("excluded target included", excluded)
		}
	}
	selected := syntheticInterface()
	selected.IPv4 = []string{"192.0.2.10/16"}
	args = nil
	if _, err := p.Discover(context.Background(), selected); err == nil || args != nil {
		t.Fatal("large subnet executed")
	}
	p = fixtureProvider(t, fixture(t, "nmap-services.xml"), &args)
	for _, target := range []string{"192.0.2.0", "192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.255", "198.51.100.20", "127.0.0.1", "169.254.1.1", "::1", "--script=evil", "192.0.2.20; touch file", "192.0.2.20/24"} {
		args = nil
		if _, err := p.Scan(context.Background(), syntheticInterface(), target); err == nil || args != nil {
			t.Fatal("invalid target executed", target)
		}
	}
	if _, err := p.Scan(context.Background(), syntheticInterface(), "192.0.2.20"); err != nil {
		t.Fatal(err)
	}
	command = " " + strings.Join(args, " ") + " "
	for _, flag := range []string{" -sT ", " -sV ", " --version-light ", " -T4 ", " -p 1-1024,", " -oX - "} {
		if !strings.Contains(command, flag) {
			t.Fatal("missing fixed profile", flag, args)
		}
	}
	for _, flag := range []string{"--script", "-A", "-O", "-sU", "--allports"} {
		if strings.Contains(command, flag) {
			t.Fatal("forbidden profile", args)
		}
	}
	p.run = func(_ context.Context, _ []string) ([]byte, error) {
		return fixture(t, "nmap-hosts.xml"), nil
	}
	if _, err := p.Scan(context.Background(), syntheticInterface(), "192.0.2.20"); err == nil {
		t.Fatal("unexpected additional hosts accepted")
	}
	p.lookup = func(string) (string, error) { return "", errors.New("missing") }
	if p.Available() {
		t.Fatal("missing Nmap available")
	}
	if _, err := p.Scan(context.Background(), syntheticInterface(), "192.0.2.20"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}

func TestContextAndOutputBounds(t *testing.T) {
	var args []string
	p := fixtureProvider(t, nil, &args)
	p.run = func(ctx context.Context, _ []string) ([]byte, error) { <-ctx.Done(); return nil, ctx.Err() }
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := p.Scan(ctx, syntheticInterface(), "192.0.2.20"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	buffer := &boundedBuffer{limit: 4}
	if n, err := buffer.Write([]byte("123456")); err != nil || n != 6 || buffer.Len() != 4 || !buffer.overflow {
		t.Fatal("output bound failed")
	}
}

// TestMain implements a controlled fake executable; no helper mode sends packets.
func TestMain(m *testing.M) {
	if os.Getenv("NETEXPLORER_NMAP_TEST_HELPER") == "1" {
		switch os.Getenv("NETEXPLORER_NMAP_TEST_MODE") {
		case "nse":
			if len(os.Args) == 3 && os.Args[1] == "--script-help" && os.Args[2] == "smb-vuln-ms17-010" {
				_, _ = os.Stdout.Write([]byte("smb-vuln-ms17-010\nCategories: safe vuln"))
				break
			}
			command := " " + strings.Join(os.Args[1:], " ") + " "
			for _, required := range []string{" -sT ", " -Pn ", " -n ", " -p 445 ", " --script smb-vuln-ms17-010 ", "smbnoguest=true,smbport=445,vulns.showall=true,smb-vuln-ms17-010.sharename=IPC$", " 192.0.2.20 "} {
				if !strings.Contains(command, required) {
					os.Exit(2)
				}
			}
			_, _ = os.Stdout.Write(checkXML("smb-vuln-ms17-010", ms17Table("VULNERABLE", ""), true))
		case "arp":
			for _, required := range []string{"--interface=fixture0", "--plain", "--ignoredups", "--retry=2", "--format=${ip}\\t${mac}\\t${vendor}", "192.0.2.20"} {
				found := false
				for _, arg := range os.Args[1:] {
					if arg == required {
						found = true
					}
				}
				if !found {
					os.Exit(2)
				}
			}
			_, _ = os.Stdout.Write([]byte("192.0.2.20\t00:11:22:33:44:55\tFixture vendor\n"))
		case "arp-permission":
			_, _ = os.Stderr.Write([]byte("Operation not permitted: CAP_NET_RAW"))
			os.Exit(1)
		case "shares":
			command := " " + strings.Join(os.Args[1:], " ") + " "
			for _, required := range []string{" -L 192.0.2.20 ", " -I 192.0.2.20 ", " -p 445 ", " -N ", " -U % ", " -g ", " --use-kerberos=off ", " --option=client min protocol=SMB2 ", " --option=interfaces=192.0.2.10 "} {
				if !strings.Contains(command, required) {
					os.Exit(2)
				}
			}
			for _, forbidden := range []string{" -c ", " --password ", " -A ", " //"} {
				if strings.Contains(command, forbidden) {
					os.Exit(2)
				}
			}
			_, _ = os.Stdout.Write([]byte("Disk|Public|Fixture files\nDisk|C$|Hidden\nIPC|IPC$|Metadata\n"))
		case "wait":
			time.Sleep(10 * time.Second)
		case "overflow":
			_, _ = os.Stdout.Write([]byte(strings.Repeat("x", (32<<20)+1)))
		default:
			_, _ = os.Stdout.Write([]byte(`<nmaprun><host><status state="up"/><address addr="192.0.2.20" addrtype="ipv4"/></host><runstats><finished exit="success"/></runstats></nmaprun>`))
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestRealSubprocessFixtureAndCancellation(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Symlink(executable, directory+"/nmap"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("NETEXPLORER_NMAP_TEST_HELPER", "1")
	p := New()
	p.locals = func() ([]net.Addr, error) { return nil, nil }
	result, err := p.Scan(context.Background(), syntheticInterface(), "192.0.2.20")
	if err != nil || result.IP != "192.0.2.20" {
		t.Fatal(result, err)
	}
	t.Setenv("NETEXPLORER_NMAP_TEST_MODE", "wait")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := p.Scan(ctx, syntheticInterface(), "192.0.2.20"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("subprocess was not cancelled", err)
	}
	t.Setenv("NETEXPLORER_NMAP_TEST_MODE", "overflow")
	if _, err := p.Scan(context.Background(), syntheticInterface(), "192.0.2.20"); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatal("subprocess output bound not enforced", err)
	}
}

func TestDiscoverAddsICMPOnlyHostsWithoutLocalProbes(t *testing.T) {
	var args []string
	p := fixtureProvider(t, fixture(t, "nmap-hosts.xml"), &args)
	p.echo = func(ctx context.Context, local, target netip.Addr) bool {
		if local.String() != "192.0.2.10" {
			t.Errorf("incorrect source %s", local)
		}
		for _, excluded := range []string{"192.0.2.0", "192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.255"} {
			if target.String() == excluded {
				t.Errorf("excluded ICMP target %s", target)
			}
		}
		return target.String() == "192.0.2.99" || target.String() == "192.0.2.20"
	}
	hosts, err := p.Discover(context.Background(), syntheticInterface())
	if err != nil || len(hosts) != 3 {
		t.Fatal(hosts, err)
	}
	for _, host := range hosts {
		if host.IP == "192.0.2.99" && strings.Join(host.Sources, ",") != "icmp" {
			t.Fatal("incorrect ICMP provenance", host)
		}
		if host.IP == "192.0.2.20" && strings.Join(host.Sources, ",") != "nmap,icmp" {
			t.Fatal("combined provenance missing", host)
		}
	}
	if !strings.Contains(strings.Join(args, " "), "-PS22,80,443,445") {
		t.Fatal("broader discovery profile missing")
	}
}

func TestDiscoverKeepsVerifiedICMPOnProcessFailure(t *testing.T) {
	var args []string
	p := fixtureProvider(t, fixture(t, "nmap-hosts.xml"), &args)
	observed := make(chan struct{})
	p.echo = func(ctx context.Context, local, target netip.Addr) bool {
		if target.String() == "192.0.2.99" {
			close(observed)
			return true
		}
		return false
	}
	p.run = func(ctx context.Context, args []string) ([]byte, error) {
		<-observed
		return nil, errors.New("fixture process failed")
	}
	hosts, err := p.Discover(context.Background(), syntheticInterface())
	if err == nil || len(hosts) != 1 || hosts[0].IP != "192.0.2.99" {
		t.Fatal("verified partial evidence lost", hosts, err)
	}
}

func TestFullProfileAndCoverage(t *testing.T) {
	var args []string
	provider := fixtureProvider(t, fixture(t, "nmap-services.xml"), &args)
	host, err := provider.ScanProfile(context.Background(), syntheticInterface(), "192.0.2.20", "full")
	if err != nil || host.Coverage != "1-65535" || !strings.Contains(strings.Join(args, " "), "-p 1-65535") {
		t.Fatal(host, err, args)
	}
	args = nil
	if _, err := provider.ScanProfile(context.Background(), syntheticInterface(), "192.0.2.20", "--script=vuln"); err == nil || args != nil {
		t.Fatal("unvalidated profile executed")
	}
}

func TestFullRangeXMLAndCPE(t *testing.T) {
	var data strings.Builder
	data.WriteString(`<nmaprun><host><status state="up"/><address addr="192.0.2.20" addrtype="ipv4"/><ports>`)
	for port := 1; port <= 65535; port++ {
		fmt.Fprintf(&data, `<port protocol="tcp" portid="%d"><state state="closed"/></port>`, port)
	}
	data.WriteString(`</ports></host><runstats><finished exit="success"/></runstats></nmaprun>`)
	hosts, err := Parse([]byte(data.String()))
	if err != nil || len(hosts) != 1 || len(hosts[0].Ports) != 65535 {
		t.Fatal("full-range XML rejected", err)
	}
	xml := strings.Replace(string(fixture(t, "nmap-services.xml")), `name="https"`, `name="https" tunnel="ssl"`, 1)
	xml = strings.Replace(xml, `</port>`, `<service name="fixture" tunnel="ssl"><cpe>cpe:/a:vendor:product:1.2.3</cpe></service></port>`, 1)
	hosts, err = Parse([]byte(xml))
	if err != nil || len(hosts[0].Ports[0].CPEs) != 1 || hosts[0].Ports[0].Tunnel != "ssl" {
		t.Fatal(hosts, err)
	}
}

func TestShareMetadataAndPeerValidation(t *testing.T) {
	shares := parseShares("Disk|Public|Public files\nDisk|C$|Admin\nIPC|IPC$|IPC\nDisk|Public|duplicate\nDisk|Photos|Albums\n")
	if len(shares) != 2 || shares[0].Name != "Public" || shares[1].Name != "Photos" {
		t.Fatal(shares)
	}
	var args []string
	provider := fixtureProvider(t, nil, &args)
	for _, target := range []string{"192.0.2.10", "198.51.100.20", "--command=ls"} {
		if _, err := provider.ListShares(context.Background(), syntheticInterface(), target, 445); err == nil {
			t.Fatal("invalid share target accepted", target)
		}
	}
	if _, err := provider.ListShares(context.Background(), syntheticInterface(), "192.0.2.20", 80); err == nil {
		t.Fatal("non-SMB port accepted")
	}
}

func TestShareSubprocessIsMetadataOnlyAndCancellable(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Symlink(executable, directory+"/smbclient"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	t.Setenv("NETEXPLORER_NMAP_TEST_HELPER", "1")
	t.Setenv("NETEXPLORER_NMAP_TEST_MODE", "shares")
	provider := New()
	provider.locals = func() ([]net.Addr, error) { return []net.Addr{}, nil }
	shares, err := provider.ListShares(context.Background(), syntheticInterface(), "192.0.2.20", 445)
	if err != nil || len(shares) != 1 || shares[0].Name != "Public" {
		t.Fatal(shares, err)
	}
	t.Setenv("NETEXPLORER_NMAP_TEST_MODE", "wait")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := provider.ListShares(ctx, syntheticInterface(), "192.0.2.20", 445); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	t.Setenv("NETEXPLORER_NMAP_TEST_MODE", "overflow")
	if _, err := provider.ListShares(context.Background(), syntheticInterface(), "192.0.2.20", 445); err == nil {
		t.Fatal("unbounded share output accepted")
	}
}

func TestBufferCopyCannotBypassLimit(t *testing.T) {
	buffer := &boundedBuffer{limit: 4}
	// LimitReader suppresses the source's WriterTo optimization and exercises io.Copy.
	count, err := io.Copy(buffer, io.LimitReader(strings.NewReader("123456789"), 9))
	if err != nil || count != 9 || buffer.String() != "1234" || !buffer.overflow {
		t.Fatal(count, err, buffer.String(), buffer.overflow)
	}
}

func TestParseOperatingSystemAndTTL(t *testing.T) {
	fixture := `<nmaprun><host><status state="up" reason_ttl="128"/><address addr="192.0.2.20" addrtype="ipv4"/><ports><port protocol="tcp" portid="135"><state state="open"/><service name="msrpc" product="Microsoft Windows RPC" ostype="Windows"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`
	hosts, err := Parse([]byte(fixture))
	if err != nil || len(hosts) != 1 || hosts[0].TTL != 128 || len(hosts[0].Ports) != 1 || hosts[0].Ports[0].OSType != "Windows" {
		t.Fatalf("hosts=%+v error=%v", hosts, err)
	}
	if _, err := Parse([]byte(strings.Replace(fixture, `reason_ttl="128"`, `reason_ttl="256"`, 1))); err == nil {
		t.Fatal("invalid TTL accepted")
	}
}

func TestDiscoveryBatchesRetainCompletedResults(t *testing.T) {
	var args []string
	p := fixtureProvider(t, fixture(t, "nmap-hosts.xml"), &args)
	var mu sync.Mutex
	calls := 0
	p.run = func(ctx context.Context, args []string) ([]byte, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		targets := []string{}
		for _, arg := range args {
			if ip, err := netip.ParseAddr(arg); err == nil && ip.Is4() {
				targets = append(targets, arg)
			}
		}
		if len(targets) > 32 {
			t.Error("unbounded batch")
		}
		if targets[0] == "192.0.2.1" {
			return nil, context.DeadlineExceeded
		}
		return []byte(fmt.Sprintf(`<nmaprun><host><status state="up"/><address addr="%s" addrtype="ipv4"/></host><runstats><finished exit="success"/></runstats></nmaprun>`, targets[0])), nil
	}
	targets := []netip.Addr{}
	for i := 1; i <= 130; i++ {
		targets = append(targets, netip.MustParseAddr(fmt.Sprintf("192.0.2.%d", i)))
	}
	hosts, err := p.discoverBatches(context.Background(), []string{"-sn"}, targets)
	if !errors.Is(err, context.DeadlineExceeded) || len(hosts) != 4 || calls != 5 {
		t.Fatal(hosts, err, calls)
	}
	if hosts[0].IP != "192.0.2.33" || hosts[3].IP != "192.0.2.129" {
		t.Fatal("completed batches lost", hosts)
	}
}
