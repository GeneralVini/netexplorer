package nmap

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"netexplorer/internal/discovery/network"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestARPValidationAndDeduplication(t *testing.T) {
	scope := scope{prefix: netip.MustParsePrefix("192.0.2.0/24"), local: map[netip.Addr]bool{netip.MustParseAddr("192.0.2.10"): true}}
	rows := "192.0.2.20\t00:11:22:33:44:55\tVendor\n192.0.2.20\t00:11:22:33:44:55\tVendor\n192.0.2.21\t02:11:22:33:44:55\tRandom\n"
	hosts, err := parseARP([]byte(rows), scope)
	if err != nil || len(hosts) != 2 || hosts[0].Vendor != "Vendor" || hosts[1].Vendor != "" {
		t.Fatalf("hosts=%+v error=%v", hosts, err)
	}
	for _, row := range []string{"192.0.2.10\t00:11:22:33:44:55\tLocal", "192.0.3.20\t00:11:22:33:44:55\tOutside", "192.0.2.20\tff:ff:ff:ff:ff:ff\tMulticast", "192.0.2.20\t00:00:00:00:00:00\tZero", "invalid", "192.0.2.20\t00:11:22:33:44:55\t" + strings.Repeat("a", 1025)} {
		if _, err := parseARP([]byte(row), scope); err == nil {
			t.Fatalf("accepted invalid row %q", row)
		}
	}
	hosts, err = parseARP([]byte(rows+"192.0.2.20\t00:11:22:33:44:66\tOther\n"), scope)
	if err == nil || len(hosts) != 2 {
		t.Fatal("conflicting MAC not reported")
	}
}

func TestDiscoveryMergesARPAndFallsBackOnPermissionError(t *testing.T) {
	for _, permissionDenied := range []bool{false, true} {
		var args []string
		p := fixtureProvider(t, fixture(t, "nmap-hosts.xml"), &args)
		p.arp = func(_ context.Context, s scope, targets []netip.Addr) ([]Host, error) {
			for _, target := range targets {
				if !s.allows(target) {
					t.Fatal("invalid ARP target")
				}
			}
			if permissionDenied {
				return nil, fmt.Errorf("raw-socket permission unavailable")
			}
			return []Host{{IP: "192.0.2.20", MAC: "00:11:22:33:44:55", Vendor: "ARP vendor", Sources: []string{"arp"}}}, nil
		}
		hosts, err := p.Discover(context.Background(), syntheticInterface())
		if permissionDenied && (err == nil || len(hosts) == 0) {
			t.Fatalf("fallback lost evidence: %+v %v", hosts, err)
		}
		if !permissionDenied {
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, host := range hosts {
				if host.IP == "192.0.2.20" {
					found = true
					if host.Vendor != "ARP vendor" || host.Sources[0] != "arp" {
						t.Fatal(host)
					}
				}
			}
			if !found {
				t.Fatal("ARP host missing")
			}
		}
	}
}

func TestARPSubprocessScopePermissionAndCancellation(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(executable, filepath.Join(dir, "arp-scan")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("NETEXPLORER_NMAP_TEST_HELPER", "1")
	t.Setenv("NETEXPLORER_NMAP_TEST_MODE", "arp")
	p := New()
	s, err := p.scopeFor(syntheticInterface())
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := p.discoverARP(context.Background(), s, []netip.Addr{netip.MustParseAddr("192.0.2.20")})
	if err != nil || len(hosts) != 1 || hosts[0].Vendor != "Fixture vendor" {
		t.Fatalf("hosts=%+v err=%v", hosts, err)
	}
	t.Setenv("NETEXPLORER_NMAP_TEST_MODE", "arp-permission")
	if _, err := p.discoverARP(context.Background(), s, []netip.Addr{netip.MustParseAddr("192.0.2.20")}); err == nil || !strings.Contains(err.Error(), "permission unavailable") {
		t.Fatal(err)
	}
	t.Setenv("NETEXPLORER_NMAP_TEST_MODE", "wait")
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := p.discoverARP(ctx, s, []netip.Addr{netip.MustParseAddr("192.0.2.20")}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

func TestARPOnlyDiscoveryWithoutNmap(t *testing.T) {
	var args []string
	p := fixtureProvider(t, nil, &args)
	p.lookup = func(name string) (string, error) {
		if name == "arp-scan" {
			return "/fixture/arp-scan", nil
		}
		return "", ErrUnavailable
	}
	p.arp = func(context.Context, scope, []netip.Addr) ([]Host, error) {
		return []Host{{IP: "192.0.2.20", Sources: []string{"arp"}}}, nil
	}
	if p.Available() || !p.DiscoveryAvailable() {
		t.Fatal("ARP discovery confused with Nmap availability")
	}
	hosts, err := p.Discover(context.Background(), syntheticInterface())
	if err != nil || len(hosts) != 1 || len(args) != 0 {
		t.Fatalf("hosts=%+v error=%v args=%v", hosts, err, args)
	}
}

func TestARPHelperRejectsUnsafeInterfacesAndSubnets(t *testing.T) {
	var args []string
	p := fixtureProvider(t, nil, &args)
	for _, selected := range []network.Interface{
		{Name: "-Ievil", Up: true, IPv4: []string{"192.0.2.10/24"}},
		{Name: "fixture0", Up: true, IPv4: []string{"192.0.2.10/16"}},
		{Name: "fixture0", Up: true, IPv4: []string{"192.0.2.10/31"}},
		{Name: "fixture0", Up: false, IPv4: []string{"192.0.2.10/24"}},
	} {
		if _, err := p.ARPOnly(context.Background(), selected); err == nil {
			t.Fatalf("unsafe helper interface accepted: %+v", selected)
		}
	}
}
