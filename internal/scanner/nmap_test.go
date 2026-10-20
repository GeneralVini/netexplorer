package scanner

import (
	"context"
	"errors"
	"testing"
	"time"

	"netexplorer/internal/discovery/network"
	"netexplorer/internal/enrichment/nmap"
	"netexplorer/internal/inventory"
)

// fixtureNmap supplies deterministic host and port evidence without network actions.
type fixtureNmap struct {
	available bool
	scan      func(context.Context, string) (nmap.Host, error)
}

func (f *fixtureNmap) Available() bool { return f.available }
func (f *fixtureNmap) Discover(context.Context, network.Interface) ([]nmap.Host, error) {
	return []nmap.Host{{IP: "192.0.2.20"}, {IP: "192.0.2.30", Vendor: "Fixture Company"}}, nil
}
func (f *fixtureNmap) Scan(ctx context.Context, _ network.Interface, ip string) (nmap.Host, error) {
	return f.scan(ctx, ip)
}

func TestHostDiscoveryAndManualEnrichment(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	provider := &fixtureNmap{available: true, scan: func(ctx context.Context, ip string) (nmap.Host, error) {
		close(started)
		select {
		case <-release:
		case <-ctx.Done():
			return nmap.Host{}, ctx.Err()
		}
		return nmap.Host{IP: ip, Ports: []nmap.Port{{Number: 80, Protocol: "tcp", State: "open", Service: "http"}}}, nil
	}}
	runner := func(context.Context, network.Interface, time.Duration, bool, func(string, any), func([]inventory.Device)) (Report, error) {
		return Report{Devices: []inventory.Device{{ID: "logical-one", UDN: "uuid:one", IP: "192.0.2.20"}, {ID: "logical-two", UDN: "uuid:two", IP: "192.0.2.20"}}, Warnings: []Warning{}}, nil
	}
	manager := NewManager(context.Background(), runner, provider)
	defer manager.Close()
	id, err := manager.StartWithOptions(scanInterface(), time.Second, ScanOptions{AllHosts: true})
	if err != nil {
		t.Fatal(err)
	}
	state := awaitScan(t, manager, id)
	if len(state.Report.Devices) != 2 || len(state.Report.Hosts) != 2 {
		t.Fatal("physical/logical evidence conflated", state)
	}
	job, err := manager.StartNmap("logical-one", scanInterface())
	if err != nil {
		t.Fatal(err)
	}
	<-started
	if _, err := manager.Start(scanInterface(), time.Second, false); !errors.Is(err, ErrBusy) {
		t.Fatal("network admission not shared", err)
	}
	if _, err := manager.StartNmap("logical-two", scanInterface()); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	close(release)
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		job, ok := manager.NmapState(job.ID)
		if !ok {
			t.Fatal("job missing")
		}
		if job.Status == "completed" {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("job did not finish")
		case <-time.After(time.Millisecond):
		}
	}
	state, _ = manager.State(id)
	for _, device := range state.Report.Devices {
		if len(device.Services) != 0 {
			t.Fatal("TCP port attributed to logical UPnP service")
		}
	}
	found := false
	for _, host := range state.Report.Hosts {
		if host.IP == "192.0.2.20" {
			found = true
			if len(host.Ports) != 1 || host.EnrichedAt.IsZero() {
				t.Fatal(host)
			}
		}
	}
	if !found {
		t.Fatal("host missing")
	}
	state.Report.Hosts[0].Ports[0].Service = "mutated"
	actual, _ := manager.State(id)
	if actual.Report.Hosts[0].Ports[0].Service == "mutated" {
		t.Fatal("host snapshot aliases state")
	}
	if _, err := manager.StartNmap("missing", scanInterface()); err == nil {
		t.Fatal("unknown target admitted")
	}
	provider.available = false
	if _, err := manager.StartWithOptions(scanInterface(), time.Second, ScanOptions{AllHosts: true}); !errors.Is(err, nmap.ErrUnavailable) {
		t.Fatal(err)
	}
	if _, err := manager.Start(scanInterface(), time.Second, false); err != nil {
		t.Fatal("SSDP requires optional Nmap", err)
	}
}

func TestManualNmapCancellation(t *testing.T) {
	provider := &fixtureNmap{available: true, scan: func(ctx context.Context, ip string) (nmap.Host, error) { <-ctx.Done(); return nmap.Host{}, ctx.Err() }}
	manager := NewManager(context.Background(), func(context.Context, network.Interface, time.Duration, bool, func(string, any), func([]inventory.Device)) (Report, error) {
		return Report{Devices: []inventory.Device{{ID: "fixture", IP: "192.0.2.20"}}}, nil
	}, provider)
	defer manager.Close()
	id, err := manager.Start(scanInterface(), time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	awaitScan(t, manager, id)
	job, err := manager.StartNmap(inventory.HostID("192.0.2.20"), scanInterface())
	if err != nil {
		t.Fatal(err)
	}
	if !manager.CancelNmap(job.ID) {
		t.Fatal("cancel failed")
	}
	manager.Close()
	final, ok := manager.NmapState(job.ID)
	if !ok || final.Status != "cancelled" {
		t.Fatal(final)
	}
	state, _ := manager.State(id)
	if len(state.Report.Devices) != 1 || len(state.Report.Hosts[0].Ports) != 0 {
		t.Fatal("cancellation changed evidence")
	}
}
