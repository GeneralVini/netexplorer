package scanner

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"netexplorer/internal/discovery/network"
	"netexplorer/internal/enrichment/nmap"
	"netexplorer/internal/inventory"
)

// monitorFixture counts attempts without creating a subprocess or sending packets.
type monitorFixture struct {
	mu      sync.Mutex
	counts  map[string]int
	block   bool
	started chan string
}

func (f *monitorFixture) Available() bool { return true }
func (f *monitorFixture) Discover(context.Context, network.Interface) ([]nmap.Host, error) {
	return nil, nil
}
func (f *monitorFixture) Scan(ctx context.Context, _ network.Interface, ip string) (nmap.Host, error) {
	f.mu.Lock()
	f.counts[ip]++
	f.mu.Unlock()
	if f.started != nil {
		f.started <- ip
	}
	if f.block {
		<-ctx.Done()
		return nmap.Host{}, ctx.Err()
	}
	return nmap.Host{IP: ip, Coverage: "common fixture", Ports: []nmap.Port{{Number: 80, Protocol: "tcp", State: "open"}}}, nil
}

func TestContinuousDiscoveryPreservesInspectionsAndFindsLaterHosts(t *testing.T) {
	f := &monitorFixture{counts: map[string]int{}}
	windows := 0
	runner := func(ctx context.Context, _ network.Interface, _ time.Duration, _ bool, _ func(string, any), update func([]inventory.Device)) (Report, error) {
		windows++
		devices := []inventory.Device{{ID: "first", IP: "192.0.2.20"}}
		if windows > 1 {
			devices = []inventory.Device{{ID: "later", IP: "192.0.2.21"}}
		}
		update(devices)
		return Report{Devices: devices}, nil
	}
	m := NewManager(context.Background(), runner, f)
	defer m.Close()
	// Exercise the internal scheduler with a short fixture interval; public admission requires >=10s.
	ctx, cancel := context.WithCancel(m.ctx)
	s := &session{state: State{ID: "fixture", Status: "running", Interface: scanInterface().Name, Continuous: true}, notify: make(chan struct{}), cancel: cancel}
	m.sessions[s.state.ID] = s
	m.latest = s.state.ID
	m.active = s.state.ID
	m.wg.Add(1)
	go m.run(ctx, s, scanInterface(), time.Second, ScanOptions{Continuous: true, AutoTCP: true, Interval: time.Millisecond})
	deadline := time.After(time.Second)
	for {
		state, _ := m.State(s.state.ID)
		if state.Window >= 3 && len(state.Report.Hosts) == 2 && !state.Report.Hosts[0].EnrichedAt.IsZero() && !state.Report.Hosts[1].EnrichedAt.IsZero() {
			break
		}
		select {
		case <-deadline:
			t.Fatal("monitor fixture timeout")
		case <-time.After(time.Millisecond):
		}
	}
	if _, err := m.Start(scanInterface(), time.Second, false); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	m.Cancel(s.state.ID)
	final := awaitScan(t, m, s.state.ID)
	if final.Status != "cancelled" || len(final.Report.Devices) != 2 || len(final.Report.Hosts) != 2 {
		t.Fatal(final)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.counts["192.0.2.20"] != 1 || f.counts["192.0.2.21"] != 1 {
		t.Fatal(f.counts)
	}
	events, _, _, _, _ := m.Events(s.state.ID, 0)
	found := false
	for _, event := range events {
		if event.Type == "window-complete" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing window notifications")
	}
}

func TestAutomaticInspectionCancellationAndAdmission(t *testing.T) {
	f := &monitorFixture{counts: map[string]int{}, block: true, started: make(chan string, 1)}
	m := NewManager(context.Background(), func(_ context.Context, _ network.Interface, _ time.Duration, _ bool, _ func(string, any), _ func([]inventory.Device)) (Report, error) {
		return Report{Devices: []inventory.Device{{ID: "peer", IP: "192.0.2.20"}}}, nil
	}, f)
	defer m.Close()
	if _, err := m.StartWithOptions(scanInterface(), time.Second, ScanOptions{Continuous: true, Interval: time.Second}); err == nil {
		t.Fatal("accepted short public interval")
	}
	id, err := m.StartWithOptions(scanInterface(), time.Second, ScanOptions{AutoTCP: true})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.started:
	case <-time.After(time.Second):
		t.Fatal("automatic scan did not start")
	}
	m.Cancel(id)
	state := awaitScan(t, m, id)
	if state.Status != "cancelled" || !state.Report.Hosts[0].EnrichedAt.IsZero() {
		t.Fatal(state)
	}
}

func TestAutoTCPQueueProgressAndWorkerLimit(t *testing.T) {
	f := &monitorFixture{counts: map[string]int{}, block: true, started: make(chan string, 4)}
	m := NewManager(context.Background(), func(context.Context, network.Interface, time.Duration, bool, func(string, any), func([]inventory.Device)) (Report, error) {
		return Report{Devices: []inventory.Device{{ID: "one", IP: "192.0.2.20"}, {ID: "two", IP: "192.0.2.21"}, {ID: "three", IP: "192.0.2.22"}}}, nil
	}, f)
	defer m.Close()
	id, err := m.StartWithOptions(scanInterface(), time.Second, ScanOptions{AutoTCP: true})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-f.started:
		case <-time.After(time.Second):
			t.Fatal("workers did not start")
		}
	}
	select {
	case <-f.started:
		t.Fatal("more than two TCP workers")
	case <-time.After(20 * time.Millisecond):
	}
	state, _ := m.State(id)
	if state.TCPScheduled != 3 || len(state.TCPActive) != 2 {
		t.Fatal(state.TCPScheduled, state.TCPActive)
	}
	queued := 0
	for _, host := range state.Report.Hosts {
		if host.AutoTCPStatus == "queued" {
			queued++
		}
	}
	if queued != 1 {
		t.Fatal("missing queued card", state.Report.Hosts)
	}
	m.Cancel(id)
	state = awaitScan(t, m, id)
	if state.TCPCompleted+state.TCPFailed != 3 || len(state.TCPActive) != 0 || state.Phase != "stopped" {
		t.Fatal(state)
	}
}

func TestMACRegistryEvidenceFollowsLatestObservation(t *testing.T) {
	previous := inventory.Host{IP: "192.0.2.20", MAC: "00:11:22:33:44:55", Vendor: "Old vendor", ObservedAt: time.Now().Add(-time.Minute)}
	current := inventory.Host{IP: previous.IP, MAC: "02:11:22:33:44:55", ObservedAt: time.Now()}
	for _, order := range [][]inventory.Host{{previous, current}, {current, previous}} {
		hosts := mergeHostEvidence(nil, order)
		if len(hosts) != 1 || hosts[0].MAC != current.MAC || hosts[0].Vendor != "" {
			t.Fatalf("stale MAC/vendor restored: %+v", hosts)
		}
	}
}

func TestPausePreservesSessionAndReleasesOnResumeOrCancel(t *testing.T) {
	m := NewManager(context.Background(), nil)
	defer m.Close()
	ctx, cancel := context.WithCancel(m.ctx)
	s := &session{state: State{ID: "pause-fixture", Status: "running", Continuous: true, Report: Report{Hosts: []inventory.Host{{ID: "known", IP: "192.0.2.20", EnrichedAt: time.Now()}}}}, notify: make(chan struct{}), cancel: cancel}
	m.sessions[s.state.ID] = s
	if !m.SetPaused(s.state.ID, true) {
		t.Fatal("pause rejected")
	}
	entered := make(chan struct{})
	released := make(chan bool, 1)
	go func() { close(entered); released <- m.waitUnpaused(ctx, s) }()
	<-entered
	select {
	case <-released:
		t.Fatal("paused work started")
	default:
	}
	state, _ := m.State(s.state.ID)
	if !state.Paused || len(state.Report.Hosts) != 1 || state.Report.Hosts[0].EnrichedAt.IsZero() {
		t.Fatal("pause lost evidence")
	}
	if !m.SetPaused(s.state.ID, false) {
		t.Fatal("resume rejected")
	}
	select {
	case ok := <-released:
		if !ok {
			t.Fatal("resume cancelled work")
		}
	case <-time.After(time.Second):
		t.Fatal("resume blocked")
	}
	m.SetPaused(s.state.ID, true)
	go func() { released <- m.waitUnpaused(ctx, s) }()
	m.Cancel(s.state.ID)
	select {
	case ok := <-released:
		if ok {
			t.Fatal("cancel admitted work")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel blocked")
	}
}

func TestDiscoveryWarningExpiresAfterSuccessfulWindow(t *testing.T) {
	old := []Warning{{Message: "LAN host discovery: context deadline exceeded"}, {Message: "context deadline exceeded"}, {IP: "192.0.2.20", Message: "Automatic TCP inspection failed"}}
	got := mergeWindowWarnings(old, nil)
	if len(got) != 1 || got[0].IP != "192.0.2.20" {
		t.Fatal("stale discovery warning retained or TCP evidence lost", got)
	}
	current := Warning{Message: "LAN host discovery: nmap discovery: 1/8 batches incomplete: context deadline exceeded"}
	got = mergeWindowWarnings(old, []Warning{current})
	if len(got) != 2 || got[0].Message != current.Message {
		t.Fatal("current incomplete coverage hidden", got)
	}
}
