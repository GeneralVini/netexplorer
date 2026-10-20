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

// fixtureChecks implements all providers without connecting to any network.
type fixtureChecks struct {
	fixtureNmap
	check func(context.Context, string, nmap.Port, string) (nmap.CheckResult, error)
}

func (f *fixtureChecks) Check(ctx context.Context, _ network.Interface, ip string, port nmap.Port, id string) (nmap.CheckResult, error) {
	return f.check(ctx, ip, port, id)
}

func checkManager(t *testing.T, provider *fixtureChecks) *Manager {
	t.Helper()
	manager := NewManager(context.Background(), func(context.Context, network.Interface, time.Duration, bool, func(string, any), func([]inventory.Device)) (Report, error) {
		return Report{Hosts: []inventory.Host{{ID: inventory.HostID("192.0.2.20"), IP: "192.0.2.20", Ports: []nmap.Port{{Number: 445, Protocol: "tcp", State: "open", Service: "microsoft-ds"}}, EnrichedAt: time.Now().UTC()}}}, nil
	}, provider)
	t.Cleanup(manager.Close)
	id, err := manager.Start(scanInterface(), time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	awaitScan(t, manager, id)
	return manager
}

func awaitCheck(t *testing.T, manager *Manager, id string) CheckJob {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		job, ok := manager.CheckState(id)
		if !ok {
			t.Fatal("check job missing")
		}
		if job.Status != "running" {
			return job
		}
		select {
		case <-deadline.C:
			t.Fatal("check job did not finish")
		case <-time.After(time.Millisecond):
		}
	}
}

func TestChecksShareAdmissionAndDetachEvidence(t *testing.T) {
	entered, release := make(chan struct{}, 1), make(chan struct{})
	provider := &fixtureChecks{fixtureNmap: fixtureNmap{available: true}, check: func(ctx context.Context, ip string, port nmap.Port, id string) (nmap.CheckResult, error) {
		entered <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return nmap.CheckResult{}, ctx.Err()
		}
		return nmap.CheckResult{CheckID: id, IP: ip, Port: port.Number, Assessment: "positive", CVEs: []string{"CVE-2017-0143"}, Evidence: []nmap.Script{{ID: id, Tables: []nmap.ScriptTable{{Key: "fixture"}}}}}, nil
	}}
	manager := checkManager(t, provider)
	hostID := inventory.HostID("192.0.2.20")
	for _, test := range []struct {
		id   string
		port int
	}{{"vuln", 445}, {"smb-vuln-ms17-010", 80}, {"rdp-ntlm-info", 445}} {
		if _, err := manager.StartCheck(hostID, scanInterface(), test.id, test.port); err == nil {
			t.Fatal("invalid check admitted", test)
		}
	}
	job, err := manager.StartCheck(hostID, scanInterface(), "smb-vuln-ms17-010", 445)
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	if _, err := manager.Start(scanInterface(), time.Second, false); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if _, err := manager.StartNmap(hostID, scanInterface()); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if _, err := manager.ListShares(context.Background(), hostID, scanInterface(), 445); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if _, err := manager.StartCheck(hostID, scanInterface(), "smb2-time", 445); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	close(release)
	job = awaitCheck(t, manager, job.ID)
	if job.Status != "completed" || job.Result == nil {
		t.Fatal(job)
	}
	job.Result.CVEs[0] = "mutated"
	job.Result.Evidence[0].Tables[0].Key = "mutated"
	fresh, _ := manager.CheckState(job.ID)
	if fresh.Result.CVEs[0] != "CVE-2017-0143" || fresh.Result.Evidence[0].Tables[0].Key != "fixture" {
		t.Fatal("job snapshot aliases evidence")
	}
	state, _ := manager.Latest()
	if len(state.Report.Hosts[0].Ports) != 1 || state.Report.Hosts[0].Ports[0].Number != 445 {
		t.Fatal("check replaced port inventory")
	}
	if len(manager.CheckJobs(hostID)) != 1 {
		t.Fatal("missing retained evidence")
	}
}

func TestCheckCancellationRetentionAndShutdown(t *testing.T) {
	provider := &fixtureChecks{fixtureNmap: fixtureNmap{available: true}, check: func(ctx context.Context, _ string, _ nmap.Port, _ string) (nmap.CheckResult, error) {
		<-ctx.Done()
		return nmap.CheckResult{}, ctx.Err()
	}}
	manager := checkManager(t, provider)
	hostID := inventory.HostID("192.0.2.20")
	job, err := manager.StartCheck(hostID, scanInterface(), "smb2-time", 445)
	if err != nil {
		t.Fatal(err)
	}
	if !manager.CancelCheck(job.ID) {
		t.Fatal("missing cancel")
	}
	if completed := awaitCheck(t, manager, job.ID); completed.Status != "cancelled" || completed.Result != nil {
		t.Fatal(completed)
	}
	job, err = manager.StartCheck(hostID, scanInterface(), "smb2-time", 445)
	if err != nil {
		t.Fatal(err)
	}
	manager.Close()
	completed, _ := manager.CheckState(job.ID)
	if completed.Status != "cancelled" {
		t.Fatal(completed)
	}
	if _, err := manager.StartCheck(hostID, scanInterface(), "smb2-time", 445); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestCheckFailedRunsDoNotErasePreviousEvidence(t *testing.T) {
	calls := 0
	provider := &fixtureChecks{fixtureNmap: fixtureNmap{available: true}, check: func(_ context.Context, ip string, port nmap.Port, id string) (nmap.CheckResult, error) {
		calls++
		if calls > 1 {
			return nmap.CheckResult{}, context.DeadlineExceeded
		}
		return nmap.CheckResult{CheckID: id, IP: ip, Port: port.Number, Assessment: "positive"}, nil
	}}
	manager := checkManager(t, provider)
	hostID := inventory.HostID("192.0.2.20")
	first, err := manager.StartCheck(hostID, scanInterface(), "smb-vuln-ms17-010", 445)
	if err != nil {
		t.Fatal(err)
	}
	awaitCheck(t, manager, first.ID)
	for run := 0; run < 2; run++ {
		job, err := manager.StartCheck(hostID, scanInterface(), "smb-vuln-ms17-010", 445)
		if err != nil {
			t.Fatal(err)
		}
		if job := awaitCheck(t, manager, job.ID); job.Status != "timed_out" || job.Result != nil {
			t.Fatal(job)
		}
	}
	if first, ok := manager.CheckState(first.ID); !ok || first.Result.Assessment != "positive" {
		t.Fatal("failed retry erased evidence")
	}
	for run := 0; run < 6; run++ {
		job, err := manager.StartCheck(hostID, scanInterface(), "smb2-time", 445)
		if err != nil {
			t.Fatal(err)
		}
		awaitCheck(t, manager, job.ID)
	}
	if _, ok := manager.CheckState(first.ID); ok || len(manager.CheckJobs(hostID)) != 8 {
		t.Fatal("job retention is unbounded")
	}
}
