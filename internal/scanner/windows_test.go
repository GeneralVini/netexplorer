package scanner

import (
	"netexplorer/internal/enrichment/windows"
	"netexplorer/internal/inventory"
	"testing"
	"time"
)

func TestWindowsImportScopeAndDetachedEvidence(t *testing.T) {
	m := checkManager(t, &fixtureChecks{})
	state, _ := m.Latest()
	id := inventory.HostID("192.0.2.20")
	s := windows.Snapshot{Addresses: []string{"192.0.2.21"}}
	if _, err := m.ImportWindows(state.ID, id, s); err == nil {
		t.Fatal("accepted wrong peer")
	}
	s = windows.Snapshot{Addresses: []string{"192.0.2.20"}, Components: map[string]string{"vbscript": "fixture"}, CollectedAt: time.Now()}
	report, err := m.ImportWindows(state.ID, id, s)
	if err != nil {
		t.Fatal(err)
	}
	s.Components["vbscript"] = "mutated"
	report.Snapshot.Components["vbscript"] = "caller"
	retained, ok := m.WindowsReport(id)
	if !ok || retained.Snapshot.Components["vbscript"] != "fixture" {
		t.Fatal("retained evidence is aliased")
	}
	if _, err := m.ImportWindows("old", id, s); err == nil {
		t.Fatal("accepted stale scan")
	}
}
