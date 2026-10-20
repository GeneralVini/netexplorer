package windows

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func fixture(now time.Time) Snapshot {
	return Snapshot{SchemaVersion: 1, CollectedAt: now, ComputerName: "fixture", Addresses: []string{"192.0.2.20"}, Caption: "Microsoft Windows 7", Version: "6.1.7601", Build: "7601", ProductType: 1, ServicePackMajor: 1, Spooler: "running"}
}

func TestDecodeUntrustedEvidence(t *testing.T) {
	now := time.Now().UTC()
	valid := fixture(now)
	data, _ := json.Marshal(valid)
	if _, err := Decode(strings.NewReader(string(data)), "192.0.2.20", now); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{string(data) + "{}", strings.Replace(string(data), `"schema_version":1`, `"schema_version":2`, 1), strings.Replace(string(data), `"192.0.2.20"`, `"192.0.2.21"`, 1), strings.Replace(string(data), `"computer_name":"fixture"`, `"password":"secret"`, 1), strings.Repeat(" ", 262145)} {
		if _, err := Decode(strings.NewReader(input), "192.0.2.20", now); err == nil {
			t.Fatal("accepted invalid input")
		}
	}
	valid.CollectedAt = now.Add(-31 * 24 * time.Hour)
	data, _ = json.Marshal(valid)
	if _, err := Decode(strings.NewReader(string(data)), "192.0.2.20", now); err == nil {
		t.Fatal("accepted stale evidence")
	}
}

func TestPatchEvidenceDoesNotInferMissingUpdates(t *testing.T) {
	now := time.Now()
	s := fixture(now)
	r := Evaluate(s, now)
	if len(r.Findings) != 9 {
		t.Fatal(r)
	}
	for _, f := range r.Findings {
		if f.Assessment != "inconclusive" {
			t.Fatal(f)
		}
	}
	s.Hotfixes = []string{"KB4499164"}
	r = Evaluate(s, now)
	if r.Findings[0].Assessment != "negative" {
		t.Fatal(r.Findings[0])
	}
	s.Version = "10.0.19045"
	s.Build = "19045"
	r = Evaluate(s, now)
	if r.Findings[0].Assessment != "not_applicable" || r.Findings[2].Assessment != "inconclusive" {
		t.Fatal(r)
	}
	s.PointAndPrint = map[string]int{"NoWarningNoElevationOnInstall": 1}
	r = Evaluate(s, now)
	if len(r.Findings[1].Warnings) != 1 || r.Findings[1].Assessment != "inconclusive" {
		t.Fatal(r.Findings[1])
	}
	s.ProductType = 3
	s.Version = "6.1.7600"
	s.ServicePackMajor = 0
	r = Evaluate(s, now)
	if r.Findings[0].Assessment != "inconclusive" {
		t.Fatal("patch applied to wrong service pack")
	}
}
