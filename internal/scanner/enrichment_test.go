package scanner

import (
	"context"
	"errors"
	"fmt"
	"netexplorer/internal/discovery/ssdp"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

type fixtureFetcher struct {
	calls atomic.Int32
	body  []byte
	err   error
}

func (f *fixtureFetcher) Fetch(ctx context.Context, location, peerIP string) ([]byte, string, error) {
	f.calls.Add(1)
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	return f.body, location, f.err
}

func TestEnrichmentAndFailures(t *testing.T) {
	body, err := os.ReadFile("../../testdata/minidlna-rootdesc.xml")
	if err != nil {
		t.Fatal(err)
	}
	responses := []ssdp.Response{{IP: "192.0.2.10", USN: "uuid:fixture-server::upnp:rootdevice", Location: "http://192.0.2.10/root"}, {IP: "192.0.2.10", USN: "uuid:fixture-server::urn:service", Location: "http://192.0.2.10/root"}}
	fetcher := &fixtureFetcher{body: body}
	report, err := Enrich(context.Background(), responses, fetcher)
	if err != nil || len(report.Devices) != 2 || len(report.Warnings) != 0 || fetcher.calls.Load() != 1 {
		t.Fatalf("%+v %v", report, err)
	}
	fetcher = &fixtureFetcher{err: errors.New("blocked URL")}
	report, err = Enrich(context.Background(), responses, fetcher)
	if err != nil || len(report.Devices) != 1 || len(report.Warnings) != 1 {
		t.Fatalf("%+v %v", report, err)
	}
	fetcher = &fixtureFetcher{body: []byte("malformed XML")}
	report, _ = Enrich(context.Background(), responses, fetcher)
	if len(report.Warnings) != 1 {
		t.Fatal(report)
	}
	responses[0].USN = "uuid:unrelated"
	report, _ = Enrich(context.Background(), responses[:1], &fixtureFetcher{body: body})
	if len(report.Warnings) != 1 || len(report.Devices) != 1 {
		t.Fatal("mismatched description accepted")
	}
}

func TestCancellationRetainsDiscovery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := Enrich(ctx, []ssdp.Response{{IP: "192.0.2.10", USN: "uuid:test", Location: "http://192.0.2.10/root"}}, &fixtureFetcher{})
	if !errors.Is(err, context.Canceled) || len(report.Devices) != 1 || len(report.Warnings) != 1 {
		t.Fatalf("%+v %v", report, err)
	}
}

type boundedFetcher struct {
	active, max, calls atomic.Int32
	body               []byte
}

func (f *boundedFetcher) Fetch(ctx context.Context, location, peerIP string) ([]byte, string, error) {
	active := f.active.Add(1)
	defer f.active.Add(-1)
	f.calls.Add(1)
	for old := f.max.Load(); active > old; old = f.max.Load() {
		if f.max.CompareAndSwap(old, active) {
			break
		}
	}
	time.Sleep(time.Millisecond)
	return f.body, location, nil
}
func TestWorkerAndRequestLimits(t *testing.T) {
	body, err := os.ReadFile("../../testdata/minidlna-rootdesc.xml")
	if err != nil {
		t.Fatal(err)
	}
	responses := make([]ssdp.Response, 260)
	for i := range responses {
		responses[i] = ssdp.Response{IP: "192.0.2.10", USN: "uuid:fixture-server", Location: fmt.Sprintf("http://192.0.2.10/%d", i)}
	}
	fetcher := &boundedFetcher{body: body}
	report, err := Enrich(context.Background(), responses, fetcher)
	if err != nil || fetcher.calls.Load() != 256 || fetcher.max.Load() > 4 || len(report.Warnings) != 4 {
		t.Fatalf("calls=%d workers=%d warnings=%d error=%v", fetcher.calls.Load(), fetcher.max.Load(), len(report.Warnings), err)
	}
}

func TestDuplicateUDNEnrichmentPreservesValidProfiles(t *testing.T) {
	body, err := os.ReadFile("../../testdata/duplicate-udn-rootdesc.xml")
	if err != nil {
		t.Fatal(err)
	}
	response := ssdp.Response{IP: "192.0.2.20", USN: "uuid:fixture-gateway::upnp:rootdevice", Location: "http://192.0.2.20/root.xml", SeenAt: time.Now().UTC()}
	report, err := Enrich(context.Background(), []ssdp.Response{response}, &fixtureFetcher{body: body})
	if err != nil || len(report.Devices) != 3 || len(report.Warnings) != 1 {
		t.Fatalf("%+v %v", report, err)
	}
	for _, device := range report.Devices {
		if device.Attributes["friendly_name"] == "" || device.Attributes["friendly_name"] == "Fixture Duplicate LAN" {
			t.Fatal("invalid profile retained", device)
		}
		if device.UDN == "uuid:fixture-connection" && (device.ParentID == "" || len(device.Services) != 1) {
			t.Fatal("hierarchy or services lost", device)
		}
	}
}
