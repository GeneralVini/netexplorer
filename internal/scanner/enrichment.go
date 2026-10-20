// Package scanner coordinates discovery enrichment independently of HTTP handlers.
package scanner

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"netexplorer/internal/discovery/ssdp"
	"netexplorer/internal/enrichment/upnp"
	"netexplorer/internal/inventory"
)

// Fetcher downloads a document under a caller-supplied peer validation policy.
// Production callers must use safehttp.Client; implementations must honor ctx.
type Fetcher interface {
	Fetch(ctx context.Context, location, peerIP string) ([]byte, string, error)
}

// Warning records an enrichment failure while retaining the associated discovery evidence.
type Warning struct {
	// IP identifies the announcing peer.
	IP string `json:"ip"`
	// Location identifies the failed or skipped description.
	Location string `json:"location"`
	// Message describes the failure without treating it as a missing device.
	Message string `json:"message"`
}

// Report contains logical devices and enrichment failures from a single scan.
type Report struct {
	// Devices contains merged logical records with provenance.
	Devices []inventory.Device `json:"devices"`
	// Hosts contains IP-level evidence separately from logical devices.
	Hosts []inventory.Host `json:"hosts"`
	// Warnings records failed descriptions and bounded-work skips.
	Warnings []Warning `json:"warnings"`
}

// Enrich records every SSDP announcement, then fetches each IP/LOCATION pair once.
// It uses four workers and at most 256 description requests. The caller must
// bound ctx; cancellation preserves discovery evidence and returns ctx.Err().
// Individual HTTP/XML failures become warnings rather than failing the scan.
func Enrich(ctx context.Context, responses []ssdp.Response, fetcher Fetcher) (Report, error) {
	return EnrichWithProgress(ctx, responses, fetcher, nil)
}

// EnrichWithProgress publishes independent inventory snapshots after each parsed
// description. Calls are serialized; observers must return promptly.
func EnrichWithProgress(ctx context.Context, responses []ssdp.Response, fetcher Fetcher, observe func([]inventory.Device)) (Report, error) {
	registry := inventory.New()
	report := Report{Warnings: []Warning{}}
	type job struct{ response ssdp.Response }
	jobs := make([]job, 0)
	seen := map[string]bool{}
	for _, response := range responses {
		if err := registry.Observe(response); err != nil {
			report.Warnings = append(report.Warnings, Warning{IP: response.IP, Location: response.Location, Message: err.Error()})
			continue
		}
		key := response.IP + "|" + response.Location
		if seen[key] {
			continue
		}
		seen[key] = true
		if len(jobs) >= 256 {
			report.Warnings = append(report.Warnings, Warning{IP: response.IP, Location: response.Location, Message: "description request limit reached"})
			continue
		}
		jobs = append(jobs, job{response})
	}
	var progressMu sync.Mutex
	publish := func() {
		if observe != nil {
			progressMu.Lock()
			defer progressMu.Unlock()
			observe(registry.Snapshot())
		}
	}
	publish()
	queue := make(chan job)
	var workers sync.WaitGroup
	var warningMu sync.Mutex
	addWarning := func(response ssdp.Response, err error) {
		warningMu.Lock()
		defer warningMu.Unlock()
		report.Warnings = append(report.Warnings, Warning{IP: response.IP, Location: response.Location, Message: err.Error()})
	}
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for item := range queue {
				response := item.response
				if ctx.Err() != nil {
					addWarning(response, ctx.Err())
					continue
				}
				body, _, err := fetcher.Fetch(ctx, response.Location, response.IP)
				if err != nil {
					addWarning(response, err)
					continue
				}
				description, parseWarnings, err := upnp.ParseWithWarnings(body)
				if err != nil {
					addWarning(response, err)
					continue
				}
				// A description must contain the UUID claimed by this announcement.
				udn := strings.SplitN(response.USN, "::", 2)[0]
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(udn)), "uuid:") && !containsUDN(description.Device, udn) {
					addWarning(response, fmt.Errorf("description does not match announcing UUID"))
					continue
				}
				for _, warning := range parseWarnings {
					addWarning(response, fmt.Errorf("%s", warning))
				}
				if err := registry.Apply(response.IP, response.Location, description, response.SeenAt); err != nil {
					addWarning(response, err)
				}
				publish()
			}
		}()
	}
	for _, item := range jobs {
		select {
		case queue <- item:
		case <-ctx.Done():
			addWarning(item.response, ctx.Err())
		}
	}
	close(queue)
	workers.Wait()
	report.Devices = registry.Snapshot()
	report.Hosts = mergeHostEvidence(report.Devices, nil)
	sort.Slice(report.Warnings, func(i, j int) bool {
		a, b := report.Warnings[i], report.Warnings[j]
		if a.IP != b.IP {
			return a.IP < b.IP
		}
		if a.Location != b.Location {
			return a.Location < b.Location
		}
		return a.Message < b.Message
	})
	return report, ctx.Err()
}

// containsUDN checks root and embedded claims before correlation.
func containsUDN(device upnp.Device, udn string) bool {
	if strings.EqualFold(strings.TrimSpace(device.UDN), strings.TrimSpace(udn)) {
		return true
	}
	for _, child := range device.Children {
		if containsUDN(child, udn) {
			return true
		}
	}
	return false
}
