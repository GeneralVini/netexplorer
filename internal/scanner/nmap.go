package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"netexplorer/internal/discovery/network"
	"netexplorer/internal/enrichment/macvendor"
	"netexplorer/internal/enrichment/nmap"
	"netexplorer/internal/inventory"
)

// NmapProvider separates optional process execution from scan session coordination.
type NmapProvider interface {
	// Available performs executable lookup without scanning.
	Available() bool
	// Discover observes bounded remote LAN hosts without port scanning.
	Discover(context.Context, network.Interface) ([]nmap.Host, error)
	// Scan performs explicit TCP enrichment of one previously discovered IP.
	Scan(context.Context, network.Interface, string) (nmap.Host, error)
}

// NmapJob describes a retained manual enrichment action and its target scope.
type NmapJob struct {
	// ID identifies the job for status and cancellation.
	ID string `json:"id"`
	// ScanID identifies the source inventory session.
	ScanID string `json:"scan_id"`
	// HostID identifies IP-level evidence, independent of logical UUIDs.
	HostID string `json:"host_id"`
	// IP is the sole network target.
	IP string `json:"ip"`
	// Profile identifies fixed common or full TCP coverage.
	Profile string `json:"profile"`
	// Status is running, completed, failed, or cancelled.
	Status string `json:"status"`
	// StartedAt records the UTC request start.
	StartedAt time.Time `json:"started_at"`
	// FinishedAt records completion when present.
	FinishedAt time.Time `json:"finished_at,omitempty"`
	// Error contains the terminal failure, when present.
	Error string `json:"error,omitempty"`
}

// nmapTask adds private cancellation without exposing it through JSON snapshots.
type nmapTask struct {
	job    NmapJob
	cancel context.CancelFunc
}

// NmapAvailable reports optional executable availability without running it.
func (m *Manager) NmapAvailable() bool { return m.provider.Available() }

// StartNmap reserves the shared network slot for one existing latest-inventory IP.
// The web layer obtains explicit authorization and re-enumerates the interface.
func (m *Manager) StartNmap(targetID string, selected network.Interface) (NmapJob, error) {
	return m.StartNmapProfile(targetID, selected, "common")
}

// StartNmapProfile admits a validated profile and reserves the shared network slot.
func (m *Manager) StartNmapProfile(targetID string, selected network.Interface, profile string) (NmapJob, error) {
	timeout, err := nmap.ProfileTimeout(profile)
	if err != nil {
		return NmapJob{}, err
	}
	if profile == "" {
		profile = "common"
	}
	if !m.provider.Available() {
		return NmapJob{}, nmap.ErrUnavailable
	}
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return NmapJob{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.ctx.Err() != nil {
		return NmapJob{}, context.Canceled
	}
	if m.active != "" {
		return NmapJob{}, ErrBusy
	}
	session, ok := m.sessions[m.latest]
	if !ok || session.state.Interface != selected.Name {
		return NmapJob{}, fmt.Errorf("target scan or interface is unavailable")
	}
	ip := ""
	for _, host := range session.state.Report.Hosts {
		if host.ID == targetID {
			ip = host.IP
			break
		}
	}
	if ip == "" {
		for _, device := range session.state.Report.Devices {
			if device.ID == targetID {
				ip = device.IP
				break
			}
		}
	}
	if ip == "" {
		return NmapJob{}, fmt.Errorf("target is not in the latest inventory")
	}
	ctx, cancel := context.WithTimeout(m.ctx, timeout+10*time.Second)
	id := hex.EncodeToString(bytes)
	task := &nmapTask{job: NmapJob{ID: id, ScanID: session.state.ID, HostID: inventory.HostID(ip), IP: ip, Profile: profile, Status: "running", StartedAt: time.Now().UTC()}, cancel: cancel}
	if len(m.nmapOrder) == 8 {
		delete(m.nmapJobs, m.nmapOrder[0])
		m.nmapOrder = m.nmapOrder[1:]
	}
	m.nmapJobs[id] = task
	m.nmapOrder = append(m.nmapOrder, id)
	m.active = "nmap:" + id
	m.wg.Add(1)
	go m.runNmap(ctx, task, selected, session)
	return task.job, nil
}

// runNmap attaches TCP evidence only to host records and always frees admission.
func (m *Manager) runNmap(ctx context.Context, task *nmapTask, selected network.Interface, s *session) {
	defer m.wg.Done()
	defer task.cancel()
	var result nmap.Host
	var err error
	if provider, ok := m.provider.(interface {
		ScanProfile(context.Context, network.Interface, string, string) (nmap.Host, error)
	}); ok {
		result, err = provider.ScanProfile(ctx, selected, task.job.IP, task.job.Profile)
	} else if task.job.Profile == "common" {
		result, err = m.provider.Scan(ctx, selected, task.job.IP)
	} else {
		err = fmt.Errorf("provider does not support full TCP coverage")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	task.job.FinishedAt = time.Now().UTC()
	task.job.Status = "completed"
	if err == nil && result.IP != task.job.IP {
		err = fmt.Errorf("nmap returned a different target")
	}
	if err != nil {
		task.job.Status = "failed"
		if errors.Is(err, context.Canceled) {
			task.job.Status = "cancelled"
		}
		task.job.Error = err.Error()
	} else {
		for i := range s.state.Report.Hosts {
			host := &s.state.Report.Hosts[i]
			if host.IP != result.IP {
				continue
			}
			if result.TTL > 0 {
				host.TTL = result.TTL
			}
			host.Ports = append([]nmap.Port{}, result.Ports...)
			host.EnrichedAt = task.job.FinishedAt
			host.Coverage = result.Coverage
			if result.MAC != "" {
				host.MAC = result.MAC
			}
			if result.Vendor != "" {
				host.Vendor = result.Vendor
			}
			if macvendor.Local(host.MAC) {
				host.Vendor = ""
			} else if vendor := macvendor.Default.Lookup(host.MAC); vendor != "" {
				host.Vendor = vendor
			}
			seen := false
			for _, source := range host.Sources {
				if source == "nmap" {
					seen = true
				}
			}
			if !seen {
				host.Sources = append(host.Sources, "nmap")
			}
		}
	}
	m.active = ""
	m.appendLocked(s, "host-updated", map[string]string{"host_id": task.job.HostID, "ip": task.job.IP, "status": task.job.Status})
}

// NmapState returns a value snapshot or false for expired/unknown jobs.
func (m *Manager) NmapState(id string) (NmapJob, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	task, ok := m.nmapJobs[id]
	if !ok {
		return NmapJob{}, false
	}
	return task.job, true
}

// CancelNmap requests termination while keeping prior host and logical evidence.
func (m *Manager) CancelNmap(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	task, ok := m.nmapJobs[id]
	if ok {
		task.cancel()
	}
	return ok
}

// LatestNmap returns the most recently accepted manual job for reload recovery.
func (m *Manager) LatestNmap() (NmapJob, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.nmapOrder) == 0 {
		return NmapJob{}, false
	}
	task, ok := m.nmapJobs[m.nmapOrder[len(m.nmapOrder)-1]]
	if !ok {
		return NmapJob{}, false
	}
	return task.job, true
}

// DiscoveryAvailable distinguishes host discovery tools from TCP inspection support.
func (m *Manager) DiscoveryAvailable() bool {
	if provider, ok := m.provider.(interface{ DiscoveryAvailable() bool }); ok {
		return provider.DiscoveryAvailable()
	}
	return m.provider.Available()
}
