package scanner

import (
	"context"
	"strings"
	"time"

	"netexplorer/internal/discovery/network"
	"netexplorer/internal/enrichment/macvendor"
	"netexplorer/internal/enrichment/nmap"
	"netexplorer/internal/inventory"
)

// mergeWindowDevices retains missing identities and bounds long-running inventory.
func mergeWindowDevices(previous, observed []inventory.Device) []inventory.Device {
	result := append([]inventory.Device{}, previous...)
	indexes := map[string]int{}
	for i, device := range result {
		indexes[device.ID] = i
	}
	for _, device := range observed {
		if index, ok := indexes[device.ID]; ok {
			result[index] = device
			continue
		}
		if len(result) >= 2048 {
			break
		}
		indexes[device.ID] = len(result)
		result = append(result, device)
	}
	return result
}

// autoTCP runs one queue worker for fixed common-profile inspections without NSE checks.
// The monitor owns shared admission; cancelling it also cancels the active process.
func (m *Manager) autoTCP(ctx context.Context, s *session, selected network.Interface, queue <-chan inventory.Host) {
	for {
		select {
		case <-ctx.Done():
			return
		case host, ok := <-queue:
			if !ok || ctx.Err() != nil || !m.waitUnpaused(ctx, s) {
				return
			}
			m.mu.Lock()
			s.state.TCPActive = append(s.state.TCPActive, host.IP)
			s.state.TCPIP = s.state.TCPActive[0]
			m.setTCPStatusLocked(s, host.IP, "running")
			m.progressLocked(s)
			m.appendLocked(s, "auto-tcp-started", map[string]string{"ip": host.IP, "host_id": host.ID})
			m.mu.Unlock()
			timeout, _ := nmap.ProfileTimeout("common")
			scanCtx, cancel := context.WithTimeout(ctx, timeout+10*time.Second)
			result, err := m.provider.Scan(scanCtx, selected, host.IP)
			if scanCtx.Err() != nil {
				err = scanCtx.Err()
			}
			cancel()
			m.mu.Lock()
			if err == nil && result.IP == host.IP {
				for i := range s.state.Report.Hosts {
					target := &s.state.Report.Hosts[i]
					if target.IP != host.IP {
						continue
					}
					if result.TTL > 0 {
						target.TTL = result.TTL
					}
					target.Ports = append([]nmap.Port{}, result.Ports...)
					target.Coverage = result.Coverage
					target.EnrichedAt = time.Now().UTC()
					if result.Vendor != "" {
						target.Vendor = result.Vendor
					}
					if result.MAC != "" {
						target.MAC = result.MAC
					}
					if macvendor.Local(target.MAC) {
						target.Vendor = ""
					} else if vendor := macvendor.Default.Lookup(target.MAC); vendor != "" {
						target.Vendor = vendor
					}
				}
			}
			status := "completed"
			if err != nil || result.IP != host.IP {
				status = "failed"
				message := "Automatic TCP inspection failed for " + host.IP
				if err != nil {
					message += ": " + err.Error()
				}
				if len(s.state.Report.Warnings) < 64 {
					s.state.Report.Warnings = append(s.state.Report.Warnings, Warning{IP: host.IP, Message: message})
				}
			}
			if status == "completed" {
				s.state.TCPCompleted++
			} else {
				s.state.TCPFailed++
			}
			m.setTCPStatusLocked(s, host.IP, status)
			active := []string{}
			for _, ip := range s.state.TCPActive {
				if ip != host.IP {
					active = append(active, ip)
				}
			}
			s.state.TCPActive = active
			s.state.TCPIP = ""
			if len(active) > 0 {
				s.state.TCPIP = active[0]
			}
			m.progressLocked(s)
			m.appendLocked(s, "auto-tcp-complete", map[string]string{"ip": host.IP, "host_id": host.ID, "status": status})
			m.mu.Unlock()
		}
	}
}

// mergeWindowWarnings bounds repeated failures without erasing earlier TCP errors.
func mergeWindowWarnings(previous, observed []Warning) []Warning {
	result := []Warning{}
	seen := map[string]bool{}
	// Discovery warnings describe the latest pass; TCP and per-host evidence remains retained.
	retained := []Warning{}
	for _, warning := range previous {
		if warning.IP == "" && (strings.HasPrefix(warning.Message, "LAN host discovery:") || warning.Message == context.DeadlineExceeded.Error()) {
			continue
		}
		retained = append(retained, warning)
	}
	for _, warning := range append(append([]Warning{}, observed...), retained...) {
		key := warning.IP + "|" + warning.Message
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, warning)
		if len(result) == 64 {
			break
		}
	}
	return result
}

// setTCPStatusLocked attaches automatic work state to the corresponding card.
func (m *Manager) setTCPStatusLocked(s *session, ip, status string) {
	for i := range s.state.Report.Hosts {
		if s.state.Report.Hosts[i].IP == ip {
			s.state.Report.Hosts[i].AutoTCPStatus = status
		}
	}
}

// progressLocked emits small timestamped progress without copying the inventory.
func (m *Manager) progressLocked(s *session) {
	m.appendLocked(s, "monitor-progress", map[string]any{"phase": s.state.Phase, "paused": s.state.Paused, "deadline": s.state.Deadline, "window": s.state.Window, "new_hosts": s.state.NewHosts, "interval_seconds": s.state.IntervalSeconds, "auto_tcp": s.state.AutoTCP, "tcp_scheduled": s.state.TCPScheduled, "tcp_completed": s.state.TCPCompleted, "tcp_failed": s.state.TCPFailed, "tcp_active": s.state.TCPActive})
}

// SetPaused suspends future work in a continuous session, preserving active work and evidence.
func (m *Manager) SetPaused(id string, paused bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok || s.state.Status != "running" || !s.state.Continuous {
		return false
	}
	if s.state.Paused == paused {
		return true
	}
	s.state.Paused = paused
	if paused {
		s.pauseWake = make(chan struct{})
	} else if s.pauseWake != nil {
		close(s.pauseWake)
		s.pauseWake = nil
	}
	m.progressLocked(s)
	m.appendLocked(s, "pause-changed", map[string]bool{"paused": paused})
	return true
}

// waitUnpaused gates new work without holding the manager lock while waiting.
func (m *Manager) waitUnpaused(ctx context.Context, s *session) bool {
	for {
		m.mu.Lock()
		paused, wake := s.state.Paused, s.pauseWake
		m.mu.Unlock()
		if ctx.Err() != nil {
			return false
		}
		if !paused {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-wake:
		}
	}
}
