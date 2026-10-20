package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"netexplorer/internal/discovery/network"
	"netexplorer/internal/enrichment/windows"
	"time"
)

// ImportWindows binds validated local evidence to the current host without network activity.
// One report per host and at most eight reports are retained; a new scan hides older evidence.
func (m *Manager) ImportWindows(scanID, hostID string, snapshot windows.Snapshot) (windows.Report, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[m.latest]
	if !ok || m.latest != scanID || m.closed {
		return windows.Report{}, fmt.Errorf("inventory changed; reopen the host")
	}
	found := false
	for _, host := range session.state.Report.Hosts {
		if host.ID == hostID {
			for _, address := range snapshot.Addresses {
				found = found || address == host.IP
			}
		}
	}
	if !found {
		return windows.Report{}, fmt.Errorf("windows inventory does not match a current host")
	}
	key := scanID + ":" + hostID
	if m.windowsReports == nil {
		m.windowsReports = map[string]windows.Report{}
	}
	if _, exists := m.windowsReports[key]; !exists {
		if len(m.windowsOrder) == 8 {
			delete(m.windowsReports, m.windowsOrder[0])
			m.windowsOrder = m.windowsOrder[1:]
		}
		m.windowsOrder = append(m.windowsOrder, key)
	}
	for i := range session.state.Report.Hosts {
		if session.state.Report.Hosts[i].ID == hostID {
			session.state.Report.Hosts[i].WindowsCaption = snapshot.Caption
		}
	}
	report := windows.Evaluate(snapshot, time.Now())
	m.windowsReports[key] = copyWindowsReport(report)
	m.appendLocked(session, "windows-updated", map[string]string{"host_id": hostID})
	return copyWindowsReport(report), nil
}

// WindowsReport returns a detached imported assessment for the current inventory host.
func (m *Manager) WindowsReport(hostID string) (windows.Report, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	report, ok := m.windowsReports[m.latest+":"+hostID]
	return copyWindowsReport(report), ok
}

// copyWindowsReport prevents callers from changing retained maps and slices.
func copyWindowsReport(report windows.Report) windows.Report {
	data, _ := json.Marshal(report)
	var copy windows.Report
	_ = json.Unmarshal(data, &copy)
	return copy
}

// CollectWindowsSSH reserves shared admission for one manual key-authenticated host.
func (m *Manager) CollectWindowsSSH(parent context.Context, selected network.Interface, hostID, user string) (windows.Report, error) {
	if err := windows.ValidateSSHUser(user); err != nil {
		return windows.Report{}, err
	}
	m.mu.Lock()
	if m.closed || m.ctx.Err() != nil {
		m.mu.Unlock()
		return windows.Report{}, context.Canceled
	}
	if m.active != "" {
		m.mu.Unlock()
		return windows.Report{}, ErrBusy
	}
	session, ok := m.sessions[m.latest]
	if !ok || session.state.Interface != selected.Name {
		m.mu.Unlock()
		return windows.Report{}, fmt.Errorf("inventory interface unavailable")
	}
	ip := ""
	for _, host := range session.state.Report.Hosts {
		if host.ID != hostID {
			continue
		}
		for _, port := range host.Ports {
			if port.Number == 22 && port.Protocol == "tcp" && port.State == "open" && (port.Service == "ssh" || port.Service == "ssh?" || port.Service == "unknown" || port.Service == "") {
				ip = host.IP
			}
		}
	}
	if ip == "" {
		m.mu.Unlock()
		return windows.Report{}, fmt.Errorf("an observed open SSH service on TCP 22 is required")
	}
	scanID := session.state.ID
	m.active = "windows:" + hostID
	m.wg.Add(1)
	m.mu.Unlock()
	defer m.wg.Done()
	defer func() { m.mu.Lock(); m.active = ""; m.mu.Unlock() }()
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	stop := context.AfterFunc(m.ctx, cancel)
	defer stop()
	defer cancel()
	snapshot, err := windows.CollectSSH(ctx, selected, ip, user)
	if ctx.Err() != nil {
		return windows.Report{}, ctx.Err()
	}
	if err != nil {
		return windows.Report{}, err
	}
	return m.ImportWindows(scanID, hostID, snapshot)
}
