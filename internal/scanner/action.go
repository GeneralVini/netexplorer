package scanner

import (
	"context"
	"fmt"
	"time"

	"netexplorer/internal/discovery/network"
	"netexplorer/internal/enrichment/nmap"
	"netexplorer/internal/enrichment/services"
)

// ListShares reserves the shared slot for an explicit inventory-backed metadata request.
func (m *Manager) ListShares(parent context.Context, targetID string, selected network.Interface, port int) ([]nmap.Share, error) {
	m.mu.Lock()
	if m.closed || m.ctx.Err() != nil {
		m.mu.Unlock()
		return nil, context.Canceled
	}
	if m.active != "" {
		m.mu.Unlock()
		return nil, ErrBusy
	}
	session, ok := m.sessions[m.latest]
	if !ok || session.state.Interface != selected.Name {
		m.mu.Unlock()
		return nil, fmt.Errorf("inventory interface is unavailable")
	}
	ip := ""
	for _, host := range session.state.Report.Hosts {
		if host.ID == targetID {
			for _, observation := range host.Ports {
				if observation.Number == port && services.Annotate(host.IP, observation).Action == "shares" {
					ip = host.IP
				}
			}
		}
	}
	if ip == "" {
		m.mu.Unlock()
		return nil, fmt.Errorf("an observed open SMB port is required")
	}
	m.active = "shares:" + targetID
	m.wg.Add(1)
	m.mu.Unlock()
	defer m.wg.Done()
	defer func() { m.mu.Lock(); m.active = ""; m.mu.Unlock() }()
	ctx, cancel := context.WithTimeout(parent, 12*time.Second)
	stop := context.AfterFunc(m.ctx, cancel)
	defer stop()
	defer cancel()
	return nmap.New().ListShares(ctx, selected, ip, port)
}
