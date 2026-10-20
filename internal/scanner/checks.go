package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"netexplorer/internal/discovery/network"
	"netexplorer/internal/enrichment/nmap"
)

// checkProvider performs a reviewed check without changing TCP inventory.
type checkProvider interface {
	Check(context.Context, network.Interface, string, nmap.Port, string) (nmap.CheckResult, error)
}

// CheckJob separates execution status from the retained script assessment.
type CheckJob struct {
	// ID identifies this job for status and cancellation.
	ID string `json:"id"`
	// ScanID ties evidence to the inventory session in which it was requested.
	ScanID string `json:"scan_id"`
	// HostID identifies the known inventory host.
	HostID string `json:"host_id"`
	// IP is the single remote peer.
	IP string `json:"ip"`
	// Port identifies the existing observed service.
	Port int `json:"port"`
	// CheckID identifies the reviewed script.
	CheckID string `json:"check_id"`
	// Status is running, completed, failed, timed_out or cancelled.
	Status string `json:"status"`
	// StartedAt records admission time.
	StartedAt time.Time `json:"started_at"`
	// FinishedAt records terminal time.
	FinishedAt time.Time `json:"finished_at,omitempty"`
	// Error describes execution failure without implying a negative assessment.
	Error string `json:"error,omitempty"`
	// Result is present only after successful execution and bounded interpretation.
	Result *nmap.CheckResult `json:"result,omitempty"`
}

// checkTask adds private cancellation to a retained snapshot.
type checkTask struct {
	job    CheckJob
	cancel context.CancelFunc
}

// StartCheck admits one known open service and catalog ID into the shared slot.
func (m *Manager) StartCheck(hostID string, selected network.Interface, id string, number int) (CheckJob, error) {
	if _, err := nmap.CheckSpecFor(id); err != nil {
		return CheckJob{}, err
	}
	provider, ok := m.provider.(checkProvider)
	if !ok || !m.provider.Available() {
		return CheckJob{}, nmap.ErrUnavailable
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return CheckJob{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.ctx.Err() != nil {
		return CheckJob{}, context.Canceled
	}
	if m.active != "" {
		return CheckJob{}, ErrBusy
	}
	session, ok := m.sessions[m.latest]
	if !ok || selected.Name != session.state.Interface {
		return CheckJob{}, fmt.Errorf("inventory interface is unavailable")
	}
	ip := ""
	var port nmap.Port
	for _, host := range session.state.Report.Hosts {
		if host.ID != hostID {
			continue
		}
		for _, candidate := range host.Ports {
			if candidate.Number != number {
				continue
			}
			for _, spec := range nmap.ApplicableChecks(candidate) {
				if spec.ID == id {
					ip = host.IP
					port = candidate
				}
			}
		}
	}
	if ip == "" {
		return CheckJob{}, fmt.Errorf("an observed open compatible service is required")
	}
	key := hex.EncodeToString(random)
	ctx, cancel := context.WithTimeout(m.ctx, time.Minute)
	task := &checkTask{job: CheckJob{ID: key, ScanID: session.state.ID, HostID: hostID, IP: ip, Port: number, CheckID: id, Status: "running", StartedAt: time.Now().UTC()}, cancel: cancel}
	if len(m.checkOrder) == 8 {
		delete(m.checkJobs, m.checkOrder[0])
		m.checkOrder = m.checkOrder[1:]
	}
	m.checkJobs[key] = task
	m.checkOrder = append(m.checkOrder, key)
	m.active = "check:" + key
	m.wg.Add(1)
	go m.runCheck(ctx, provider, selected, port, task, session)
	return task.job, nil
}

// runCheck never overwrites port observations or previous completed check results.
func (m *Manager) runCheck(ctx context.Context, provider checkProvider, selected network.Interface, port nmap.Port, task *checkTask, session *session) {
	defer m.wg.Done()
	defer task.cancel()
	result, err := provider.Check(ctx, selected, task.job.IP, port, task.job.CheckID)
	// Cancellation takes precedence even when an injected provider returns late data.
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err == nil && (result.IP != task.job.IP || result.Port != task.job.Port || result.CheckID != task.job.CheckID) {
		err = fmt.Errorf("NSE result scope mismatch")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	task.job.FinishedAt = time.Now().UTC()
	task.job.Status = "completed"
	if err != nil {
		task.job.Status = "failed"
		if errors.Is(err, context.Canceled) {
			task.job.Status = "cancelled"
		}
		if errors.Is(err, context.DeadlineExceeded) {
			task.job.Status = "timed_out"
		}
		task.job.Error = err.Error()
	} else {
		task.job.Result = &result
	}
	m.active = ""
	m.appendLocked(session, "check-updated", map[string]string{"host_id": task.job.HostID, "job_id": task.job.ID, "status": task.job.Status})
}

// copyCheckJob detaches nested evidence and assessments before leaving the manager lock.
func copyCheckJob(job CheckJob) CheckJob {
	data, _ := json.Marshal(job)
	var copy CheckJob
	_ = json.Unmarshal(data, &copy)
	return copy
}

// CheckState returns a detached retained job snapshot.
func (m *Manager) CheckState(id string) (CheckJob, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	task, ok := m.checkJobs[id]
	if !ok {
		return CheckJob{}, false
	}
	return copyCheckJob(task.job), true
}

// CheckJobs returns jobs belonging to the requested host in the current inventory.
func (m *Manager) CheckJobs(hostID string) []CheckJob {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := []CheckJob{}
	for _, id := range m.checkOrder {
		task := m.checkJobs[id]
		if task.job.HostID == hostID && task.job.ScanID == m.latest {
			result = append(result, copyCheckJob(task.job))
		}
	}
	return result
}

// CancelCheck terminates a retained manual check without removing earlier evidence.
func (m *Manager) CancelCheck(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	task, ok := m.checkJobs[id]
	if ok {
		task.cancel()
	}
	return ok
}

// LatestCheck supports read-only recovery of a running manual action on reload.
func (m *Manager) LatestCheck() (CheckJob, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.checkOrder) == 0 {
		return CheckJob{}, false
	}
	task := m.checkJobs[m.checkOrder[len(m.checkOrder)-1]]
	return copyCheckJob(task.job), true
}
