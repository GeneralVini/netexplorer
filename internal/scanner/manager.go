package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"netexplorer/internal/enrichment/nmap"
	"sort"
	"sync"
	"time"

	"netexplorer/internal/discovery/network"
	"netexplorer/internal/discovery/ssdp"
	"netexplorer/internal/enrichment/windows"
	"netexplorer/internal/inventory"
	"netexplorer/internal/security/safehttp"
)

// ErrBusy indicates that the single discovery slot is already occupied.
var ErrBusy = errors.New("a scan is already running")

// Event is a bounded, replayable notification; inventory is retrieved separately.
type Event struct {
	// ID increases monotonically within a scan.
	ID uint64 `json:"id"`
	// Type identifies the SSE event name.
	Type string `json:"type"`
	// Data contains a JSON notification payload.
	Data json.RawMessage `json:"data"`
}

// State describes a scan without exposing mutable registry internals.
type State struct {
	// ID identifies a retained scan.
	ID string `json:"id"`
	// Status is running, completed, cancelled, or failed.
	Status string `json:"status"`
	// Interface names the selected LAN interface.
	Interface string `json:"interface"`
	// StartedAt is the UTC start time.
	StartedAt time.Time `json:"started_at"`
	// FinishedAt is zero until the scan finishes.
	FinishedAt time.Time `json:"finished_at,omitempty"`
	// Error records a terminal failure, if any.
	Error string `json:"error,omitempty"`
	// Window identifies the current discovery window.
	Window int `json:"window"`
	// Continuous keeps discovery active until cancellation.
	Continuous bool `json:"continuous"`
	// Paused suspends new continuous discovery windows and queued TCP work.
	Paused bool `json:"paused"`
	// NewHosts counts peers first observed in the last completed window.
	NewHosts int `json:"new_hosts"`
	// TCPIP identifies the current automatic common-profile target, if any.
	TCPIP string `json:"tcp_ip,omitempty"`
	// Phase distinguishes discovery from waiting and final TCP work.
	Phase string `json:"phase"`
	// Deadline is the UTC end of the current timed phase.
	Deadline time.Time `json:"deadline,omitempty"`
	// IntervalSeconds records the authorized monitor cadence.
	IntervalSeconds int `json:"interval_seconds"`
	// AutoTCP records whether automatic common inspection was authorized.
	AutoTCP bool `json:"auto_tcp"`
	// TCPScheduled counts queued automatic attempts in this session.
	TCPScheduled int `json:"tcp_scheduled"`
	// TCPCompleted counts successful automatic attempts.
	TCPCompleted int `json:"tcp_completed"`
	// TCPFailed counts unsuccessful automatic attempts.
	TCPFailed int `json:"tcp_failed"`
	// TCPActive lists the at most two current automatic peers.
	TCPActive []string `json:"tcp_active"`
	// Report retains the latest scan inventory and enrichment warnings.
	Report Report `json:"report"`
}

// Runner performs bounded discovery and publishes progress synchronously.
// Implementations must honor context cancellation and return independent reports.
type Runner func(context.Context, network.Interface, time.Duration, bool, func(string, any), func([]inventory.Device)) (Report, error)

// session retains a bounded journal and wakes readers without blocking producers.
type session struct {
	state     State
	events    []Event
	next      uint64
	notify    chan struct{}
	cancel    context.CancelFunc
	pauseWake chan struct{}
}

// Manager owns one active scan, the latest inventory, and eight retained sessions.
// Events are limited to 512 per session; slow readers receive a reset notification.
type Manager struct {
	mu             sync.Mutex
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	runner         Runner
	sessions       map[string]*session
	order          []string
	active         string
	latest         string
	closed         bool
	provider       NmapProvider
	nmapJobs       map[string]*nmapTask
	nmapOrder      []string
	checkJobs      map[string]*checkTask
	checkOrder     []string
	windowsReports map[string]windows.Report
	windowsOrder   []string
}

// NewManager creates a manager whose work ends with parent or Close.
// A nil runner selects native SSDP and safe UPnP enrichment.
func NewManager(parent context.Context, runner Runner, providers ...NmapProvider) *Manager {
	ctx, cancel := context.WithCancel(parent)
	if runner == nil {
		runner = runNative
	}
	var provider NmapProvider = nmap.New()
	if len(providers) > 0 && providers[0] != nil {
		provider = providers[0]
	}
	return &Manager{ctx: ctx, cancel: cancel, runner: runner, sessions: map[string]*session{}, provider: provider, nmapJobs: map[string]*nmapTask{}, checkJobs: map[string]*checkTask{}}
}

// Close cancels and joins all workers. It is safe to call repeatedly.
func (m *Manager) Close() {
	m.mu.Lock()
	m.closed = true
	m.cancel()
	m.mu.Unlock()
	m.wg.Wait()
}

// Start reserves the single scan slot after validating duration and interface.
// The caller must obtain explicit authorization to scan the selected LAN.
func (m *Manager) Start(selected network.Interface, duration time.Duration, enrich bool) (string, error) {
	return m.StartWithOptions(selected, duration, ScanOptions{Enrich: enrich})
}

// StartWithOptions also permits explicit bounded LAN host discovery using Nmap.
func (m *Manager) StartWithOptions(selected network.Interface, duration time.Duration, options ScanOptions) (string, error) {
	if duration < time.Second || duration > time.Minute {
		return "", fmt.Errorf("duration must be between 1 and 60 seconds")
	}
	if !selected.Up || selected.Loopback || (!selected.Multicast && !options.AllHosts) || len(selected.IPv4) == 0 {
		return "", fmt.Errorf("select an active multicast IPv4 interface")
	}
	if options.Continuous && (options.Interval < 10*time.Second || options.Interval > time.Hour) {
		return "", fmt.Errorf("window interval must be between 10 and 3600 seconds")
	}
	if options.AutoTCP && !m.provider.Available() {
		return "", nmap.ErrUnavailable
	}
	if options.AllHosts || options.AutoTCP {
		if !m.DiscoveryAvailable() {
			return "", nmap.ErrUnavailable
		}
		prefix, err := netip.ParsePrefix(selected.IPv4[0])
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 22 {
			return "", fmt.Errorf("host discovery requires an IPv4 subnet of /22 or narrower")
		}
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.ctx.Err() != nil {
		return "", context.Canceled
	}
	if m.active != "" {
		return "", ErrBusy
	}
	key := hex.EncodeToString(id)
	total := duration + 35*time.Second
	if options.AllHosts {
		total += 60 * time.Second
	}
	ctx, cancel := context.WithCancel(m.ctx)
	if !options.Continuous && !options.AutoTCP {
		cancel()
		ctx, cancel = context.WithTimeout(m.ctx, total)
	}
	s := &session{state: State{ID: key, Status: "running", Continuous: options.Continuous, AutoTCP: options.AutoTCP, IntervalSeconds: int(options.Interval / time.Second), Interface: selected.Name, StartedAt: time.Now().UTC(), Report: Report{Devices: []inventory.Device{}, Warnings: []Warning{}}}, notify: make(chan struct{}), cancel: cancel}
	if len(m.order) == 8 {
		delete(m.sessions, m.order[0])
		m.order = m.order[1:]
	}
	m.sessions[key] = s
	m.order = append(m.order, key)
	m.active = key
	m.latest = key
	m.appendLocked(s, "scan-started", map[string]string{"id": key, "interface": selected.Name})
	m.wg.Add(1)
	go m.run(ctx, s, selected, duration, options)
	return key, nil
}

// appendLocked copies payloads and signals journal changes under m.mu.
func (m *Manager) appendLocked(s *session, kind string, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		slog.Error("unable to encode scan event", "error", err)
		return
	}
	s.next++
	s.events = append(s.events, Event{ID: s.next, Type: kind, Data: data})
	if len(s.events) > 512 {
		copy(s.events, s.events[len(s.events)-512:])
		s.events = s.events[:512]
	}
	close(s.notify)
	s.notify = make(chan struct{})
}

// run owns the monitor admission while bounded discovery and two TCP workers run.
func (m *Manager) run(ctx context.Context, s *session, selected network.Interface, duration time.Duration, options ScanOptions) {
	defer m.wg.Done()
	defer s.cancel()
	emit := func(kind string, value any) {
		m.mu.Lock()
		defer m.mu.Unlock()
		if kind == "host-discovery-started" {
			s.state.Phase = "hosts"
			s.state.Deadline = time.Now().Add(time.Minute)
			m.progressLocked(s)
		}
		m.appendLocked(s, kind, value)
	}
	queue := make(chan inventory.Host, 1024)
	attempted := map[string]bool{}
	update := func(devices []inventory.Device) {
		m.mu.Lock()
		defer m.mu.Unlock()
		previous := map[string]inventory.Device{}
		for _, device := range s.state.Report.Devices {
			previous[device.ID] = device
		}
		for _, device := range devices {
			old, exists := previous[device.ID]
			if !exists {
				m.appendLocked(s, "device-found", map[string]string{"id": device.ID})
			}
			services := map[string]bool{}
			for _, service := range old.Services {
				services[service.ID+"|"+service.Type] = true
			}
			for _, service := range device.Services {
				if !services[service.ID+"|"+service.Type] {
					m.appendLocked(s, "service-found", map[string]string{"device_id": device.ID, "service_id": service.ID})
				}
			}
		}
		if options.Continuous {
			devices = mergeWindowDevices(s.state.Report.Devices, devices)
		}
		s.state.Report.Devices = devices
		s.state.Report.Hosts = mergeHostEvidence(devices, s.state.Report.Hosts)
		m.appendLocked(s, "device-updated", map[string]int{"devices": len(devices)})
		if options.AutoTCP {
			for _, host := range s.state.Report.Hosts {
				if attempted[host.IP] || len(attempted) >= 1024 || !host.EnrichedAt.IsZero() {
					continue
				}
				select {
				case queue <- host:
					attempted[host.IP] = true
					s.state.TCPScheduled++
					m.setTCPStatusLocked(s, host.IP, "queued")
					m.progressLocked(s)
				default:
				}
			}
		}
	}
	done := make(chan struct{})
	if options.AutoTCP {
		go func() {
			var workers sync.WaitGroup
			workers.Add(2)
			for i := 0; i < 2; i++ {
				go func() { defer workers.Done(); m.autoTCP(ctx, s, selected, queue) }()
			}
			workers.Wait()
			close(done)
		}()
	} else {
		close(done)
	}
	known := map[string]bool{}
	var terminal error
	for window := 1; ; window++ {
		if !m.waitUnpaused(ctx, s) {
			terminal = ctx.Err()
			break
		}
		if ctx.Err() != nil {
			terminal = ctx.Err()
			break
		}
		began := time.Now()
		m.mu.Lock()
		s.state.Window = window
		s.state.Phase = "discovering"
		s.state.Deadline = began.Add(duration)
		m.progressLocked(s)
		m.appendLocked(s, "window-started", map[string]int{"window": window})
		m.mu.Unlock()
		limit := duration + 35*time.Second
		if options.AllHosts {
			limit += 60 * time.Second
		}
		windowCtx, cancel := context.WithTimeout(ctx, limit)
		report, err := m.discoverWindow(windowCtx, selected, duration, options, emit, update)
		cancel()
		if err != nil {
			present := false
			for _, warning := range report.Warnings {
				if warning.Message == err.Error() {
					present = true
					break
				}
			}
			if !present {
				report.Warnings = append(report.Warnings, Warning{Message: err.Error()})
			}
		}
		update(report.Devices)
		m.mu.Lock()
		// Retain TCP evidence written concurrently and hosts absent from a later window.
		report.Devices = mergeWindowDevices(s.state.Report.Devices, report.Devices)
		report.Hosts = mergeHostEvidence(report.Devices, append(report.Hosts, s.state.Report.Hosts...))
		if len(report.Hosts) > 1024 {
			report.Hosts = report.Hosts[:1024]
			report.Warnings = append(report.Warnings, Warning{Message: "Inventory limited to 1024 hosts"})
		}
		if len(report.Warnings) > 64 {
			report.Warnings = report.Warnings[:64]
		}
		report.Warnings = mergeWindowWarnings(s.state.Report.Warnings, report.Warnings)
		s.state.Report = report
		newHosts := 0
		candidates := []inventory.Host{}
		for _, host := range report.Hosts {
			if !known[host.IP] && len(known) < 1024 {
				known[host.IP] = true
				newHosts++
			}
			if options.AutoTCP && !attempted[host.IP] && len(attempted) < 1024 {
				attempted[host.IP] = true
				if host.EnrichedAt.IsZero() {
					candidates = append(candidates, host)
					s.state.TCPScheduled++
					m.setTCPStatusLocked(s, host.IP, "queued")
				}
			}
		}
		s.state.NewHosts = newHosts
		s.state.Phase = "waiting"
		s.state.Deadline = began.Add(options.Interval)
		if !options.Continuous {
			s.state.Phase = "tcp"
			s.state.Deadline = time.Time{}
		}
		m.progressLocked(s)
		m.appendLocked(s, "window-complete", map[string]int{"window": window, "new_hosts": newHosts, "hosts": len(report.Hosts)})
		m.mu.Unlock()
		for _, host := range candidates {
			select {
			case queue <- host:
			case <-ctx.Done():
			}
		}
		if !options.Continuous || ctx.Err() != nil {
			terminal = err
			if ctx.Err() != nil {
				terminal = ctx.Err()
			}
			break
		}
		wait := options.Interval - time.Since(began)
		if wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
			case <-ctx.Done():
			}
			timer.Stop()
		}
	}
	close(queue)
	<-done
	if ctx.Err() != nil {
		terminal = ctx.Err()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctx.Err() != nil {
		for i := range s.state.Report.Hosts {
			if s.state.Report.Hosts[i].AutoTCPStatus == "queued" {
				s.state.Report.Hosts[i].AutoTCPStatus = "cancelled"
				s.state.TCPFailed++
			}
		}
	}
	s.state.Phase = "stopped"
	s.state.Deadline = time.Time{}
	m.progressLocked(s)
	s.state.FinishedAt = time.Now().UTC()
	s.state.Status = "completed"
	kind := "scan-complete"
	if terminal != nil {
		s.state.Status = "failed"
		if errors.Is(terminal, context.Canceled) {
			s.state.Status = "cancelled"
		}
		s.state.Error = terminal.Error()
		kind = "scan-error"
	}
	m.active = ""
	m.appendLocked(s, kind, map[string]string{"status": s.state.Status, "error": s.state.Error})
	slog.Info("browser scan finished", "scan", s.state.ID, "status", s.state.Status, "devices", len(s.state.Report.Devices))
}

// discoverWindow applies a separate deadline on every non-overlapping discovery pass.
func (m *Manager) discoverWindow(ctx context.Context, selected network.Interface, duration time.Duration, options ScanOptions, emit func(string, any), update func([]inventory.Device)) (Report, error) {
	var report Report
	var err error
	if selected.Multicast {
		report, err = m.runner(ctx, selected, duration, options.Enrich, emit, update)
	} else {
		report = Report{Devices: []inventory.Device{}, Warnings: []Warning{{Message: "SSDP skipped: interface does not support multicast"}}}
	}
	report.Hosts = mergeHostEvidence(report.Devices, report.Hosts)
	if options.AllHosts && ctx.Err() == nil {
		emit("host-discovery-started", map[string]string{"interface": selected.Name})
		discovered, hostErr := m.provider.Discover(ctx, selected)
		if hostErr != nil {
			hostErr = fmt.Errorf("LAN host discovery: %w", hostErr)
			report.Warnings = append(report.Warnings, Warning{Message: hostErr.Error()})
			var optional *nmap.DiscoveryWarning
			if !errors.As(hostErr, &optional) {
				err = errors.Join(err, hostErr)
			}
		}
		if len(discovered) > 0 {
			seen := map[string]bool{}
			for _, host := range report.Hosts {
				seen[host.IP] = true
			}
			at := time.Now().UTC()
			for _, host := range discovered {
				if !seen[host.IP] {
					emit("host-found", map[string]string{"ip": host.IP, "source": "nmap"})
				}
				sources := host.Sources
				if len(sources) == 0 {
					sources = []string{"nmap"}
				}
				report.Hosts = append(report.Hosts, inventory.Host{ID: inventory.HostID(host.IP), IP: host.IP, TTL: host.TTL, MDNS: host.MDNS, MAC: host.MAC, Vendor: host.Vendor, Sources: sources, Ports: []nmap.Port{}, ObservedAt: at})
			}
			report.Hosts = mergeHostEvidence(report.Devices, report.Hosts)
		}
	}
	return report, err
}

// State returns a detached snapshot, or false for expired and unknown sessions.
func (m *Manager) State(id string) (State, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return State{}, false
	}
	// JSON copying also detaches nested evidence maps and service slices.
	data, _ := json.Marshal(s.state)
	var result State
	_ = json.Unmarshal(data, &result)
	return result, true
}

// Latest returns the most recently started scan, including partial inventory.
func (m *Manager) Latest() (State, bool) {
	m.mu.Lock()
	id := m.latest
	m.mu.Unlock()
	return m.State(id)
}

// Cancel requests cancellation of a known scan without discarding its evidence.
func (m *Manager) Cancel(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if ok {
		s.cancel()
	}
	return ok
}

// Events returns detached events after cursor and a change notification channel.
// A reset means the cursor predates retained history or exceeds the last event.
func (m *Manager) Events(id string, cursor uint64) ([]Event, <-chan struct{}, bool, bool, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return nil, nil, false, false, false
	}
	reset := cursor > s.next || (len(s.events) > 0 && cursor+1 < s.events[0].ID)
	result := []Event{}
	for _, e := range s.events {
		if reset || e.ID > cursor {
			e.Data = append(json.RawMessage(nil), e.Data...)
			result = append(result, e)
		}
	}
	return result, s.notify, s.state.Status != "running", reset, true
}

// runNative applies the same bounded discovery and HTTP policy as the CLI.
func runNative(ctx context.Context, selected network.Interface, duration time.Duration, enrich bool, emit func(string, any), update func([]inventory.Device)) (Report, error) {
	registry := inventory.New()
	hosts := map[string]bool{}
	var published time.Time
	responses, discoveryErr := ssdp.DiscoverWithProgress(ctx, selected, duration, func(r ssdp.Response) {
		if !hosts[r.IP] {
			hosts[r.IP] = true
			emit("host-found", map[string]string{"ip": r.IP})
		}
		if err := registry.Observe(r); err != nil {
			return
		}
		// Batch packet bursts so snapshot work cannot overwhelm socket collection.
		if time.Since(published) >= 100*time.Millisecond {
			update(registry.Snapshot())
			published = time.Now()
		}
	})
	if discoveryErr != nil {
		discoveryErr = fmt.Errorf("SSDP discovery: %w", discoveryErr)
	}
	if !enrich {
		return Report{Devices: registry.Snapshot(), Warnings: []Warning{}}, discoveryErr
	}
	client, err := safehttp.New(selected.IPv4[0])
	if err != nil {
		return Report{Devices: registry.Snapshot()}, errors.Join(discoveryErr, err)
	}
	enrichmentCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	report, enrichErr := EnrichWithProgress(enrichmentCtx, responses, client, update)
	if enrichErr != nil {
		enrichErr = fmt.Errorf("UPnP description enrichment: %w", enrichErr)
	}
	return report, errors.Join(discoveryErr, enrichErr)
}

// ScanOptions describes explicitly requested optional network actions.
type ScanOptions struct {
	// Enrich enables safe UPnP description requests.
	Enrich bool
	// AllHosts enables bounded Nmap host discovery without port scanning.
	AllHosts bool
	// Continuous repeats discovery until explicit cancellation.
	Continuous bool
	// Interval is the minimum delay between discovery window starts.
	Interval time.Duration
	// AutoTCP inspects newly discovered peers once with fixed common coverage.
	AutoTCP bool
}

// mergeHostEvidence preserves logical identities while consolidating IP evidence.
func mergeHostEvidence(devices []inventory.Device, hosts []inventory.Host) []inventory.Host {
	byIP := map[string]inventory.Host{}
	for _, host := range hosts {
		if host.IP == "" {
			continue
		}
		old, found := byIP[host.IP]
		if found {
			if old.ObservedAt.After(host.ObservedAt) && old.MAC != "" {
				host.MAC = old.MAC
				host.Vendor = old.Vendor
				host.ObservedAt = old.ObservedAt
			}
			host.Sources = append(host.Sources, old.Sources...)
			if host.MAC == "" {
				host.MAC = old.MAC
			}
			if host.Vendor == "" && host.MAC == old.MAC {
				host.Vendor = old.Vendor
			}
			if host.AutoTCPStatus == "" {
				host.AutoTCPStatus = old.AutoTCPStatus
			}
			if len(host.MDNS) == 0 {
				host.MDNS = append([]string{}, old.MDNS...)
			}
			if host.TTL == 0 {
				host.TTL = old.TTL
			}
			if host.WindowsCaption == "" {
				host.WindowsCaption = old.WindowsCaption
			}
			if len(host.Ports) == 0 {
				host.Ports = old.Ports
				host.Coverage = old.Coverage
			}
			if old.EnrichedAt.After(host.EnrichedAt) {
				host.EnrichedAt = old.EnrichedAt
			}
		}
		sources := []string{}
		for _, source := range host.Sources {
			seen := false
			for _, value := range sources {
				if source == value {
					seen = true
				}
			}
			if !seen {
				sources = append(sources, source)
			}
		}
		host.Sources = sources
		byIP[host.IP] = host
	}
	for _, device := range devices {
		if device.IP == "" {
			continue
		}
		host, ok := byIP[device.IP]
		if !ok {
			host = inventory.Host{ID: inventory.HostID(device.IP), IP: device.IP, Ports: []nmap.Port{}, ObservedAt: device.LastSeen}
		}
		seen := false
		for _, source := range host.Sources {
			if source == "ssdp" {
				seen = true
			}
		}
		if !seen {
			host.Sources = append(host.Sources, "ssdp")
		}
		byIP[device.IP] = host
	}
	result := []inventory.Host{}
	for _, host := range byIP {
		result = append(result, host)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].IP < result[j].IP })
	return result
}
