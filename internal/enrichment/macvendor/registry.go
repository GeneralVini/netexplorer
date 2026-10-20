// Package macvendor classifies MAC addresses and maintains an offline IEEE registry.
package macvendor

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// State describes the active registry and the last refresh attempt.
type State struct {
	// Conflicts counts ambiguous IEEE prefixes excluded from the latest downloaded base.
	Conflicts int `json:"conflicts"`
	// Entries counts IEEE prefix assignments.
	Entries int `json:"entries"`
	// Modified is the file modification time, an age estimate for system files.
	Modified time.Time `json:"modified,omitempty"`
	// Checked timestamps the last completed download attempt.
	Checked time.Time `json:"checked,omitempty"`
	// Updated timestamps the latest successful application-managed update.
	Updated time.Time `json:"updated,omitempty"`
	// Source identifies the active local file.
	Source string `json:"source"`
	// Stale reports missing data or data older than 30 days.
	Stale bool `json:"stale"`
	// Running reports the single reserved download worker.
	Running bool `json:"running"`
	// Automatic enables hourly age checks while the application runs.
	Automatic bool `json:"automatic"`
	// Error records the latest update failure without discarding active data.
	Error string `json:"error,omitempty"`
}

// Registry publishes immutable snapshots while downloads run outside its lock.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]string
	custom  map[string]string
	state   State
	dir     string
	client  *http.Client
}

// Default is shared by discovery and HTTP; system files are read-only fallbacks.
var Default = newDefault()

// The privileged ARP helper never needs vendor data or app-owned settings.
func newDefault() *Registry {
	if filepath.Base(os.Args[0]) == "netexplorer-arp" {
		return &Registry{entries: map[string]string{}, custom: map[string]string{}}
	}
	return New(defaultDir())
}

func defaultDir() string {
	if value := os.Getenv("NETEXPLORER_VENDOR_DIR"); value != "" {
		return value
	}
	return "/var/lib/netexplorer/vendors"
}

// Local reports a locally administered Ethernet address, not proof of randomness.
func Local(value string) bool {
	mac, err := net.ParseMAC(value)
	return err == nil && len(mac) == 6 && mac[0]&2 != 0
}

// New loads application data first and otherwise reads a system registry.
func New(dir string) *Registry {
	r := &Registry{dir: dir, entries: map[string]string{}, custom: map[string]string{}, client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}
	for _, path := range []string{filepath.Join(dir, "ieee-oui.txt"), "/usr/share/arp-scan/ieee-oui.txt", "/usr/local/share/arp-scan/ieee-oui.txt", "/opt/homebrew/share/arp-scan/ieee-oui.txt"} {
		data, err := readFile(path)
		if err != nil {
			continue
		}
		entries, err := parseTXT(data)
		if err != nil || len(entries) == 0 {
			continue
		}
		r.entries = entries
		r.state.Source = path
		if info, err := os.Stat(path); err == nil {
			r.state.Modified = info.ModTime()
			if path == filepath.Join(dir, "ieee-oui.txt") {
				r.state.Updated = info.ModTime()
			}
		}
		break
	}
	for _, path := range []string{"/etc/arp-scan/mac-vendor.txt", filepath.Join(dir, "mac-vendor.txt")} {
		if data, err := readFile(path); err == nil {
			if entries, err := parseTXT(data); err == nil {
				for k, v := range entries {
					r.custom[k] = v
				}
			}
		}
	}
	if data, err := readFile(filepath.Join(dir, "settings.json")); err == nil {
		var settings struct {
			Automatic bool `json:"automatic"`
		}
		if json.Unmarshal(data, &settings) == nil {
			r.state.Automatic = settings.Automatic
		}
	}
	if data, err := readFile(filepath.Join(dir, "status.json")); err == nil {
		var previous State
		if json.Unmarshal(data, &previous) == nil {
			r.state.Checked = previous.Checked
			r.state.Error = previous.Error
			if previous.Source == r.state.Source && previous.Modified.Equal(r.state.Modified) {
				r.state.Conflicts = previous.Conflicts
				r.state.Updated = previous.Updated
			}
		}
	}
	r.state.Entries = len(r.entries)
	return r
}

// Status returns a detached snapshot; modification time is only an age estimate.
func (r *Registry) Status() State {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s := r.state
	s.Stale = s.Modified.IsZero() || time.Since(s.Modified) > 30*24*time.Hour
	return s
}

// Lookup uses the most specific prefix; explicit custom entries take precedence.
func (r *Registry) Lookup(value string) string {
	mac, err := net.ParseMAC(value)
	if err != nil || len(mac) != 6 || mac[0]&3 != 0 || mac.String() == "00:00:00:00:00:00" {
		return ""
	}
	key := strings.ToUpper(hex.EncodeToString(mac))
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, entries := range []map[string]string{r.custom, r.entries} {
		for n := 12; n >= 2; n-- {
			if vendor := entries[key[:n]]; vendor != "" {
				return vendor
			}
		}
	}
	return ""
}

func valid(prefix, vendor string) bool {
	if len(prefix) < 2 || len(prefix) > 12 || len(vendor) == 0 || len(vendor) > 1024 || strings.ContainsAny(vendor, "\x00\r\n\t") {
		return false
	}
	for _, c := range prefix {
		if !strings.ContainsRune("0123456789ABCDEF", c) {
			return false
		}
	}
	return true
}

func parseTXT(data []byte) (map[string]string, error) {
	if len(data) > 16<<20 {
		return nil, fmt.Errorf("registry exceeds size limit")
	}
	result := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 4096), 8192)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid registry row")
		}
		prefix := strings.ToUpper(parts[0])
		vendor := strings.TrimSpace(strings.TrimPrefix(line, parts[0]))
		if !valid(prefix, vendor) {
			return nil, fmt.Errorf("invalid registry entry")
		}
		result[prefix] = vendor
	}
	return result, scanner.Err()
}

// Update fetches only fixed IEEE endpoints and publishes after complete validation.
// Cancellation or any failed source leaves the previous file and snapshot active.
func (r *Registry) Update(ctx context.Context) (err error) {
	if err = r.begin(); err != nil {
		return err
	}
	return r.update(ctx)
}

func (r *Registry) begin() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state.Running {
		return fmt.Errorf("registry update already running")
	}
	r.state.Running = true
	return nil
}

// Start reserves the single update worker before returning to the HTTP caller.
func (r *Registry) Start(ctx context.Context) error {
	if err := r.begin(); err != nil {
		return err
	}
	go func() { _ = r.update(ctx) }()
	return nil
}

func (r *Registry) update(ctx context.Context) (err error) {
	defer func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.state.Running = false
		r.state.Checked = time.Now().UTC()
		r.state.Error = ""
		if err != nil {
			r.state.Error = err.Error()
		}
		if os.MkdirAll(r.dir, 0750) == nil {
			if data, e := json.Marshal(r.state); e == nil {
				_ = os.WriteFile(filepath.Join(r.dir, "status.json"), data, 0600)
			}
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	entries := map[string]string{}
	conflicts := map[string]bool{}
	for _, source := range []struct {
		url    string
		length int
	}{{"https://standards-oui.ieee.org/oui/oui.csv", 6}, {"https://standards-oui.ieee.org/oui28/mam.csv", 7}, {"https://standards-oui.ieee.org/oui36/oui36.csv", 9}} {
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, source.url, nil)
		if e != nil {
			return e
		}
		req.Header.Set("User-Agent", "NetExplorer MAC registry updater")
		response, e := r.client.Do(req)
		if e != nil {
			return fmt.Errorf("IEEE download failed: %w", e)
		}
		data, e := io.ReadAll(io.LimitReader(response.Body, (16<<20)+1))
		closeErr := response.Body.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		if response.StatusCode != 200 || len(data) > 16<<20 {
			return fmt.Errorf("IEEE returned invalid response (%d)", response.StatusCode)
		}
		reader := csv.NewReader(strings.NewReader(string(data)))
		header, e := reader.Read()
		if e != nil || len(header) < 3 || header[1] != "Assignment" || header[2] != "Organization Name" {
			return fmt.Errorf("invalid IEEE CSV header")
		}
		count := 0
		for {
			row, e := reader.Read()
			if e == io.EOF {
				break
			}
			if e != nil || len(row) < 3 {
				return fmt.Errorf("invalid IEEE CSV row")
			}
			prefix := strings.ToUpper(strings.TrimSpace(row[1]))
			vendor := strings.TrimSpace(row[2])
			if len(prefix) != source.length || !valid(prefix, vendor) {
				return fmt.Errorf("invalid IEEE assignment")
			}
			if old := entries[prefix]; old != "" && old != vendor {
				conflicts[prefix] = true
				delete(entries, prefix)
			} else if !conflicts[prefix] {
				entries[prefix] = vendor
			}
			count++
		}
		if count < 100 {
			return fmt.Errorf("IEEE registry unexpectedly small")
		}
	}
	if len(entries) < 100 || len(conflicts) > len(entries)/10 {
		return fmt.Errorf("IEEE registry contains excessive conflicts")
	}
	var output strings.Builder
	output.WriteString("# NetExplorer IEEE registry; generated from MA-L, MA-M and MA-S CSV sources.\n")
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&output, "%s\t%s\n", k, entries[k])
	}
	if err = os.MkdirAll(r.dir, 0750); err != nil {
		return err
	}
	file, e := os.CreateTemp(r.dir, ".oui-*")
	if e != nil {
		return e
	}
	defer func() { _ = os.Remove(file.Name()) }()
	if _, err = file.WriteString(output.String()); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	path := filepath.Join(r.dir, "ieee-oui.txt")
	if err = os.Rename(file.Name(), path); err != nil {
		return err
	}
	r.mu.Lock()
	r.entries = entries
	r.state.Entries = len(entries)
	r.state.Conflicts = len(conflicts)
	r.state.Updated = time.Now().UTC()
	r.state.Modified = r.state.Updated
	if info, e := os.Stat(path); e == nil {
		r.state.Modified = info.ModTime()
	}
	r.state.Source = path
	r.mu.Unlock()
	return nil
}

// Run periodically refreshes stale data while enabled and stops with the app context.
func (r *Registry) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		s := r.Status()
		if s.Automatic && s.Stale && (s.Checked.IsZero() || time.Since(s.Checked) > 24*time.Hour) {
			_ = r.Update(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// SetAutomatic persists the opt-in hourly age check; failed attempts retry after one day.
func (r *Registry) SetAutomatic(enabled bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := os.MkdirAll(r.dir, 0750); err != nil {
		return err
	}
	data, err := json.Marshal(struct {
		Automatic bool `json:"automatic"`
	}{enabled})
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(r.dir, "settings.json"), data, 0600); err != nil {
		return err
	}
	r.state.Automatic = enabled
	return nil
}

// readFile bounds file reads before allocation, including administrator-provided files.
func readFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 16<<20 {
		return nil, fmt.Errorf("registry must be a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, (16<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 16<<20 {
		return nil, fmt.Errorf("registry file exceeds size limit")
	}
	return data, nil
}
