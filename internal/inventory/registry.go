// Package inventory correlates discovery evidence into an in-memory logical-device registry.
package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"netexplorer/internal/discovery/ssdp"
	"netexplorer/internal/enrichment/upnp"
)

// Evidence preserves a field observation, including conflicting advertised values.
type Evidence struct {
	// Source names the discovery or enrichment protocol.
	Source string `json:"source"`
	// Value is the observed field value.
	Value string `json:"value"`
	// Location identifies the announcement or description responsible for the value.
	Location string `json:"location"`
	// ObservedAt records when the evidence was collected.
	ObservedAt time.Time `json:"observed_at"`
}

// Device is a logical device correlated by advertised UUID, not by friendly name or IP alone.
// Devices sharing an IP may be distinct. Identity claims are evidence, not authentication.
type Device struct {
	winners map[string]Evidence
	// ID is a deterministic hash of the correlation key.
	ID string `json:"id"`
	// UDN is the advertised UUID, or empty for a provisional endpoint record.
	UDN string `json:"udn,omitempty"`
	// IP is the most recently observed source IP; prior values remain in Evidence.
	IP string `json:"ip"`
	// ParentID links an embedded UPnP device to its logical parent.
	ParentID string `json:"parent_id,omitempty"`
	// Attributes contains current nonempty profile fields; alternatives remain in Evidence.
	Attributes map[string]string `json:"attributes"`
	// Services contains distinct advertised service records for this device.
	Services []upnp.Service `json:"services"`
	// USNs preserves distinct SSDP service names belonging to this device.
	USNs []string `json:"usns"`
	// Locations preserves discovered description endpoints.
	Locations []string `json:"locations"`
	// Evidence maps profile fields and service claims to their provenance.
	Evidence map[string][]Evidence `json:"evidence"`
	// FirstSeen is the earliest retained observation timestamp.
	FirstSeen time.Time `json:"first_seen"`
	// LastSeen is the latest retained observation timestamp.
	LastSeen time.Time `json:"last_seen"`
}

// Registry stores bounded logical-device records. Use New to construct it.
// Methods are safe for concurrent use and return independent snapshots.
type Registry struct {
	mu      sync.RWMutex
	devices map[string]*Device
}

// New creates an empty registry with a limit of 4096 devices per scan.
func New() *Registry { return &Registry{devices: map[string]*Device{}} }

// deviceID avoids exposing arbitrary network strings as identifiers.
func deviceID(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// uuidKey normalizes the advertised UUID prefix used for logical correlation.
func uuidKey(udn string) string {
	key := strings.ToLower(strings.TrimSpace(udn))
	if strings.HasPrefix(key, "uuid:") && len(key) > 5 {
		return "udn:" + key
	}
	return ""
}

// endpointKey distinguishes provisional records until an XML UUID is available.
func endpointKey(ip, location string) string { return "endpoint:" + ip + "|" + location }

// ensure creates a bounded record; the caller must hold the registry lock.
func (r *Registry) ensure(key, udn string) (*Device, error) {
	if device := r.devices[key]; device != nil {
		return device, nil
	}
	if len(r.devices) >= 4096 {
		return nil, fmt.Errorf("inventory device limit reached")
	}
	device := &Device{ID: deviceID(key), UDN: udn, Attributes: map[string]string{}, Services: []upnp.Service{}, USNs: []string{}, Locations: []string{}, Evidence: map[string][]Evidence{}, winners: map[string]Evidence{}}
	r.devices[key] = device
	return device, nil
}

// observeField keeps at most 16 distinct provenance claims per field and refreshes repeated claims.
func observeField(device *Device, field, value, source, location string, at time.Time) {
	if value == "" {
		return
	}
	candidate := Evidence{Source: source, Value: value, Location: location, ObservedAt: at}
	current, exists := device.winners[field]
	// Prefer profile-specific UPnP claims, then newer evidence. IP always follows
	// observation time. Equal-time conflicts use lexical order for reproducibility.
	priority := func(source string) int {
		if field != "ip" && source == "upnp" {
			return 2
		}
		return 1
	}
	if !exists || priority(source) > priority(current.Source) || (priority(source) == priority(current.Source) && (at.After(current.ObservedAt) || (at.Equal(current.ObservedAt) && value > current.Value))) {
		device.Attributes[field] = value
		device.winners[field] = candidate
	}
	entries := device.Evidence[field]
	for i, entry := range entries {
		if entry.Source == source && entry.Value == value && entry.Location == location {
			if at.After(entry.ObservedAt) {
				entries[i].ObservedAt = at
			}
			device.Evidence[field] = entries
			return
		}
	}
	if len(entries) >= 16 {
		entries = entries[1:]
	}
	device.Evidence[field] = append(entries, Evidence{Source: source, Value: value, Location: location, ObservedAt: at})
}

// touch updates a record's time range without assuming observation order.
func touch(device *Device, at time.Time) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	if device.FirstSeen.IsZero() || at.Before(device.FirstSeen) {
		device.FirstSeen = at
	}
	if at.After(device.LastSeen) {
		device.LastSeen = at
	}
}

// unique appends an unseen string while preserving observation order.
func unique(values []string, value string) []string {
	for _, old := range values {
		if old == value {
			return values
		}
	}
	return append(values, value)
}

// Observe merges one SSDP announcement by UUID, or by source IP and LOCATION
// when UUID evidence is absent. It never merges solely by friendly name or IP.
func (r *Registry) Observe(response ssdp.Response) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	udn := strings.TrimSpace(strings.SplitN(response.USN, "::", 2)[0])
	key := uuidKey(udn)
	if key == "" {
		key = endpointKey(response.IP, response.Location)
		udn = ""
	}
	device, err := r.ensure(key, udn)
	if err != nil {
		return err
	}
	at := response.SeenAt
	if at.IsZero() {
		at = time.Now().UTC()
	}
	touch(device, at)
	device.USNs = unique(device.USNs, response.USN)
	device.Locations = unique(device.Locations, response.Location)
	for field, value := range map[string]string{"ip": response.IP, "udn": udn, "location": response.Location, "usn": response.USN, "st": response.ST, "server": response.Server, "cache_control": response.CacheControl, "ext": fmt.Sprint(response.EXT)} {
		observeField(device, field, value, "ssdp", response.Location, at)
	}
	device.IP = device.Attributes["ip"]
	return nil
}

// Apply merges a validated root and embedded UPnP devices into the registry.
// A provisional endpoint is promoted to the root UUID when possible. Distinct
// UUIDs remain separate and parent links preserve the XML hierarchy. A limit
// error may leave earlier devices enriched; collected evidence is not discarded.
func (r *Registry) Apply(ip, location string, description upnp.Description, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if at.IsZero() {
		at = time.Now().UTC()
	}
	key := uuidKey(description.Device.UDN)
	if key == "" {
		return fmt.Errorf("missing UPnP UUID")
	}
	provisional := endpointKey(ip, location)
	if old := r.devices[provisional]; old != nil {
		if existing := r.devices[key]; existing != nil {
			for field, entries := range old.Evidence {
				for _, entry := range entries {
					observeField(existing, field, entry.Value, entry.Source, entry.Location, entry.ObservedAt)
				}
			}
			for _, usn := range old.USNs {
				existing.USNs = unique(existing.USNs, usn)
			}
			for _, url := range old.Locations {
				existing.Locations = unique(existing.Locations, url)
			}
			touch(existing, old.FirstSeen)
			touch(existing, old.LastSeen)
		} else {
			old.ID = deviceID(key)
			old.UDN = description.Device.UDN
			r.devices[key] = old
		}
		delete(r.devices, provisional)
	}
	if err := r.applyDevice(ip, location, description.Device, "", at); err != nil {
		return err
	}
	observeField(r.devices[key], "url_base", description.URLBase, "upnp", location, at)
	return nil
}

// applyDevice adds metadata recursively under the registry lock.
func (r *Registry) applyDevice(ip, location string, profile upnp.Device, parentID string, at time.Time) error {
	key := uuidKey(profile.UDN)
	if key == "" {
		return fmt.Errorf("invalid embedded UUID")
	}
	device, err := r.ensure(key, profile.UDN)
	if err != nil {
		return err
	}
	device.Locations = unique(device.Locations, location)
	touch(device, at)
	fields := map[string]string{"ip": ip, "udn": profile.UDN, "location": location, "parent_id": parentID, "friendly_name": profile.FriendlyName, "manufacturer": profile.Manufacturer, "manufacturer_url": profile.ManufacturerURL, "model_description": profile.ModelDescription, "model_name": profile.ModelName, "model_number": profile.ModelNumber, "model_url": profile.ModelURL, "serial_number": profile.SerialNumber, "device_type": profile.DeviceType, "presentation_url": profile.PresentationURL}
	for field, value := range fields {
		observeField(device, field, value, "upnp", location, at)
	}
	device.IP = device.Attributes["ip"]
	device.ParentID = device.Attributes["parent_id"]
	for _, service := range profile.Services {
		exists := false
		for _, old := range device.Services {
			if old == service {
				exists = true
				break
			}
		}
		if !exists {
			if len(device.Services) >= 256 {
				return fmt.Errorf("inventory service limit reached")
			}
			device.Services = append(device.Services, service)
		}
		// Include the complete service record in provenance, including conflicting URLs.
		observeField(device, "service:"+service.ID, fmt.Sprintf("%s|%s|%s|%s", service.Type, service.SCPDURL, service.ControlURL, service.EventSubURL), "upnp", location, at)
	}
	for _, child := range profile.Children {
		if err := r.applyDevice(ip, location, child, device.ID, at); err != nil {
			return err
		}
	}
	return nil
}

// Snapshot returns a deep copy of all records sorted by ID.
func (r *Registry) Snapshot() []Device {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Device, 0, len(r.devices))
	for _, original := range r.devices {
		copy := *original
		copy.winners = nil
		copy.Attributes = map[string]string{}
		for k, v := range original.Attributes {
			copy.Attributes[k] = v
		}
		copy.Evidence = map[string][]Evidence{}
		for k, v := range original.Evidence {
			copy.Evidence[k] = append([]Evidence(nil), v...)
		}
		copy.Services = append([]upnp.Service{}, original.Services...)
		copy.USNs = append([]string{}, original.USNs...)
		copy.Locations = append([]string{}, original.Locations...)
		result = append(result, copy)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}
