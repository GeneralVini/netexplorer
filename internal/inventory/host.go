package inventory

import (
	"netexplorer/internal/enrichment/nmap"
	"time"
)

// Host keeps IP-level discovery/enrichment separate from logical UPnP identities.
type Host struct {
	// ID is a deterministic host-scoped identifier, never a UUID identity claim.
	ID string `json:"id"`
	// IP identifies the remote IPv4 host in the current scan.
	IP string `json:"ip"`
	// TTL is optional response evidence; it is not a verified OS identity.
	TTL int `json:"ttl,omitempty"`
	// MDNS contains unverified hostname, model and service advertisements.
	MDNS []string `json:"mdns,omitempty"`
	// MAC is optional Nmap link-layer evidence.
	MAC string `json:"mac,omitempty"`
	// Vendor is optional MAC vendor evidence, not a UPnP manufacturer claim.
	Vendor string `json:"vendor,omitempty"`
	// Sources lists the protocols that observed the host.
	Sources []string `json:"sources"`
	// Coverage records the successfully requested TCP range.
	Coverage string `json:"coverage,omitempty"`
	// AutoTCPStatus records queue, running or terminal automatic inspection status.
	AutoTCPStatus string `json:"auto_tcp_status,omitempty"`
	// WindowsCaption comes from a validated Windows endpoint snapshot.
	WindowsCaption string `json:"windows_caption,omitempty"`
	// Ports contains manual Nmap TCP observations belonging to this host only.
	Ports []nmap.Port `json:"ports"`
	// ObservedAt timestamps host discovery evidence.
	ObservedAt time.Time `json:"observed_at"`
	// EnrichedAt timestamps a successful manual port/service scan.
	EnrichedAt time.Time `json:"enriched_at,omitempty"`
}

// HostID keeps transient IP-based host identity distinct from logical device IDs.
func HostID(ip string) string { return deviceID("host:" + ip) }
