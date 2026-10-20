// Package services adds conservative, offline references to observed TCP evidence.
package services

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"netexplorer/internal/enrichment/nmap"
)

// Reference describes a historical association or an unverified version match.
type Reference struct {
	// Label identifies the advisory or historical family.
	Label string `json:"label"`
	// URL links to the public evidence supporting the reference.
	URL string `json:"url"`
	// Note explains applicability limits; references never confirm a vulnerability.
	Note string `json:"note"`
}

// Row contains presentation metadata without triggering network requests.
type Row struct {
	// Port retains the original transport, state and product evidence.
	nmap.Port
	// WebURL is a literal-IP browser action for an HTTP-like service.
	WebURL string `json:"web_url,omitempty"`
	// MediaURL is a credential-free literal-IP RTSP endpoint for an observed TCP service.
	MediaURL string `json:"media_url,omitempty"`
	// Action is shares, rdp, or copy; remote access is always manual.
	Action string `json:"action"`
	// History is an optional port association, never an infection diagnosis.
	History *Reference `json:"history,omitempty"`
	// CVEs contains potential matches from the small reviewed offline catalog.
	CVEs []Reference `json:"cves,omitempty"`
	// Checks lists compatible manual actions without executing them.
	Checks []nmap.CheckSpec `json:"checks,omitempty"`
	// SearchURL lets users review other product/version references at NVD.
	SearchURL string `json:"search_url,omitempty"`
}

const nmapSource = "https://github.com/nmap/nmap/blob/master/nmap-services"

// Annotate handles arbitrary port numbers, favoring detected protocols over defaults.
func Annotate(ip string, port nmap.Port) Row {
	row := Row{Port: port, Action: "copy", Checks: nmap.ApplicableChecks(port)}
	address, err := netip.ParseAddr(ip)
	if err != nil || !address.Is4() || port.Number < 1 || port.Number > 65535 {
		return row
	}
	service := strings.ToLower(port.Service)
	reachable := port.State == "open" || port.State == "filtered" || port.State == "open|filtered"
	if reachable {
		if port.Protocol == "tcp" && (service == "rtsp" || service == "rtsp?" || service == "rtsp-alt" || (service == "" || service == "unknown") && (port.Number == 554 || port.Number == 8554)) {
			host := address.String()
			if port.Number != 554 {
				host += ":" + strconv.Itoa(port.Number)
			}
			row.MediaURL = "rtsp://" + host + "/"
		}
		if service == "ms-wbt-server" || (service == "unknown" || service == "") && port.Number == 3389 {
			row.Action = "rdp"
		}
		scheme := ""
		if strings.Contains(service, "http") {
			scheme = "http"
			if port.Tunnel == "ssl" || strings.Contains(service, "https") {
				scheme = "https"
			}
		}
		if scheme == "" && (service == "" || service == "unknown") {
			if port.Number == 80 {
				scheme = "http"
			}
			if port.Number == 443 {
				scheme = "https"
			}
		}
		if scheme != "" {
			host := ip
			if !(scheme == "http" && port.Number == 80) && !(scheme == "https" && port.Number == 443) {
				host += ":" + strconv.Itoa(port.Number)
			}
			row.WebURL = scheme + "://" + host + "/"
		}
	}
	if port.State == "open" {
		if service == "microsoft-ds" || service == "microsoft-ds?" || service == "netbios-ssn" || (service == "unknown" || service == "") && (port.Number == 445 || port.Number == 139) {
			row.Action = "shares"
		}
		if service == "ms-wbt-server" || (service == "unknown" || service == "") && port.Number == 3389 {
			row.Action = "rdp"
		}
		family := map[int]string{12345: "NetBus", 12346: "NetBus", 27374: "SubSeven", 54320: "Back Orifice 2000"}[port.Number]
		if family != "" {
			row.History = &Reference{Label: family, URL: nmapSource, Note: "Historical TCP port association only. Legitimate applications can use this port; verify the process on the host."}
		}
		if port.Number == 6200 {
			row.History = &Reference{Label: "Compromised vsftpd distribution", URL: "https://nvd.nist.gov/vuln/detail/CVE-2011-2523", Note: "Historical backdoor port association; this port alone does not identify vsftpd or prove compromise."}
		}
		product := strings.ToLower(strings.TrimSpace(port.Product))
		if product == "vsftpd" && port.Version == "2.3.4" {
			row.CVEs = append(row.CVEs, Reference{Label: "CVE-2011-2523", URL: "https://nvd.nist.gov/vuln/detail/CVE-2011-2523", Note: "Potential version match. Only compromised downloads from June 30–July 3, 2011 were affected; provenance and patch status are unknown."})
		}
		if product == "apache httpd" && (port.Version == "2.4.49" || port.Version == "2.4.50") {
			if port.Version == "2.4.49" {
				row.CVEs = append(row.CVEs, apacheReference("CVE-2021-41773"))
			}
			row.CVEs = append(row.CVEs, apacheReference("CVE-2021-42013"))
		}
	}
	if port.Product != "" && port.Version != "" {
		row.SearchURL = "https://nvd.nist.gov/vuln/search/results?" + url.Values{"query": {port.Product + " " + port.Version}, "search_type": {"all"}}.Encode()
	}
	return row
}

// apacheReference explicitly preserves the distinction between a banner and applicability.
func apacheReference(id string) Reference {
	return Reference{Label: id, URL: "https://httpd.apache.org/security/vulnerabilities_24.html#" + id, Note: "Potential exact version match. Configuration, vendor backports and banner accuracy require verification; no vulnerability probe was performed."}
}
