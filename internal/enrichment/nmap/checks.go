package nmap

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"netexplorer/internal/discovery/network"
)

// CheckSpec describes a reviewed, fixed system-Nmap script action.
type CheckSpec struct {
	// ID is the sole public selector; it never accepts expressions or paths.
	ID string `json:"id"`
	// Label names the manual action.
	Label string `json:"label"`
	// Kind is information or vulnerability.
	Kind string `json:"kind"`
	// Note describes protocol interaction and interpretation limits.
	Note string `json:"note"`
	// Reference is the reviewed public documentation.
	Reference string `json:"reference"`
}

// CheckCatalog returns independent metadata for the enabled scripts.
func CheckCatalog() []CheckSpec {
	return []CheckSpec{
		{ID: "rdp-ntlm-info", Label: "RDP details", Kind: "information", Note: "Requests RDP/CredSSP negotiation metadata with null credentials; no password attempts.", Reference: "https://nmap.org/nsedoc/scripts/rdp-ntlm-info.html"},
		{ID: "smb2-security-mode", Label: "SMB signing", Kind: "information", Note: "Negotiates SMB2/SMB3 signing metadata; no disk-share access.", Reference: "https://nmap.org/nsedoc/scripts/smb2-security-mode.html"},
		{ID: "smb2-time", Label: "SMB time", Kind: "information", Note: "Requests SMB2 server time metadata; no disk-share access.", Reference: "https://nmap.org/nsedoc/scripts/smb2-time.html"},
		{ID: "smb-vuln-ms17-010", Label: "Check MS17-010", Kind: "vulnerability", Note: "Active SMBv1 patch-state check through anonymous IPC$ metadata. No exploit, passwords or disk-share access. Authentication/network failures are inconclusive.", Reference: "https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html"},
	}
}

// CheckSpecFor rejects unknown script names before process admission.
func CheckSpecFor(id string) (CheckSpec, error) {
	for _, spec := range CheckCatalog() {
		if spec.ID == id {
			return spec, nil
		}
	}
	return CheckSpec{}, fmt.Errorf("unknown or disabled NSE check")
}

// ApplicableChecks permits only observed open, reviewed default-port services.
func ApplicableChecks(port Port) []CheckSpec {
	result := []CheckSpec{}
	if port.Protocol != "tcp" || port.State != "open" {
		return result
	}
	service := strings.ToLower(port.Service)
	smb := (port.Number == 139 || port.Number == 445) && (service == "microsoft-ds" || service == "microsoft-ds?" || service == "netbios-ssn" || service == "" || service == "unknown")
	rdp := port.Number == 3389 && (service == "ms-wbt-server" || service == "ms-wbt-server?" || service == "" || service == "unknown")
	for _, spec := range CheckCatalog() {
		if (rdp && spec.ID == "rdp-ntlm-info") || (smb && spec.ID != "rdp-ntlm-info") {
			result = append(result, spec)
		}
	}
	return result
}

// ScriptElement is a bounded NSE scalar, rendered only as untrusted text.
type ScriptElement struct {
	// Key identifies the script-defined field when present.
	Key string `xml:"key,attr" json:"key,omitempty"`
	// Value is the scalar text value.
	Value string `xml:",chardata" json:"value"`
}

// ScriptTable preserves bounded nested NSE evidence without evaluating it.
type ScriptTable struct {
	// Key identifies the script-defined table.
	Key string `xml:"key,attr" json:"key,omitempty"`
	// Elements contains scalar child fields.
	Elements []ScriptElement `xml:"elem" json:"elements,omitempty"`
	// Tables contains nested tables.
	Tables []ScriptTable `xml:"table" json:"tables,omitempty"`
}

// Script is raw evidence retained independently from a check assessment.
type Script struct {
	// ID identifies the script that produced the evidence.
	ID string `xml:"id,attr" json:"id"`
	// Output is display-only human-readable output.
	Output string `xml:"output,attr" json:"output,omitempty"`
	// Elements contains root scalar fields.
	Elements []ScriptElement `xml:"elem" json:"elements,omitempty"`
	// Tables contains nested structured evidence.
	Tables []ScriptTable `xml:"table" json:"tables,omitempty"`
}

// CheckResult records an assessment without claiming exploitation or overall security.
type CheckResult struct {
	// CheckID identifies the reviewed script.
	CheckID string `json:"check_id"`
	// IP is the single validated remote peer.
	IP string `json:"ip"`
	// Port identifies the observed service requested by the caller.
	Port int `json:"port"`
	// Assessment is positive, negative, inconclusive or not_applicable.
	Assessment string `json:"assessment"`
	// Summary explains exactly what the adapter concluded.
	Summary string `json:"summary"`
	// CVEs preserves script-reported IDs, never guessed from a port.
	CVEs []string `json:"cves,omitempty"`
	// Evidence contains original bounded script data.
	Evidence []Script `json:"evidence"`
	// NmapVersion is the version recorded in the run XML.
	NmapVersion string `json:"nmap_version,omitempty"`
	// ObservedAt timestamps interpretation of the completed run.
	ObservedAt time.Time `json:"observed_at"`
}

// validateScripts enforces additional evidence limits inside the shared XML bounds.
func validateScripts(scripts []Script) error {
	if len(scripts) > 32 {
		return fmt.Errorf("too many NSE results")
	}
	seen := map[string]bool{}
	for _, script := range scripts {
		if script.ID == "" || len(script.ID) > 128 || seen[script.ID] || len(script.Output) > 64<<10 {
			return fmt.Errorf("invalid or oversized NSE script")
		}
		seen[script.ID] = true
		nodes, bytes := 0, len(script.Output)
		if err := validateNodes(script.Elements, script.Tables, 1, &nodes, &bytes); err != nil {
			return err
		}
	}
	return nil
}

// validateNodes bounds recursive evidence even when a script supplies unexpected keys.
func validateNodes(elements []ScriptElement, tables []ScriptTable, depth int, nodes, bytes *int) error {
	if depth > 12 {
		return fmt.Errorf("NSE evidence depth exceeded")
	}
	for _, element := range elements {
		*nodes++
		*bytes += len(element.Key) + len(element.Value)
		if len(element.Key) > 128 || len(element.Value) > 4096 {
			return fmt.Errorf("NSE scalar exceeds limit")
		}
	}
	for _, table := range tables {
		*nodes++
		*bytes += len(table.Key)
		if len(table.Key) > 128 {
			return fmt.Errorf("NSE table key exceeds limit")
		}
		if err := validateNodes(table.Elements, table.Tables, depth+1, nodes, bytes); err != nil {
			return err
		}
	}
	if *nodes > 1024 || *bytes > 128<<10 {
		return fmt.Errorf("NSE evidence exceeds limit")
	}
	return nil
}

// Check executes exactly one catalog script after independently validating LAN scope.
// SMB's guest account fallback is disabled; only anonymous metadata negotiation is allowed.
func (p *Provider) Check(ctx context.Context, selected network.Interface, target string, port Port, id string) (CheckResult, error) {
	spec, err := CheckSpecFor(id)
	if err != nil {
		return CheckResult{}, err
	}
	allowed := false
	for _, candidate := range ApplicableChecks(port) {
		if candidate.ID == id {
			allowed = true
		}
	}
	if !allowed {
		return CheckResult{}, fmt.Errorf("check is incompatible with the observed service")
	}
	scope, err := p.scopeFor(selected)
	if err != nil {
		return CheckResult{}, err
	}
	ip, err := netip.ParseAddr(target)
	if err != nil || !scope.allows(ip) {
		return CheckResult{}, fmt.Errorf("target is not a remote IPv4 in the selected LAN")
	}
	if _, err := p.lookup("nmap"); err != nil {
		return CheckResult{}, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 55*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return CheckResult{}, err
	}
	// Script help resolves only the fixed catalog name, performs no network action,
	// and detects absent installed scripts before attempting a peer check.
	help, err := p.run(ctx, []string{"--script-help", spec.ID})
	if err != nil {
		return CheckResult{}, fmt.Errorf("installed NSE script %s unavailable or invalid: %w", spec.ID, err)
	}
	if len(help) > 256<<10 || !strings.Contains(string(help), spec.ID) {
		return CheckResult{}, fmt.Errorf("installed NSE script %s was not found", spec.ID)
	}
	scriptArgs := "smbnoguest=true"
	if spec.ID != "rdp-ntlm-info" {
		scriptArgs += ",smbport=" + strconv.Itoa(port.Number)
	}
	if spec.ID == "smb-vuln-ms17-010" {
		scriptArgs += ",vulns.showall=true,smb-vuln-ms17-010.sharename=IPC$"
	}
	args := []string{"-sT", "-Pn", "-n", "-e", scope.iface, "-p", strconv.Itoa(port.Number), "--max-retries", "1", "--host-timeout", "45s", "--script-timeout", "30s", "--script", spec.ID, "--script-args", scriptArgs, "-oX", "-", ip.String()}
	data, err := p.run(ctx, args)
	if err != nil {
		return CheckResult{}, err
	}
	if len(data) > 2<<20 {
		return CheckResult{}, fmt.Errorf("NSE XML exceeds size limit")
	}
	hosts, err := Parse(data)
	if err != nil {
		return CheckResult{}, err
	}
	if len(hosts) != 1 || hosts[0].IP != target {
		return CheckResult{}, fmt.Errorf("NSE returned an unexpected peer")
	}
	host := hosts[0]
	scripts := append([]Script{}, host.Scripts...)
	open := false
	for _, observation := range host.Ports {
		if observation.Number != port.Number {
			return CheckResult{}, fmt.Errorf("NSE returned an unexpected port")
		}
		open = observation.State == "open"
		scripts = append(scripts, observation.Scripts...)
	}
	if err := validateScripts(scripts); err != nil {
		return CheckResult{}, err
	}
	for _, script := range scripts {
		if script.ID != id {
			return CheckResult{}, fmt.Errorf("NSE returned an unrequested script")
		}
	}
	result := interpretCheck(spec, target, port.Number, scripts)
	result.NmapVersion = host.NmapVersion
	result.ObservedAt = time.Now().UTC()
	if !open {
		result.Assessment = "not_applicable"
		result.CVEs = nil
		result.Summary = "The service is no longer observed open; no applicable check result."
	}
	return result, nil
}

var cveID = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// interpretCheck uses structured script-specific fields, never arbitrary output substrings.
func interpretCheck(spec CheckSpec, ip string, port int, scripts []Script) CheckResult {
	result := CheckResult{CheckID: spec.ID, IP: ip, Port: port, Assessment: "inconclusive", Summary: "No interpretable script evidence; this is not a negative finding.", Evidence: scripts}
	if len(scripts) != 1 {
		return result
	}
	script := scripts[0]
	if spec.Kind == "information" {
		valid := false
		for _, field := range script.Elements {
			if field.Value != "" && ((spec.ID == "rdp-ntlm-info" && field.Key == "Target_Name") || (spec.ID == "smb2-time" && field.Key == "date" && validScriptDate(field.Value))) {
				valid = true
			}
		}
		if spec.ID == "smb2-security-mode" {
			for _, table := range script.Tables {
				switch table.Key {
				case "2.0.2", "2.1", "3.0", "3.0.2", "3.1.1":
					for _, field := range table.Elements {
						switch field.Value {
						case "Message signing enabled and required", "Message signing enabled but not required", "Message signing is disabled and not required!", "Message signing is disabled!":
							valid = true
						}
					}
				}
			}
		}
		if valid {
			result.Assessment = "not_applicable"
			result.Summary = "Informational metadata collected; no vulnerability assessment was performed."
		}
		return result
	}
	// The upstream MS17-010 script also emits NOT VULNERABLE on connection errors.
	// A negative finding therefore requires its exact patched-system check result.
	if len(script.Tables) != 1 {
		return result
	}
	for _, table := range script.Tables {
		if table.Key != "CVE-2017-0143" {
			continue
		}
		state := ""
		stateFields := 0
		for _, field := range table.Elements {
			if field.Key == "state" {
				stateFields++
				if stateFields > 1 {
					return result
				}
				state = field.Value
			}
		}
		ids := []string{}
		patched := false
		patchTables := 0
		seenIDs := map[string]bool{}
		for _, child := range table.Tables {
			if child.Key == "check_results" {
				patchTables++
				if len(child.Elements) != 1 || len(child.Tables) != 0 {
					return result
				}
			}
			for _, field := range child.Elements {
				if child.Key == "ids" {
					id := strings.TrimPrefix(field.Value, "CVE:")
					if len(id) <= 32 && cveID.MatchString(id) && !seenIDs[id] {
						seenIDs[id] = true
						ids = append(ids, id)
						if len(ids) > 16 {
							return result
						}
					}
				}
				if child.Key == "check_results" && field.Value == "This system is patched." {
					patched = true
				}
			}
		}
		if state == "VULNERABLE" && seenIDs["CVE-2017-0143"] {
			result.Assessment = "positive"
			result.Summary = "The active script indicated missing MS17-010 protection; verify patch applicability. No exploit was executed."
			result.CVEs = ids
			return result
		}
		if state == "NOT VULNERABLE" && patched && patchTables == 1 && seenIDs["CVE-2017-0143"] {
			result.Assessment = "negative"
			result.Summary = "The script received a recognized patched-system response for this check; this is not an overall security assessment."
			result.CVEs = ids
			return result
		}
	}
	return result
}

// validScriptDate accepts the known NSE date formats instead of treating errors as metadata.
func validScriptDate(value string) bool {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05"} {
		if _, err := time.Parse(layout, value); err == nil {
			return true
		}
	}
	return false
}
