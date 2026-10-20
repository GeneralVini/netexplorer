// Package windows evaluates user-supplied, read-only endpoint inventory without network probes.
package windows

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// Snapshot is a versioned, untrusted export from the local Windows collector.
type Snapshot struct {
	// SchemaVersion selects the supported collector contract.
	SchemaVersion int `json:"schema_version"`
	// CollectedAt records when evidence was gathered.
	CollectedAt time.Time `json:"collected_at"`
	// ComputerName is informational and never used to resolve a peer.
	ComputerName string `json:"computer_name"`
	// Addresses contains endpoint IPv4 addresses for exact inventory binding.
	Addresses []string `json:"addresses"`
	// Caption is the reported operating system edition.
	Caption string `json:"caption"`
	// Version is the numeric operating system version.
	Version string `json:"version"`
	// Build is the operating system build number.
	Build string `json:"build"`
	// UBR is the optional update build revision.
	UBR *int `json:"ubr"`
	// ProductType is Win32_OperatingSystem.ProductType (1 client, 2 DC, 3 server).
	ProductType int `json:"product_type"`
	// ServicePackMajor distinguishes legacy patch applicability.
	ServicePackMajor int `json:"service_pack_major"`
	// Hotfixes contains observed KB identifiers, not a complete supersedence graph.
	Hotfixes []string `json:"hotfixes"`
	// Spooler records service state, or unknown when unavailable.
	Spooler string `json:"spooler"`
	// PointAndPrint contains policy values; absent values remain unknown.
	PointAndPrint map[string]int `json:"point_and_print"`
	// Components contains observed component versions.
	Components map[string]string `json:"components"`
	// Errors records collector failures rather than silently treating missing data as safe.
	Errors []string `json:"errors"`
}

// Finding separates patch evidence, applicability and configuration warnings.
type Finding struct {
	// ID is a CVE identifier or a named advisory without a verified CVE mapping.
	ID string `json:"id"`
	// Name is the human-readable issue name.
	Name string `json:"name"`
	// Assessment is negative, inconclusive or not_applicable; no exploit is performed.
	Assessment string `json:"assessment"`
	// Summary explains the evidence and its limits.
	Summary string `json:"summary"`
	// Reference links to the vendor or originating advisory.
	Reference string `json:"reference"`
	// Warnings identifies configuration risks without claiming exploit confirmation.
	Warnings []string `json:"warnings,omitempty"`
}

// Report retains endpoint evidence and deterministic offline assessments.
type Report struct {
	// Snapshot is the original validated endpoint inventory.
	Snapshot Snapshot `json:"snapshot"`
	// ImportedAt records server admission time.
	ImportedAt time.Time `json:"imported_at"`
	// Findings are evaluated using the bounded embedded rules.
	Findings []Finding `json:"findings"`
	// CatalogVersion identifies the reviewed rule snapshot.
	CatalogVersion string `json:"catalog_version"`
}

var kbPattern = regexp.MustCompile(`^KB[0-9]{6,8}$`)
var versionPattern = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,3}$`)

// Decode rejects unknown fields, excessive input and ambiguous endpoint identity.
func Decode(reader io.Reader, ip string, now time.Time) (Snapshot, error) {
	var s Snapshot
	data, err := io.ReadAll(io.LimitReader(reader, 262145))
	if err != nil || len(data) > 262144 {
		return s, fmt.Errorf("windows inventory exceeds 256 KiB or cannot be read")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&s); err != nil {
		return s, fmt.Errorf("invalid Windows inventory schema")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return s, fmt.Errorf("one JSON document is required")
	}
	if s.SchemaVersion != 1 || s.CollectedAt.IsZero() || s.CollectedAt.After(now.Add(5*time.Minute)) || now.Sub(s.CollectedAt) > 30*24*time.Hour {
		return s, fmt.Errorf("inventory must use schema 1 and be collected within 30 days")
	}
	if len(s.Addresses) == 0 || len(s.Addresses) > 64 || len(s.Hotfixes) > 4096 || len(s.Errors) > 64 || len(s.Components) > 16 || len(s.PointAndPrint) > 3 {
		return s, fmt.Errorf("inventory collection limit exceeded")
	}
	matched := false
	for _, address := range s.Addresses {
		a, e := netip.ParseAddr(address)
		if e != nil || !a.Is4() || a.String() != address {
			return s, fmt.Errorf("canonical IPv4 addresses required")
		}
		matched = matched || address == ip
	}
	if !matched {
		return s, fmt.Errorf("inventory does not contain this host IP")
	}
	if len(s.ComputerName) > 255 || len(s.Caption) > 255 || !strings.Contains(strings.ToLower(s.Caption), "windows") || !versionPattern.MatchString(s.Version) || !versionPattern.MatchString(s.Build) || len(s.Version) > 32 || len(s.Build) > 16 || s.ProductType < 1 || s.ProductType > 3 || s.ServicePackMajor < 0 || s.ServicePackMajor > 10 || (s.UBR != nil && (*s.UBR < 0 || *s.UBR > 10000000)) {
		return s, fmt.Errorf("invalid Windows identity")
	}
	for _, kb := range s.Hotfixes {
		if !kbPattern.MatchString(kb) {
			return s, fmt.Errorf("invalid KB identifier")
		}
	}
	for key, value := range s.Components {
		if key != "vbscript" && key != "defender_platform" && key != "defender_engine" && key != "defender_signatures" && key != "bitlocker" {
			return s, fmt.Errorf("unknown component")
		}
		if len(value) > 128 {
			return s, fmt.Errorf("component value too long")
		}
	}
	for key, value := range s.PointAndPrint {
		if key != "NoWarningNoElevationOnInstall" && key != "UpdatePromptSettings" && key != "RestrictDriverInstallationToAdministrators" {
			return s, fmt.Errorf("unknown printer policy")
		}
		if value < 0 || value > 2 || (key != "UpdatePromptSettings" && value > 1) {
			return s, fmt.Errorf("invalid printer policy value")
		}
	}
	for _, message := range s.Errors {
		if len(message) > 512 {
			return s, fmt.Errorf("collector error too long")
		}
	}
	if s.Spooler != "running" && s.Spooler != "stopped" && s.Spooler != "absent" && s.Spooler != "unknown" {
		return s, fmt.Errorf("invalid Spooler state")
	}
	return s, nil
}

// Evaluate uses positive patch observations only; absent KBs never prove vulnerability.
func Evaluate(s Snapshot, now time.Time) Report {
	r := Report{Snapshot: s, ImportedAt: now.UTC(), CatalogVersion: "2026-10-02.1", Findings: []Finding{}}
	add := func(id, name string) *Finding {
		r.Findings = append(r.Findings, Finding{ID: id, Name: name, Assessment: "inconclusive", Summary: "Local evidence retained. A verified product/component and update-supersedence rule is required.", Reference: "https://msrc.microsoft.com/update-guide/vulnerability/" + id})
		return &r.Findings[len(r.Findings)-1]
	}
	blue := add("CVE-2019-0708", "BlueKeep")
	// Microsoft excludes Windows 8 and 10; exact legacy patch observations are supported.
	modernClient := s.ProductType == 1 && (strings.HasPrefix(s.Version, "10.0.") || strings.HasPrefix(s.Version, "6.2.") || strings.HasPrefix(s.Version, "6.3."))
	if modernClient {
		blue.Assessment = "not_applicable"
		blue.Summary = "Reported client Windows version is outside the affected BlueKeep products."
	}
	if strings.HasPrefix(s.Version, "6.1.") && s.ServicePackMajor == 1 && hasKB(s, "KB4499164", "KB4499175", "KB4512506") {
		blue.Assessment = "negative"
		blue.Summary = "An explicit Windows 7 / Server 2008 R2 SP1 BlueKeep correction was reported installed. This is imported patch evidence, not a remote protocol test."
	}
	print := add("CVE-2021-34527", "PrintNightmare")
	print.Summary = "Spooler state and Point and Print policies retained. Product-specific patch and supersedence verification remains required."
	if s.Spooler == "absent" {
		print.Assessment = "not_applicable"
		print.Summary = "Collector reports Print Spooler absent; this is imported component evidence."
	}
	for _, key := range []string{"NoWarningNoElevationOnInstall", "UpdatePromptSettings"} {
		if value := s.PointAndPrint[key]; value != 0 {
			print.Warnings = append(print.Warnings, fmt.Sprintf("%s=%d: review Point and Print policy against Microsoft guidance.", key, value))
		}
	}
	print.Reference = "https://support.microsoft.com/help/5005010"
	vb := add("CVE-2018-8174", "VBScript remote code execution")
	vb.Summary = "VBScript version and installed updates retained. A verified component-version and product-specific supersedence rule is required before determining correction status."
	for _, item := range [][2]string{{"CVE-2026-45585", "YellowKey"}, {"GreenPlasma", "GreenPlasma"}, {"MiniPlasma", "MiniPlasma"}, {"CVE-2026-33825", "BlueHammer"}, {"CVE-2026-41091", "RedSun"}, {"CVE-2026-45498", "UnDefend"}} {
		f := add(item[0], item[1])
		f.Summary = "Local/physical advisory from May 2026. Current vendor product, CVE mapping and corrected component versions require verification; no network test performed."
		f.Reference = "https://www.gov.br/cisc/pt-br/alertas-de-ciberseguranca/seis-vulnerabilidades-zero-day-no-microsoft-windows"
	}
	return r
}

// hasKB requires an exact observed identifier instead of assuming update-date supersedence.
func hasKB(s Snapshot, candidates ...string) bool {
	for _, observed := range s.Hotfixes {
		for _, candidate := range candidates {
			if observed == candidate {
				return true
			}
		}
	}
	return false
}
