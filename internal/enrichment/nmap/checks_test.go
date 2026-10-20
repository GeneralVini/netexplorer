package nmap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func checkXML(script, body string, hostLevel bool) []byte {
	evidence := fmt.Sprintf(`<script id="%s" output="Fixture evidence">%s</script>`, script, body)
	ports := `<ports><port protocol="tcp" portid="445"><state state="open"/>`
	hostScripts := ""
	if hostLevel {
		ports += `</port></ports>`
		hostScripts = `<hostscript>` + evidence + `</hostscript>`
	} else {
		ports += evidence + `</port></ports>`
	}
	return []byte(`<nmaprun version="7.98-fixture"><host><status state="up"/><address addr="192.0.2.20" addrtype="ipv4"/>` + ports + hostScripts + `</host><runstats><finished exit="success"/></runstats></nmaprun>`)
}

func ms17Table(state, checks string) string {
	return `<table key="CVE-2017-0143"><elem key="state">` + state + `</elem><table key="ids"><elem>CVE:CVE-2017-0143</elem></table>` + checks + `</table>`
}

func TestNSEStructuredAssessments(t *testing.T) {
	spec, _ := CheckSpecFor("smb-vuln-ms17-010")
	for _, test := range []struct{ body, assessment string }{
		{ms17Table("VULNERABLE", ""), "positive"},
		{ms17Table("NOT VULNERABLE", `<table key="check_results"><elem>This system is patched.</elem></table>`), "negative"},
		{ms17Table("NOT VULNERABLE", `<table key="check_results"><elem>Could not connect to 'IPC$'</elem></table>`), "inconclusive"},
		{ms17Table("NOT VULNERABLE", ""), "inconclusive"},
		{ms17Table("NOT VULNERABLE", `<table key="check_results"><elem>This system is patched.</elem><elem>Connection failed</elem></table>`), "inconclusive"},
		{ms17Table("VULNERABLE", `<elem key="state">NOT VULNERABLE</elem>`), "inconclusive"},
		{ms17Table("VULNERABLE", "") + ms17Table("NOT VULNERABLE", ""), "inconclusive"},
		{strings.Replace(ms17Table("VULNERABLE", ""), "CVE:CVE-2017-0143", "CVE:CVE-2099-9999", 1), "inconclusive"},
		{`<elem>VULNERABLE CVE-2017-0143</elem>`, "inconclusive"},
	} {
		for _, hostLevel := range []bool{false, true} {
			hosts, err := Parse(checkXML(spec.ID, test.body, hostLevel))
			if err != nil {
				t.Fatal(err)
			}
			scripts := hosts[0].Scripts
			if !hostLevel {
				scripts = hosts[0].Ports[0].Scripts
			}
			result := interpretCheck(spec, "192.0.2.20", 445, scripts)
			if result.Assessment != test.assessment {
				t.Fatal(test, result)
			}
			if (result.Assessment == "positive" || result.Assessment == "negative") && (len(result.CVEs) != 1 || result.CVEs[0] != "CVE-2017-0143") {
				t.Fatal(result)
			}
		}
	}
	result := interpretCheck(spec, "192.0.2.20", 445, []Script{{ID: spec.ID, Output: "VULNERABLE CVE-2017-0143"}})
	if result.Assessment != "inconclusive" {
		t.Fatal("raw text became a finding", result)
	}
}

func TestInformationalAdapters(t *testing.T) {
	for _, test := range []struct {
		id, body string
		valid    bool
	}{
		{"rdp-ntlm-info", `<elem key="Target_Name">WORKSTATION</elem>`, true},
		{"rdp-ntlm-info", `<elem key="Error">Connection failed</elem>`, false},
		{"smb2-time", `<elem key="date">2026-10-02T12:00:00</elem>`, true},
		{"smb2-time", `<elem key="date">N/A</elem>`, false},
		{"smb2-time", `<elem key="date">Connection failed</elem>`, false},
		{"smb2-security-mode", `<table key="3.1.1"><elem>Message signing enabled and required</elem></table>`, true},
		{"smb2-security-mode", `<table key="3.1.1"><elem>Unknown response</elem></table>`, false},
	} {
		spec, _ := CheckSpecFor(test.id)
		hosts, err := Parse(checkXML(test.id, test.body, true))
		if err != nil {
			t.Fatal(err)
		}
		result := interpretCheck(spec, "192.0.2.20", 445, hosts[0].Scripts)
		expected := "inconclusive"
		if test.valid {
			expected = "not_applicable"
		}
		if result.Assessment != expected || len(result.CVEs) != 0 {
			t.Fatal(test, result)
		}
	}
}

func TestNSELimitsAndCatalog(t *testing.T) {
	for _, id := range []string{"vuln", "all", "default", "../../evil.nse", "rdp-vuln-ms12-020", "smb-brute"} {
		if _, err := CheckSpecFor(id); err == nil {
			t.Fatal("unreviewed selection accepted", id)
		}
	}
	for _, bad := range []Script{
		{ID: "test", Output: strings.Repeat("x", (64<<10)+1)},
		{ID: "test", Elements: []ScriptElement{{Key: "k", Value: strings.Repeat("x", 4097)}}},
	} {
		if err := validateScripts([]Script{bad}); err == nil {
			t.Fatal("oversized evidence accepted")
		}
	}
	if err := validateScripts([]Script{{ID: "test"}, {ID: "test"}}); err == nil {
		t.Fatal("duplicate script accepted")
	}
	nested := ScriptTable{Key: "root"}
	for depth := 0; depth < 13; depth++ {
		nested = ScriptTable{Tables: []ScriptTable{nested}}
	}
	if err := validateScripts([]Script{{ID: "test", Tables: []ScriptTable{nested}}}); err == nil {
		t.Fatal("deep evidence accepted")
	}
	for _, port := range []Port{{Number: 445, Protocol: "tcp", State: "filtered"}, {Number: 445, Protocol: "tcp", State: "open", Service: "ssh"}, {Number: 1234, Protocol: "tcp", State: "open", Service: "ms-wbt-server"}} {
		if len(ApplicableChecks(port)) != 0 {
			t.Fatal(port)
		}
	}
}

func TestCheckExecutionIsScopedAndAnonymous(t *testing.T) {
	var args []string
	provider := fixtureProvider(t, nil, &args)
	calls := 0
	provider.run = func(ctx context.Context, captured []string) ([]byte, error) {
		calls++
		if len(captured) == 2 && captured[0] == "--script-help" {
			return []byte(captured[1] + "\nCategories: safe, vuln"), nil
		}
		args = append([]string{}, captured...)
		return checkXML("smb-vuln-ms17-010", ms17Table("VULNERABLE", ""), true), nil
	}
	port := Port{Number: 445, Protocol: "tcp", State: "open", Service: "microsoft-ds"}
	result, err := provider.Check(context.Background(), syntheticInterface(), "192.0.2.20", port, "smb-vuln-ms17-010")
	if err != nil || result.Assessment != "positive" || result.NmapVersion != "7.98-fixture" || calls != 2 {
		t.Fatal(result, err, calls)
	}
	command := " " + strings.Join(args, " ") + " "
	for _, required := range []string{" -sT ", " -Pn ", " -n ", " -p 445 ", " --script smb-vuln-ms17-010 ", "smbnoguest=true,smbport=445,vulns.showall=true,smb-vuln-ms17-010.sharename=IPC$", " --script-timeout 30s ", " --host-timeout 45s ", " 192.0.2.20 "} {
		if !strings.Contains(command, required) {
			t.Fatal("missing constraint", required, args)
		}
	}
	for _, forbidden := range []string{"smbusername", "smbpassword", "smbhash", "-A", "--script vuln", "-sV"} {
		if strings.Contains(command, forbidden) {
			t.Fatal(args)
		}
	}
	for _, target := range []string{"192.0.2.10", "192.0.2.11", "192.0.2.12", "198.51.100.20", "192.0.2.255", "--script=vuln"} {
		calls = 0
		if _, err := provider.Check(context.Background(), syntheticInterface(), target, port, "smb-vuln-ms17-010"); err == nil || calls != 0 {
			t.Fatal(target, err, calls)
		}
	}
	calls = 0
	if _, err := provider.Check(context.Background(), syntheticInterface(), "192.0.2.20", port, "vuln"); err == nil || calls != 0 {
		t.Fatal("unknown script executed")
	}
	provider.run = func(context.Context, []string) ([]byte, error) { return nil, errors.New("script unavailable") }
	if _, err := provider.Check(context.Background(), syntheticInterface(), "192.0.2.20", port, "smb-vuln-ms17-010"); err == nil || !strings.Contains(err.Error(), "installed NSE script") {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls = 0
	provider.run = func(context.Context, []string) ([]byte, error) { calls++; return nil, nil }
	if _, err := provider.Check(ctx, syntheticInterface(), "192.0.2.20", port, "smb-vuln-ms17-010"); !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatal(err, calls)
	}
}

func TestNSERealFakeSubprocessAndCancellation(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Symlink(executable, directory+"/nmap"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	t.Setenv("NETEXPLORER_NMAP_TEST_HELPER", "1")
	t.Setenv("NETEXPLORER_NMAP_TEST_MODE", "nse")
	provider := New()
	provider.locals = func() ([]net.Addr, error) { return []net.Addr{}, nil }
	port := Port{Number: 445, Protocol: "tcp", State: "open", Service: "microsoft-ds"}
	result, err := provider.Check(context.Background(), syntheticInterface(), "192.0.2.20", port, "smb-vuln-ms17-010")
	if err != nil || result.Assessment != "positive" || result.NmapVersion != "7.98-fixture" {
		t.Fatal(result, err)
	}
	t.Setenv("NETEXPLORER_NMAP_TEST_MODE", "wait")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := provider.Check(ctx, syntheticInterface(), "192.0.2.20", port, "smb-vuln-ms17-010"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

func TestNSERejectsUnexpectedOutputAndKeepsMissingEvidenceInconclusive(t *testing.T) {
	var args []string
	provider := fixtureProvider(t, nil, &args)
	port := Port{Number: 445, Protocol: "tcp", State: "open", Service: "microsoft-ds"}
	valid := string(checkXML("smb-vuln-ms17-010", ms17Table("VULNERABLE", ""), true))
	for _, data := range []string{strings.Replace(valid, "192.0.2.20", "192.0.2.30", 1), strings.Replace(valid, `portid="445"`, `portid="80"`, 1), strings.Replace(valid, `id="smb-vuln-ms17-010"`, `id="smb-brute"`, 1), strings.Replace(valid, `<host>`, `<host timedout="true">`, 1), strings.Repeat("x", (2<<20)+1)} {
		provider.run = func(_ context.Context, captured []string) ([]byte, error) {
			if captured[0] == "--script-help" {
				return []byte("smb-vuln-ms17-010"), nil
			}
			return []byte(data), nil
		}
		if _, err := provider.Check(context.Background(), syntheticInterface(), "192.0.2.20", port, "smb-vuln-ms17-010"); err == nil {
			t.Fatal("unexpected NSE XML accepted")
		}
	}
	provider.run = func(_ context.Context, captured []string) ([]byte, error) {
		if captured[0] == "--script-help" {
			return []byte("smb-vuln-ms17-010"), nil
		}
		return checkXML("smb-vuln-ms17-010", "", true), nil
	}
	result, err := provider.Check(context.Background(), syntheticInterface(), "192.0.2.20", port, "smb-vuln-ms17-010")
	if err != nil || result.Assessment != "inconclusive" {
		t.Fatal(result, err)
	}
	provider.run = func(_ context.Context, captured []string) ([]byte, error) {
		if captured[0] == "--script-help" {
			return []byte("smb-vuln-ms17-010"), nil
		}
		return []byte(strings.Replace(valid, `state="open"`, `state="closed"`, 1)), nil
	}
	result, err = provider.Check(context.Background(), syntheticInterface(), "192.0.2.20", port, "smb-vuln-ms17-010")
	if err != nil || result.Assessment != "not_applicable" {
		t.Fatal(result, err)
	}
}
