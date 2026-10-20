package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"netexplorer/internal/discovery/network"
	"netexplorer/internal/enrichment/nmap"
	"netexplorer/internal/inventory"
	"netexplorer/internal/scanner"
)

// webChecksFixture produces cancellable NSE evidence without a subprocess or LAN.
type webChecksFixture struct{ webNmapFixture }

func (f *webChecksFixture) Check(ctx context.Context, _ network.Interface, ip string, port nmap.Port, id string) (nmap.CheckResult, error) {
	select {
	case <-f.release:
	case <-ctx.Done():
		return nmap.CheckResult{}, ctx.Err()
	}
	return nmap.CheckResult{IP: ip, Port: port.Number, CheckID: id, Assessment: "positive", CVEs: []string{"CVE-2017-0143"}, NmapVersion: "fixture", ObservedAt: time.Now().UTC(), Evidence: []nmap.Script{{ID: id, Output: "<script>untrusted</script>"}}}, nil
}

func TestNSEHTTPAuthorizationScopeAndRecovery(t *testing.T) {
	selected := network.Interface{Name: "fixture0", Up: true, Multicast: true, IPv4: []string{"192.0.2.10/24"}}
	provider := &webChecksFixture{webNmapFixture{available: true, release: make(chan struct{})}}
	hostID := inventory.HostID("192.0.2.20")
	manager := scanner.NewManager(context.Background(), func(context.Context, network.Interface, time.Duration, bool, func(string, any), func([]inventory.Device)) (scanner.Report, error) {
		return scanner.Report{Hosts: []inventory.Host{{ID: hostID, IP: "192.0.2.20", Ports: []nmap.Port{{Number: 445, Protocol: "tcp", State: "open", Service: "microsoft-ds"}}}}}, nil
	}, provider)
	defer manager.Close()
	id, err := manager.Start(selected, time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		state, _ := manager.State(id)
		if state.Status != "running" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("inventory fixture timed out")
		}
		time.Sleep(time.Millisecond)
	}
	server := httptest.NewUnstartedServer(nil)
	server.Config.Handler = Router("fixture", func() ([]network.Interface, error) { return []network.Interface{selected}, nil }, Options{Manager: manager, Listen: server.Listener.Addr().String()})
	server.Start()
	defer server.Close()
	request := func(method, path, body, token string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Origin", server.URL)
		req.Header.Set("X-CSRF-Token", token)
		req.Header.Set("Content-Type", "application/json")
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, string(data)
	}
	_, home := request("GET", "/", "", "")
	matches := regexp.MustCompile(`name="csrf-token" content="([a-f0-9]+)"`).FindStringSubmatch(home)
	if len(matches) != 2 {
		t.Fatal("CSRF token missing")
	}
	token := matches[1]
	path := "/api/hosts/" + hostID + "/checks"
	for _, test := range []struct {
		body, token, path string
		status            int
	}{
		{`{"authorized":true,"check_id":"smb-vuln-ms17-010","port":445}`, "", path, 403},
		{`{"authorized":false,"check_id":"smb-vuln-ms17-010","port":445}`, token, path, 400},
		{`{"authorized":true,"check_id":"vuln","port":445}`, token, path, 400},
		{`{"authorized":true,"check_id":"smb-vuln-ms17-010","port":445,"password":"forbidden"}`, token, path, 400},
		{`{"authorized":true,"check_id":"smb-vuln-ms17-010","port":445,"target":"198.51.100.20"}`, token, path, 400},
		{`{"authorized":true,"check_id":"smb-vuln-ms17-010","port":80}`, token, path, 400},
		{`{"authorized":true,"check_id":"rdp-ntlm-info","port":445}`, token, path, 400},
		{`{"authorized":true,"check_id":"smb-vuln-ms17-010","port":445}`, token, "/api/hosts/missing/checks", 404},
	} {
		if code, body := request("POST", test.path, test.body, test.token); code != test.status {
			t.Fatal(test, code, body)
		}
	}
	if code, body := request("GET", "/api/checks/catalog", "", ""); code != 200 || !strings.Contains(body, "smb-vuln-ms17-010") || strings.Contains(body, "rdp-vuln-ms12-020") {
		t.Fatal(code, body)
	}
	code, body := request("POST", path, `{"authorized":true,"check_id":"smb-vuln-ms17-010","port":445}`, token)
	if code != 202 {
		t.Fatal(code, body)
	}
	var job scanner.CheckJob
	if err := json.Unmarshal([]byte(body), &job); err != nil {
		t.Fatal(err)
	}
	if code, body := request("GET", "/", "", ""); code != 200 || !strings.Contains(body, `data-latest-check="`+job.ID+`"`) {
		t.Fatal("running check not recoverable", code, body)
	}
	if code, _ := request("POST", "/api/scans", `{"authorized":true,"seconds":1}`, token); code != 409 {
		t.Fatal("shared admission lost", code)
	}
	if code, _ := request("POST", path, `{"authorized":true,"check_id":"smb2-time","port":445}`, token); code != 409 {
		t.Fatal(code)
	}
	close(provider.release)
	deadline = time.Now().Add(time.Second)
	for {
		code, body = request("GET", "/api/checks/"+job.ID, "", "")
		if code != 200 || json.Unmarshal([]byte(body), &job) != nil {
			t.Fatal(code, body)
		}
		if job.Status != "running" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("job timed out")
		}
		time.Sleep(time.Millisecond)
	}
	if job.Status != "completed" || job.Result == nil || job.Result.Assessment != "positive" {
		t.Fatal(job)
	}
	if code, body := request("GET", path, "", ""); code != 200 || !strings.Contains(body, "CVE-2017-0143") {
		t.Fatal(code, body)
	}
	if code, body := request("GET", "/api/hosts/"+hostID+"/services", "", ""); code != 200 || !strings.Contains(body, "check_catalog") || !strings.Contains(body, "positive") {
		t.Fatal(code, body)
	}
	if code, _ := request("POST", "/api/checks/"+job.ID+"/cancel", "", ""); code != 403 {
		t.Fatal("cancel lacked CSRF", code)
	}
	if code, _ := request("POST", "/api/checks/missing/cancel", "", token); code != 404 {
		t.Fatal(code)
	}
}
