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

// webNmapFixture produces no network traffic and exposes a cancellable job.
type webNmapFixture struct {
	available bool
	release   chan struct{}
}

func (f *webNmapFixture) Available() bool { return f.available }
func (f *webNmapFixture) Discover(context.Context, network.Interface) ([]nmap.Host, error) {
	return []nmap.Host{{IP: "192.0.2.20"}, {IP: "192.0.2.30", Vendor: "Fixture Company"}}, nil
}
func (f *webNmapFixture) Scan(ctx context.Context, _ network.Interface, ip string) (nmap.Host, error) {
	select {
	case <-f.release:
	case <-ctx.Done():
		return nmap.Host{}, ctx.Err()
	}
	return nmap.Host{IP: ip, Ports: []nmap.Port{{Number: 80, Protocol: "tcp", State: "open", Product: "<script>unsafe</script>"}}}, nil
}

func TestHostAndNmapHTTPActions(t *testing.T) {
	provider := &webNmapFixture{available: true, release: make(chan struct{})}
	selected := network.Interface{Name: "fixture", Up: true, Multicast: true, IPv4: []string{"192.0.2.10/24"}}
	manager := scanner.NewManager(context.Background(), func(context.Context, network.Interface, time.Duration, bool, func(string, any), func([]inventory.Device)) (scanner.Report, error) {
		return scanner.Report{Devices: []inventory.Device{{ID: "logical", IP: "192.0.2.20"}}, Warnings: []scanner.Warning{}}, nil
	}, provider)
	defer manager.Close()
	server := httptest.NewUnstartedServer(nil)
	server.Config.Handler = Router("fixture", func() ([]network.Interface, error) { return []network.Interface{selected}, nil }, Options{Manager: manager, DefaultInterface: selected.Name, Listen: server.Listener.Addr().String()})
	server.Start()
	defer server.Close()
	client := server.Client()
	client.Timeout = 3 * time.Second
	request := func(method, path, body, token string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-CSRF-Token", token)
		req.Header.Set("Origin", server.URL)
		req.Header.Set("Content-Type", "application/json")
		response, err := client.Do(req)
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
	_, html := request("GET", "/", "", "")
	match := regexp.MustCompile(`name="csrf-token" content="([a-f0-9]+)"`).FindStringSubmatch(html)
	if len(match) != 2 {
		t.Fatal("missing token")
	}
	token := match[1]
	code, body := request("POST", "/api/scans", `{"authorized":true,"all_hosts":true,"seconds":1}`, token)
	if code != 202 {
		t.Fatal(code, body)
	}
	var started struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &started); err != nil {
		t.Fatal(err)
	}
	if code, body := request("GET", "/api/scans/"+started.ID+"/events", "", ""); code != 200 || !strings.Contains(body, "host-discovery-started") {
		t.Fatal(code, body)
	}
	code, body = request("GET", "/api/hosts", "", "")
	var hosts []inventory.Host
	if code != 200 || json.Unmarshal([]byte(body), &hosts) != nil || len(hosts) != 2 {
		t.Fatal(code, body)
	}
	if code, body := request("GET", "/devices", "", ""); code != 200 || !strings.Contains(body, "LAN host") {
		t.Fatal(code, body)
	}
	for _, test := range []struct {
		path, body, token string
		status            int
	}{{"/api/devices/logical/nmap", `{"authorized":true}`, "", 403}, {"/api/devices/logical/nmap", `{"authorized":false}`, token, 400}, {"/api/devices/logical/nmap", `{"authorized":true,"target":"198.51.100.20"}`, token, 400}, {"/api/devices/missing/nmap", `{"authorized":true}`, token, 404}, {"/api/devices/logical/nmap", `{"authorized":true,"profile":"--script=vuln"}`, token, 400}} {
		if code, _ := request("POST", test.path, test.body, test.token); code != test.status {
			t.Fatal(test, code)
		}
	}
	code, body = request("POST", "/api/devices/logical/nmap", `{"authorized":true}`, token)
	if code != 202 {
		t.Fatal(code, body)
	}
	var job scanner.NmapJob
	if err := json.Unmarshal([]byte(body), &job); err != nil {
		t.Fatal(err)
	}
	if code, _ := request("POST", "/api/scans", `{"authorized":true}`, token); code != 409 {
		t.Fatal("network slot not shared", code)
	}
	close(provider.release)
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		code, body = request("GET", "/api/nmap/"+job.ID, "", "")
		if code != 200 || json.Unmarshal([]byte(body), &job) != nil {
			t.Fatal(code, body)
		}
		if job.Status == "completed" {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("Nmap job timeout")
		case <-time.After(time.Millisecond):
		}
	}
	code, body = request("GET", "/devices", "", "")
	if code != 200 || !strings.Contains(body, "TCP ports") || strings.Contains(body, "<script>unsafe</script>") || !strings.Contains(body, "&lt;script&gt;") {
		t.Fatal("unsafe or missing TCP evidence", code, body)
	}
	if code, body := request("GET", "/api/hosts/"+inventory.HostID("192.0.2.20")+"/services", "", ""); code != 200 || !strings.Contains(body, "catalog_reviewed") || !strings.Contains(body, `"number":80`) {
		t.Fatal("missing detached service evidence", code, body)
	}
	for _, test := range []struct {
		body, token string
		status      int
	}{{`{"authorized":true,"port":445}`, "", 403}, {`{"authorized":false,"port":445}`, token, 400}, {`{"authorized":true,"port":80}`, token, 400}, {`{"authorized":true,"port":445,"password":"forbidden"}`, token, 400}, {`{"authorized":true,"port":445}`, token, 400}} {
		if code, body := request("POST", "/api/hosts/"+inventory.HostID("192.0.2.20")+"/shares", test.body, test.token); code != test.status {
			t.Fatal("unsafe share request accepted", test, code, body)
		}
	}
	if code, _ := request("GET", "/api/tools", "", ""); code != 200 {
		t.Fatal(code)
	}
}
