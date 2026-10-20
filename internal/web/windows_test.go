package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"netexplorer/internal/discovery/network"
	"netexplorer/internal/enrichment/windows"
	"netexplorer/internal/inventory"
	"netexplorer/internal/scanner"
)

func TestWindowsHTTPImportProtectionAndScope(t *testing.T) {
	selected := network.Interface{Name: "fixture0", Up: true, Multicast: true, IPv4: []string{"192.0.2.10/24"}}
	hostID := inventory.HostID("192.0.2.20")
	manager := scanner.NewManager(context.Background(), func(context.Context, network.Interface, time.Duration, bool, func(string, any), func([]inventory.Device)) (scanner.Report, error) {
		return scanner.Report{Hosts: []inventory.Host{{ID: hostID, IP: "192.0.2.20"}}}, nil
	})
	defer manager.Close()
	scan, err := manager.Start(selected, time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(time.Second); ; {
		state, _ := manager.State(scan)
		if state.Status != "running" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fixture timeout")
		}
		time.Sleep(time.Millisecond)
	}
	router := Router("fixture", func() ([]network.Interface, error) { return []network.Interface{selected}, nil }, Options{Manager: manager, Listen: "127.0.0.1:8080"})
	request := func(method, path, body, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("Origin", "http://127.0.0.1:8080")
		req.Header.Set("X-CSRF-Token", token)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	home := request("GET", "/", "", "")
	token := regexp.MustCompile(`name="csrf-token" content="([a-f0-9]+)"`).FindStringSubmatch(home.Body.String())[1]
	s := windows.Snapshot{SchemaVersion: 1, CollectedAt: time.Now().UTC(), Addresses: []string{"192.0.2.20"}, Caption: "Windows 10", Version: "10.0.19045", Build: "19045", ProductType: 1, Spooler: "unknown"}
	body, _ := json.Marshal(s)
	path := "/api/hosts/" + hostID + "/windows"
	if r := request("POST", path, string(body), ""); r.Code != http.StatusForbidden {
		t.Fatal(r.Code, r.Body)
	}
	if r := request("POST", path, string(body), token); r.Code != http.StatusOK {
		t.Fatal(r.Code, r.Body)
	}
	if r := request("GET", path, "", ""); r.Code != http.StatusOK || (!strings.Contains(r.Body.String(), "CVE-2019-0708") || !strings.Contains(r.Body.String(), `"ssh_ready":false`)) {
		t.Fatal(r.Code, r.Body)
	}
	sshPath := path + "/ssh"
	if r := request("POST", sshPath, `{"authorized":true,"user":"Administrator"}`, ""); r.Code != http.StatusForbidden {
		t.Fatal(r.Code, r.Body)
	}
	for _, body := range []string{`{"authorized":false,"user":"Administrator"}`, `{"authorized":true,"user":"Administrator","password":""}`, `{"authorized":true,"user":"-oProxyCommand=evil"}`, `{"authorized":true,"user":"Administrator","command":"whoami"}`, `{"authorized":true,"user":"Administrator"}`} {
		if r := request("POST", sshPath, body, token); r.Code != http.StatusBadRequest {
			t.Fatal(r.Code, r.Body)
		}
	}
	s.Addresses = []string{"192.0.2.21"}
	body, _ = json.Marshal(s)
	if r := request("POST", path, string(body), token); r.Code != http.StatusBadRequest {
		t.Fatal(r.Code, r.Body)
	}
	if r := request("POST", "/api/hosts/unknown/windows", string(body), token); r.Code != http.StatusNotFound {
		t.Fatal(r.Code, r.Body)
	}
	if r := request("GET", "/api/windows/collector", "", ""); r.Code != http.StatusOK || !strings.Contains(r.Body.String(), "CreateNew") {
		t.Fatal(r.Code, r.Body)
	}
}
