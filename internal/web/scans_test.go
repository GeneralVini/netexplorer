package web

import (
	"context"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"netexplorer/internal/discovery/network"
	"netexplorer/internal/inventory"
	"netexplorer/internal/scanner"
)

func TestBrowserScanLifecycle(t *testing.T) {
	release := make(chan struct{})
	manager := scanner.NewManager(context.Background(), func(ctx context.Context, _ network.Interface, _ time.Duration, _ bool, emit func(string, any), update func([]inventory.Device)) (scanner.Report, error) {
		devices := []inventory.Device{{ID: "fixture", UDN: "uuid:fixture", Attributes: map[string]string{"friendly_name": "<script>unsafe</script>"}}}
		update(devices)
		emit("host-found", map[string]string{"ip": "192.0.2.20"})
		select {
		case <-release:
		case <-ctx.Done():
			return scanner.Report{Devices: devices}, ctx.Err()
		}
		return scanner.Report{Devices: devices, Warnings: []scanner.Warning{}}, nil
	})
	defer manager.Close()
	server := httptest.NewUnstartedServer(nil)
	server.Config.Handler = Router("fixture", func() ([]network.Interface, error) {
		return []network.Interface{{Name: "fixture", Up: true, Multicast: true, IPv4: []string{"192.0.2.10/24"}}}, nil
	}, Options{Manager: manager, Listen: server.Listener.Addr().String(), DefaultInterface: "fixture"})
	server.Start()
	defer server.Close()
	client := server.Client()
	client.Timeout = 3 * time.Second
	request := func(method, path, body, token, origin, host string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-CSRF-Token", token)
		req.Header.Set("Content-Type", "application/json")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if host != "" {
			req.Host = host
		}
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
	code, home := request("GET", "/", "", "", "", "")
	if code != 200 {
		t.Fatal(code, home)
	}
	for _, path := range []string{"/api/vendors/update", "/api/vendors/settings"} {
		if code, _ := request("POST", path, `{"automatic":true}`, "", "", ""); code != http.StatusForbidden {
			t.Fatalf("unprotected vendor write %s: %d", path, code)
		}
	}
	matches := regexp.MustCompile(`name="csrf-token" content="([a-f0-9]+)"`).FindStringSubmatch(home)
	if len(matches) != 2 {
		t.Fatal("missing CSRF token")
	}
	token := matches[1]
	body := `{"interface":"fixture","seconds":1,"enrich":true,"authorized":true}`
	for _, test := range []struct{ token, origin, host string }{{"", "", ""}, {token, "https://attacker.invalid", ""}, {token, "", "attacker.invalid:8080"}} {
		if code, _ := request("POST", "/api/scans", body, test.token, test.origin, test.host); code != 403 {
			t.Fatal("untrusted request accepted", code)
		}
	}
	for _, bad := range []string{`{"authorized":false}`, `{"authorized":true,"seconds":61}`, body + `{}`, `{"authorized":true,"continuous":true,"interval_seconds":9}`, `{"authorized":true,"continuous":true,"interval_seconds":3601}`, `{"authorized":true,"auto_tcp":true,"interval_seconds":9223372036854775807}`, `{"authorized":true,"unexpected":true}`} {
		if code, _ := request("POST", "/api/scans", bad, token, server.URL, ""); code != 400 {
			t.Fatal("invalid body accepted", code)
		}
	}
	code, result := request("POST", "/api/scans", body, token, server.URL, "")
	if code != 202 {
		t.Fatal(code, result)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(result), &created); err != nil {
		t.Fatal(err)
	}
	if code, _ := request("POST", "/api/scans", body, token, server.URL, ""); code != 409 {
		t.Fatal("parallel scan accepted", code)
	}
	close(release)
	// Reading a real HTTP stream exercises flushing and ResponseController deadlines.
	code, events := request("GET", "/api/scans/"+created.ID+"/events", "", "", "", "")
	if code != 200 || !strings.Contains(events, "event: scan-complete") || !strings.Contains(events, "event: device-found") {
		t.Fatal(code, events)
	}
	code, devices := request("GET", "/devices", "", "", "", "")
	if code != 200 || strings.Contains(devices, "<script>unsafe</script>") || !strings.Contains(devices, "&lt;script&gt;") {
		t.Fatal("unsafe device template", code, devices)
	}
	if code, _ := request("GET", "/api/devices/fixture", "", "", "", ""); code != 200 {
		t.Fatal(code)
	}
	if code, _ := request("GET", "/api/devices/missing", "", "", "", ""); code != 404 {
		t.Fatal(code)
	}
	for _, asset := range []string{"bootstrap.min.css", "htmx.min.js", "app.js", "app.css", "favicon.svg", "icons/devices.svg", "icons/vendor-sony.svg"} {
		if code, _ := request("GET", "/static/"+asset, "", "", "", ""); code != 200 {
			t.Fatal("missing embedded asset", asset)
		}
	}
	for _, path := range []string{"/static/missing", "/static/icons/manifest.json", "/static/icons/simple-icons.LICENSE"} {
		if code, _ := request("GET", path, "", "", "", ""); code != 404 {
			t.Fatal(path, code)
		}
	}
	req, _ := http.NewRequest("GET", server.URL+"/api/scans/"+created.ID+"/events", nil)
	req.Header.Set("Last-Event-ID", "invalid")
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 400 {
		t.Fatal("invalid cursor accepted")
	}
}

func TestEventStreamAdmission(t *testing.T) {
	manager := scanner.NewManager(context.Background(), func(ctx context.Context, _ network.Interface, _ time.Duration, _ bool, _ func(string, any), _ func([]inventory.Device)) (scanner.Report, error) {
		<-ctx.Done()
		return scanner.Report{}, ctx.Err()
	})
	defer manager.Close()
	selected := network.Interface{Name: "fixture", Up: true, Multicast: true, IPv4: []string{"192.0.2.10/24"}}
	id, err := manager.Start(selected, time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	handler := newScanHTTP(Options{Manager: manager, Listen: "127.0.0.1:8080"}, nil)
	for i := 0; i < cap(handler.streams); i++ {
		handler.streams <- struct{}{}
	}
	response := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(response)
	c.Request = httptest.NewRequest("GET", "/api/scans/"+id+"/events", nil)
	c.Params = gin.Params{{Key: "id", Value: id}}
	handler.events(c)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatal("connection limit ignored", response.Code)
	}
}
