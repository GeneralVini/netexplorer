package web

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"netexplorer/internal/discovery/network"
	"netexplorer/internal/enrichment/nmap"
	"netexplorer/internal/inventory"
	"netexplorer/internal/scanner"
)

func TestSnapshotsRemainReadOnlyAndRoundTrip(t *testing.T) {
	manager := scanner.NewManager(context.Background(), nil)
	defer manager.Close()
	h := newScanHTTP(Options{Manager: manager, Listen: "127.0.0.1:8080"}, func() ([]network.Interface, error) { return nil, nil })
	router := gin.New()
	router.Use(h.protect)
	h.installSnapshots(router)
	router.POST("/api/scans", func(c *gin.Context) { t.Error("imported inventory reached network action"); c.Status(200) })
	host := inventory.Host{ID: "fixture", IP: "192.0.2.22", MAC: "74:84:69:4c:13:96", Vendor: "Nintendo Co.,Ltd", Ports: []nmap.Port{{Number: 80, Protocol: "tcp", State: "open"}}}
	value := snapshot{Version: 1, SavedAt: time.Now().UTC(), Scan: scanner.State{ID: "original", Status: "completed", Report: scanner.Report{Hosts: []inventory.Host{host}, Devices: []inventory.Device{}}}}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body string, authorized bool) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, strings.NewReader(body))
		if authorized {
			req.Header.Set("X-CSRF-Token", h.token)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	if rec := request("POST", "/api/snapshots/load", string(data), false); rec.Code != 403 {
		t.Fatal(rec.Code)
	}
	if rec := request("POST", "/api/snapshots/load", string(data), true); rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	if !h.offline() || len(h.hosts()) != 1 {
		t.Fatal("snapshot not visible")
	}
	if _, ok := manager.Latest(); ok {
		t.Fatal("snapshot replaced live manager inventory")
	}
	if rec := request("POST", "/api/scans", "{}", true); rec.Code != 409 {
		t.Fatal(rec.Code)
	}
	rec := request("GET", "/api/snapshots/export", "", false)
	var exported snapshot
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &exported) != nil || exported.Scan.Report.Hosts[0].MAC != host.MAC {
		t.Fatal(rec.Code, rec.Body.String())
	}
	for _, body := range []string{`{"version":2}`, string(data) + ` {}`, `{"version":1,"unexpected":true}`} {
		if rec := request("POST", "/api/snapshots/load", body, true); rec.Code != 400 {
			t.Fatal(body, rec.Code)
		}
	}
	if rec := request("POST", "/api/snapshots/live", "", true); rec.Code != 204 || h.offline() {
		t.Fatal(rec.Code)
	}
}

func TestSnapshotEndpointValidation(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1", "192.0.2.22/path", "224.0.0.1"} {
		value := snapshot{Version: 1, Scan: scanner.State{Report: scanner.Report{Hosts: []inventory.Host{{ID: "fixture", IP: ip}}}}}
		if validateSnapshot(value) == nil {
			t.Fatal(ip)
		}
	}
}
