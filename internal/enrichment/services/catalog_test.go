package services

import (
	"netexplorer/internal/enrichment/nmap"
	"testing"
)

func TestServiceActionsFollowEvidence(t *testing.T) {
	for _, test := range []struct {
		port        nmap.Port
		url, action string
	}{
		{nmap.Port{Number: 80, State: "filtered", Service: "http"}, "http://192.0.2.20/", "copy"},
		{nmap.Port{Number: 443, State: "open", Service: "http", Tunnel: "ssl"}, "https://192.0.2.20/", "copy"},
		{nmap.Port{Number: 5357, State: "open", Service: "http"}, "http://192.0.2.20:5357/", "copy"},
		{nmap.Port{Number: 80, State: "open", Service: "ssh"}, "", "copy"},
		{nmap.Port{Number: 443, State: "closed", Service: "https"}, "", "copy"},
		{nmap.Port{Number: 445, State: "open", Service: "microsoft-ds?"}, "", "shares"},
		{nmap.Port{Number: 3389, State: "open", Service: "ms-wbt-server"}, "", "rdp"},
		{nmap.Port{Number: 65535, State: "open", Service: "unknown"}, "", "copy"},
	} {
		row := Annotate("192.0.2.20", test.port)
		if row.WebURL != test.url || row.Action != test.action {
			t.Fatal(test, row)
		}
	}
	if row := Annotate("javascript:alert(1)", nmap.Port{Number: 80, State: "open", Service: "http"}); row.WebURL != "" {
		t.Fatal("unvalidated address became URL")
	}
}

func TestReferencesDoNotInferInfectionOrCVEFromPort(t *testing.T) {
	for _, port := range []int{12345, 12346, 27374, 54320, 6200} {
		row := Annotate("192.0.2.20", nmap.Port{Number: port, State: "open"})
		if row.History == nil || len(row.CVEs) != 0 || row.History.Note == "" {
			t.Fatal(row)
		}
	}
	for _, port := range []int{445, 31337, 54321} {
		row := Annotate("192.0.2.20", nmap.Port{Number: port, State: "open"})
		if row.History != nil || len(row.CVEs) != 0 {
			t.Fatal("TCP/UDP or service ambiguity lost", row)
		}
	}
	for _, test := range []struct {
		product, version, state string
		count                   int
	}{
		{"vsftpd", "2.3.4", "open", 1}, {"vsftpd", "2.3.5", "open", 0}, {"vsftpd", "", "open", 0},
		{"Apache httpd", "2.4.49", "open", 2}, {"Apache httpd", "2.4.50", "open", 1}, {"Apache httpd", "2.4.51", "open", 0},
		{"Apache httpd", "2.4.49 vendor-patched", "open", 0}, {"Apache httpd", "2.4.49", "closed", 0},
		{"Microsoft HTTPAPI httpd", "2.0", "open", 0},
	} {
		row := Annotate("192.0.2.20", nmap.Port{Number: 80, State: test.state, Product: test.product, Version: test.version})
		if len(row.CVEs) != test.count {
			t.Fatal(test, row)
		}
	}
}

func TestRTSPEndpoints(t *testing.T) {
	for _, test := range []struct {
		port                 int
		service, state, want string
	}{{554, "rtsp", "open", "rtsp://192.0.2.20/"}, {5000, "rtsp", "open", "rtsp://192.0.2.20:5000/"}, {8554, "unknown", "open", "rtsp://192.0.2.20:8554/"}, {554, "http", "open", ""}, {554, "rtsp", "closed", ""}} {
		row := Annotate("192.0.2.20", nmap.Port{Number: test.port, Protocol: "tcp", Service: test.service, State: test.state})
		if row.MediaURL != test.want {
			t.Fatal(row.MediaURL, test.want)
		}
	}
}
