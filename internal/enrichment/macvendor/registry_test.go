package macvendor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestLocalAndLongestPrefix(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ieee-oui.txt"), []byte("748469\tBase\n7484694\tMedium\n7484694C1\tSmall\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r := New(dir)
	if r.Lookup("74:84:69:4c:13:96") != "Small" {
		t.Fatal("specific prefix lost")
	}
	r.custom["748469"] = "Custom"
	if r.Lookup("74:84:69:4c:13:96") != "Custom" {
		t.Fatal("custom precedence lost")
	}
	for _, mac := range []string{"02:84:69:4c:13:96", "76:84:69:4c:13:96", "7a:84:69:4c:13:96", "7e:84:69:4c:13:96"} {
		if !Local(mac) || r.Lookup(mac) != "" {
			t.Fatal(mac)
		}
	}
	for _, mac := range []string{"01:84:69:4c:13:96", "00:00:00:00:00:00", "garbage"} {
		if r.Lookup(mac) != "" {
			t.Fatal(mac)
		}
	}
}

func TestUpdatePreservesSnapshotOnFailedSource(t *testing.T) {
	r := New(t.TempDir())
	r.entries = map[string]string{"748469": "Original"}
	calls := 0
	r.client = &http.Client{Transport: transport(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "standards-oui.ieee.org" || req.URL.Scheme != "https" {
			t.Fatal(req.URL)
		}
		calls++
		length := 6
		if calls == 2 {
			length = 7
		}
		if calls == 3 {
			length = 9
		}
		var body strings.Builder
		body.WriteString("Registry,Assignment,Organization Name,Organization Address\n")
		for i := 0; i < 100; i++ {
			fmt.Fprintf(&body, "MA,%0*X,Vendor,Address\n", length, 0x748400+i)
		}
		status := 200
		if calls == 2 {
			status = 503
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body.String())), Header: make(http.Header)}, nil
	})}
	if r.Update(context.Background()) == nil || r.Lookup("74:84:69:4c:13:96") != "Original" || r.Status().Running {
		t.Fatal(r.Status())
	}
	if _, err := os.Stat(filepath.Join(r.dir, "ieee-oui.txt")); !os.IsNotExist(err) {
		t.Fatal("failed update published")
	}
	calls = 2
	r.client.Transport = transport(func(req *http.Request) (*http.Response, error) {
		length := 6
		if strings.Contains(req.URL.Path, "oui28") {
			length = 7
		}
		if strings.Contains(req.URL.Path, "oui36") {
			length = 9
		}
		var body strings.Builder
		body.WriteString("Registry,Assignment,Organization Name,Organization Address\n")
		for i := 0; i < 100; i++ {
			fmt.Fprintf(&body, "MA,%0*X,Vendor,Address\n", length, 0x748400+i)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body.String())), Header: make(http.Header)}, nil
	})
	if err := r.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.Status().Entries != 300 || r.Status().Stale || r.Status().Error != "" {
		t.Fatal(r.Status())
	}
	if New(r.dir).Status().Entries != 300 {
		t.Fatal("file not reloadable")
	}
	if err := r.SetAutomatic(true); err != nil {
		t.Fatal(err)
	}
	if !New(r.dir).Status().Automatic {
		t.Fatal("setting not persisted")
	}
}

func TestInvalidRegistry(t *testing.T) {
	for _, data := range []string{"ZZZZZZ\tVendor", "748469", "748469\tVendor\x00"} {
		if _, err := parseTXT([]byte(data)); err == nil {
			t.Fatal(data)
		}
	}
	r := New(t.TempDir())
	if err := r.begin(); err != nil {
		t.Fatal(err)
	}
	if r.Start(context.Background()) == nil {
		t.Fatal("parallel worker accepted")
	}
}

func TestAmbiguousIEEEAssignmentsAreExcluded(t *testing.T) {
	r := New(t.TempDir())
	r.client = &http.Client{Transport: transport(func(req *http.Request) (*http.Response, error) {
		length := 6
		if strings.Contains(req.URL.Path, "oui28") {
			length = 7
		}
		if strings.Contains(req.URL.Path, "oui36") {
			length = 9
		}
		var body strings.Builder
		body.WriteString("Registry,Assignment,Organization Name,Organization Address\n")
		for i := 0; i < 100; i++ {
			fmt.Fprintf(&body, "MA,%0*X,Vendor,Address\n", length, 0x748400+i)
		}
		if length == 6 {
			body.WriteString("MA,748400,Conflicting registrant,Address\n")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body.String())), Header: make(http.Header)}, nil
	})}
	if err := r.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.Lookup("74:84:00:00:00:01") != "" || r.Status().Conflicts != 1 || r.Status().Entries != 299 {
		t.Fatal(r.Status())
	}
	reloaded := New(r.dir)
	if reloaded.Status().Conflicts != 1 || reloaded.Status().Checked.IsZero() {
		t.Fatal("metadata not restored", reloaded.Status())
	}
}
