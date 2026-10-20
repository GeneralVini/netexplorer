package inventory

import (
	"netexplorer/internal/discovery/ssdp"
	"netexplorer/internal/enrichment/upnp"
	"sync"
	"testing"
	"time"
)

func TestCorrelationAndProvenance(t *testing.T) {
	registry := New()
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	response := ssdp.Response{IP: "192.0.2.10", USN: "uuid:server::upnp:rootdevice", Location: "http://192.0.2.10/root.xml", ST: "upnp:rootdevice", SeenAt: at}
	if err := registry.Observe(response); err != nil {
		t.Fatal(err)
	}
	response.USN = "uuid:server::urn:service"
	response.ST = "urn:service"
	if err := registry.Observe(response); err != nil {
		t.Fatal(err)
	}
	description := upnp.Description{Device: upnp.Device{UDN: "uuid:server", FriendlyName: "Shared name", Manufacturer: "First", DeviceType: "urn:server", Services: []upnp.Service{{ID: "service", Type: "urn:service"}}, Children: []upnp.Device{{UDN: "uuid:child", DeviceType: "urn:child", FriendlyName: "Shared name"}}}}
	if err := registry.Apply(response.IP, response.Location, description, at); err != nil {
		t.Fatal(err)
	}
	description.Device.Manufacturer = "Second"
	if err := registry.Apply(response.IP, response.Location, description, at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	devices := registry.Snapshot()
	if len(devices) != 2 {
		t.Fatal(devices)
	}
	var root Device
	for _, device := range devices {
		if device.UDN == "uuid:server" {
			root = device
		}
	}
	if len(root.USNs) != 2 || root.Attributes["manufacturer"] != "Second" || len(root.Evidence["manufacturer"]) != 2 || len(root.Services) != 1 || !root.FirstSeen.Equal(at) || !root.LastSeen.Equal(at.Add(time.Minute)) {
		t.Fatalf("%+v", root)
	}
	for _, device := range devices {
		if device.UDN == "uuid:child" && device.ParentID != root.ID {
			t.Fatal(device)
		}
	}
	root.Attributes["manufacturer"] = "mutated"
	root.Services[0].ID = "mutated"
	root.Evidence["manufacturer"][0].Value = "mutated"
	for _, device := range registry.Snapshot() {
		if device.UDN == root.UDN && (device.Attributes["manufacturer"] != "Second" || device.Services[0].ID != "service" || device.Evidence["manufacturer"][0].Value != "First") {
			t.Fatal("snapshot aliases registry")
		}
	}
}

func TestProvisionalPromotionAndConcurrentAccess(t *testing.T) {
	registry := New()
	response := ssdp.Response{IP: "192.0.2.10", Location: "http://192.0.2.10/root", USN: "non-uuid"}
	if err := registry.Observe(response); err != nil {
		t.Fatal(err)
	}
	if err := registry.Apply(response.IP, response.Location, upnp.Description{Device: upnp.Device{UDN: "uuid:root"}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(registry.Snapshot()) != 1 {
		t.Fatal("provisional record duplicated")
	}
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			r := response
			r.USN = "uuid:root"
			for j := 0; j < 20; j++ {
				if err := registry.Observe(r); err != nil {
					t.Error(err)
				}
				registry.Snapshot()
			}
		}()
	}
	workers.Wait()
}

func TestOlderMetadataDoesNotOverwriteCurrentProfile(t *testing.T) {
	registry := New()
	at := time.Now().UTC()
	description := upnp.Description{Device: upnp.Device{UDN: "uuid:root", Manufacturer: "Current"}}
	if err := registry.Apply("192.0.2.10", "http://192.0.2.10/root", description, at); err != nil {
		t.Fatal(err)
	}
	description.Device.Manufacturer = "Older"
	if err := registry.Apply("192.0.2.11", "http://192.0.2.11/root", description, at.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	got := registry.Snapshot()[0]
	if got.IP != "192.0.2.10" || got.Attributes["manufacturer"] != "Current" || len(got.Evidence["manufacturer"]) != 2 {
		t.Fatalf("%+v", got)
	}
}

func TestRootDescriptionPreservesKnownParent(t *testing.T) {
	registry := New()
	at := time.Now().UTC()
	child := upnp.Device{UDN: "uuid:child"}
	root := upnp.Description{Device: upnp.Device{UDN: "uuid:root", Children: []upnp.Device{child}}}
	if err := registry.Apply("192.0.2.10", "http://192.0.2.10/root", root, at); err != nil {
		t.Fatal(err)
	}
	if err := registry.Apply("192.0.2.10", "http://192.0.2.10/child", upnp.Description{Device: child}, at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	for _, device := range registry.Snapshot() {
		if device.UDN == "uuid:child" && device.ParentID == "" {
			t.Fatal("embedded relationship erased by standalone description")
		}
	}
}
