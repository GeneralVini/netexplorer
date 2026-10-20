package web

import (
	"bytes"
	"html/template"
	"strings"
	"testing"
	"time"

	"netexplorer/internal/enrichment/nmap"
	"netexplorer/internal/enrichment/upnp"
	"netexplorer/internal/inventory"
)

func TestInventoryPresentationManufacturerPolicy(t *testing.T) {
	devices := []inventory.Device{
		{ID: "root", UDN: "uuid:root", IP: "192.0.2.1", Attributes: map[string]string{"manufacturer": "Sony Corporation", "friendly_name": "Living room", "device_type": "urn:schemas-upnp-org:device:MediaRenderer:1"}},
		{ID: "child", UDN: "uuid:child", ParentID: "root", IP: "192.0.2.1", Attributes: map[string]string{"device_type": "urn:schemas-upnp-org:device:MediaServer:1"}},
		{ID: "other-ip", ParentID: "root", IP: "192.0.2.2"},
		{ID: "spoof", IP: "192.0.2.3", Attributes: map[string]string{"manufacturer": "Not Sony Corporation", "friendly_name": "Sony TV"}},
		{ID: "missing", IP: "192.0.2.3", Attributes: map[string]string{"friendly_name": "Samsung TV"}},
		{ID: "alias", IP: "192.0.2.4", Attributes: map[string]string{"manufacturer": "TP-Link Technologies Co., Ltd."}},
		{ID: "cycle-a", IP: "192.0.2.5", ParentID: "cycle-b"},
		{ID: "cycle-b", IP: "192.0.2.5", ParentID: "cycle-a"},
	}
	view := inventoryRecords(devices)
	if view.Hosts != 5 || view.Devices != 2 || view.Manufacturers != 3 {
		t.Fatal(view)
	}
	root, child := view.Cards[0], view.Cards[1]
	if root.VendorLogo != "/static/icons/vendor-sony.svg" || root.Kind != "Media renderer" || root.VendorInherited {
		t.Fatal(root)
	}
	if child.VendorLogo != root.VendorLogo || !child.VendorInherited || child.Kind != "Media server" {
		t.Fatal(child)
	}
	for _, index := range []int{2, 3, 4, 6, 7} {
		if view.Cards[index].VendorLogo != "" || view.Cards[index].VendorInherited {
			t.Fatal("unjustified manufacturer match", view.Cards[index])
		}
	}
	if view.Cards[5].VendorLogo != "/static/icons/vendor-tplink.svg" {
		t.Fatal(view.Cards[5])
	}
	if _, ok := devices[1].Attributes["manufacturer"]; ok {
		t.Fatal("display inheritance changed evidence")
	}
}

func TestVisualMetadataIsEscapedAndAssetsAreLocal(t *testing.T) {
	device := inventory.Device{ID: "fixture", IP: "192.0.2.1", Attributes: map[string]string{"manufacturer": `<img src="https://attacker.invalid/logo" onerror="alert(1)">`, "friendly_name": "<script>unsafe</script>", "device_type": "urn:test:device:MediaRenderer:1"}}
	tmpl, err := template.New("devices").Funcs(template.FuncMap{"inventoryView": inventoryView, "serviceName": serviceName, "portPreview": portPreview, "stateIcon": stateIcon, "mediaLink": mediaLink}).Parse(devicesTemplate)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := tmpl.ExecuteTemplate(&output, "devices", map[string]any{"Devices": []inventory.Device{device}}); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	if strings.Contains(html, "<script>unsafe</script>") || strings.Contains(html, `<img src="https://attacker.invalid`) || !strings.Contains(html, "&lt;script&gt;") {
		t.Fatal("LAN metadata became markup", html)
	}
	for path, mime := range publicAssets() {
		if _, err := assets.ReadFile("assets/" + path); err != nil {
			t.Fatal("missing declared asset", path, err)
		}
		if strings.HasSuffix(path, ".svg") && mime != "image/svg+xml" {
			t.Fatal("wrong SVG content type", path)
		}
	}
	for _, private := range []string{"icons/manifest.json", "icons/simple-icons.LICENSE", "icons/simple-icons.DISCLAIMER.md", "../home.go"} {
		if _, allowed := publicAssets()[private]; allowed {
			t.Fatal("private resource exposed", private)
		}
	}
}

func TestInventoryViewsExcludeProvisionalIdentitiesAndClosedPorts(t *testing.T) {
	host := inventory.Host{ID: "host", IP: "192.0.2.20", Ports: []nmap.Port{{Number: 22, Protocol: "tcp", State: "open"}, {Number: 443, Protocol: "tcp", State: "closed"}}}
	view := inventoryView([]inventory.Device{{ID: "logical", UDN: "uuid:fixture", IP: host.IP, Services: []upnp.Service{{ID: "service"}}}, {ID: "provisional", IP: host.IP}}, []inventory.Host{host})
	if view.Devices != 1 || view.Hosts != 1 || view.Services != 2 || view.Cards[0].TCPServices != 1 {
		t.Fatal("view counts confused identities or closed ports", view)
	}
}

func TestPortPreviewIsBoundedAndPrioritizesOpen(t *testing.T) {
	host := inventory.Host{IP: "192.0.2.20"}
	for port := 1; port <= 65535; port++ {
		state := "closed"
		if port == 5357 || port == 65535 {
			state = "open"
		}
		host.Ports = append(host.Ports, nmap.Port{Number: port, Protocol: "tcp", State: state})
	}
	rows := portPreview(host)
	if len(rows) != 4 || rows[0].Number != 5357 || rows[1].Number != 65535 || rows[2].Number != 1 {
		t.Fatal(rows)
	}
	for _, state := range []string{"open", "closed", "filtered", "open|filtered", "unfiltered", "closed|filtered", "future"} {
		if stateIcon(state) == "" {
			t.Fatal(state)
		}
	}
}

func TestWindowsAssessmentRequiresOSServiceEvidence(t *testing.T) {
	hosts := []inventory.Host{
		{ID: "windows", IP: "192.0.2.20", Ports: []nmap.Port{{Number: 135, Product: "Microsoft Windows RPC"}}},
		{ID: "linux-rdp", IP: "192.0.2.21", Ports: []nmap.Port{{Number: 3389, Service: "ms-wbt-server", Product: "xrdp"}}},
		{ID: "unknown", IP: "192.0.2.22", Vendor: "Microsoft"},
		{ID: "imported", IP: "192.0.2.23", WindowsCaption: "Microsoft Windows 11"},
	}
	view := inventoryView(nil, hosts)
	for _, card := range view.Cards {
		want := card.Host.ID == "windows" || card.Host.ID == "imported"
		if card.IsWindows != want {
			t.Fatal(card.Host.ID, card.IsWindows)
		}
	}
}

func TestOperatingSystemEvidenceAndAmbiguousTTL(t *testing.T) {
	cases := []struct {
		host    inventory.Host
		label   string
		windows bool
	}{
		{inventory.Host{TTL: 128}, "Windows?", false},
		{inventory.Host{TTL: 64}, "Unix-like?", false},
		{inventory.Host{TTL: 128, Ports: []nmap.Port{{OSType: "Linux"}}}, "Linux", false},
		{inventory.Host{Ports: []nmap.Port{{OSType: "Windows"}}}, "Windows", true},
		{inventory.Host{Ports: []nmap.Port{{OSType: "Windows"}, {OSType: "Linux"}}}, "OS uncertain", true},
	}
	for _, item := range cases {
		label, source := operatingSystem(item.host)
		if label != item.label || source == "" || windowsEvidence(item.host) != item.windows {
			t.Fatalf("host=%+v label=%q source=%q", item.host, label, source)
		}
	}
}

func TestCardEndpointsOpenObservedServices(t *testing.T) {
	host := inventory.Host{ID: "fixture", IP: "192.0.2.26", EnrichedAt: time.Now(), Ports: []nmap.Port{
		{Number: 80, Protocol: "tcp", State: "open", Service: "http"},
		{Number: 443, Protocol: "tcp", State: "filtered", Service: "https"},
		{Number: 3389, Protocol: "tcp", State: "open", Service: "ms-wbt-server"},
	}}
	tmpl, err := template.New("devices").Funcs(template.FuncMap{"inventoryView": inventoryView, "serviceName": serviceName, "portPreview": portPreview, "stateIcon": stateIcon, "mediaLink": mediaLink}).Parse(devicesTemplate)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := tmpl.ExecuteTemplate(&output, "devices", map[string]any{"Devices": []inventory.Device{}, "Hosts": []inventory.Host{host}}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`href="http://192.0.2.26/" target="_blank" rel="noopener noreferrer"`, `href="https://192.0.2.26/" target="_blank" rel="noopener noreferrer"`, `data-rdp-ip="192.0.2.26"`, `data-rdp-port="3389"`} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing endpoint %s", want)
		}
	}
}

func TestMACVendorPresentation(t *testing.T) {
	host := inventory.Host{ID: "nintendo", IP: "192.0.2.129", MAC: "74:84:69:4c:13:96", Vendor: "Nintendo Co.,Ltd"}
	card := inventoryView(nil, []inventory.Host{host}).Cards[0]
	if card.Vendor != "Nintendo" || card.VendorLogo != "/static/icons/vendor-nintendo.svg" || card.MACLabel != "74:84:69:4C:13:96" || card.MACVendorURL != "https://api.macvendors.com/74:84:69:4C:13:96" {
		t.Fatal(card)
	}
	for _, value := range []string{"02:84:69:4c:13:96", "01:84:69:4c:13:96", "00:00:00:00:00:00", "https://attacker.invalid/", "74:84:69:4c:13:96:00:00"} {
		if _, link := macPresentation(value); link != "" {
			t.Fatalf("unexpected external link for %q: %s", value, link)
		}
	}
	if host.MAC != "74:84:69:4c:13:96" {
		t.Fatal("display changed evidence")
	}
}

func TestPrivateMACDoesNotEraseAdvertisedManufacturer(t *testing.T) {
	host := inventory.Host{ID: "private", IP: "192.0.2.10", MAC: "02:84:69:4c:13:96", Vendor: "Sony Corporation"}
	card := inventoryView(nil, []inventory.Host{host}).Cards[0]
	if !card.MACLocal || card.MACVendorURL != "" || card.Vendor != "Unknown manufacturer" {
		t.Fatal(card)
	}
	device := inventory.Device{ID: "advertised", IP: host.IP, Attributes: map[string]string{"manufacturer": "Sony Corporation"}}
	card = inventoryView([]inventory.Device{device}, []inventory.Host{host}).Cards[0]
	if !card.MACLocal || card.Vendor != "Sony" || card.VendorRegistry {
		t.Fatal(card)
	}
}

func TestAdditionalRegistryAliases(t *testing.T) {
	for name, slug := range map[string]string{"Intel Corporate": "intel", "Liteon Technology Corporation": "liteon", "Intelbras": "intelbras", "SAMSUNG ELECTRO-MECHANICS(THAILAND)": "samsung"} {
		card := inventoryView(nil, []inventory.Host{{ID: "fixture", IP: "192.0.2.22", Vendor: name}}).Cards[0]
		if card.VendorLogo != "/static/icons/vendor-"+slug+".svg" {
			t.Fatal(name, card.VendorLogo)
		}
	}
}

func TestMediaLinkRejectsUntrustedTargets(t *testing.T) {
	for _, raw := range []string{"javascript:alert(1)", "rtsp://example.com/", "rtsp://user:pass@192.0.2.20/", "rtsp://192.0.2.20:65536/", "rtsp://192.0.2.20/?x=1", "rtsp://192.0.2.20/path"} {
		if mediaLink(raw) != "" {
			t.Fatal("unsafe media link accepted", raw)
		}
	}
	if mediaLink("rtsp://192.0.2.20:5000/") == "" {
		t.Fatal("valid RTSP endpoint rejected")
	}
}

func TestInventoryGroupsAndSortsIPsWithoutLosingIdentities(t *testing.T) {
	devices := []inventory.Device{
		{ID: "wan", UDN: "uuid:wan", IP: "192.0.2.254", ParentID: "gateway", Attributes: map[string]string{"device_type": "urn:schemas-upnp-org:device:WANConnectionDevice:1"}},
		{ID: "gateway", UDN: "uuid:gateway", IP: "192.0.2.254", Attributes: map[string]string{"device_type": "urn:schemas-upnp-org:device:InternetGatewayDevice:1"}},
		{ID: "other", UDN: "uuid:other", IP: "192.0.2.20"},
	}
	hosts := []inventory.Host{{ID: "host100", IP: "192.0.2.100"}, {ID: "host3", IP: "192.0.2.3"}}
	view := inventoryView(devices, hosts)
	if len(view.Cards) != 4 || view.Devices != 3 || view.Hosts != 4 {
		t.Fatal(view)
	}
	for i, ip := range []string{"192.0.2.3", "192.0.2.20", "192.0.2.100", "192.0.2.254"} {
		if view.Cards[i].IP != ip {
			t.Fatal("incorrect numeric ordering", view.Cards)
		}
	}
	router := view.Cards[3]
	if router.ID != "gateway" || len(router.Identities) != 2 || router.Kind != "Router" {
		t.Fatal("logical records lost", router)
	}
	reversed := []inventory.Device{devices[2], devices[1], devices[0]}
	again := inventoryView(reversed, hosts)
	for i := range view.Cards {
		if again.Cards[i].ID != view.Cards[i].ID {
			t.Fatal("ordering depends on discovery order")
		}
	}
}
