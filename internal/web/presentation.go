package web

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"unicode"

	"netexplorer/internal/enrichment/macvendor"
	"netexplorer/internal/inventory"
)

// vendor defines a fixed local logo and explicit manufacturer aliases.
// Matching never derives asset paths from LAN-controlled metadata.
type vendor struct {
	name    string
	slug    string
	aliases []string
}

// vendors recognizes explicit manufacturer names rather than friendly-name guesses.
var vendors = []vendor{
	{"LITEON", "liteon", []string{"liteon", "liteon technology corporation", "lite on technology corporation"}},
	{"Intelbras", "intelbras", []string{"intelbras", "intelbras s a", "intelbras industria de telecomunicacao eletronica brasileira"}},
	{"Nintendo", "nintendo", []string{"nintendo", "nintendo co ltd", "nintendo of america inc"}},
	{"Sony", "sony", []string{"sony", "sony corporation", "sony corp"}},
	{"Samsung", "samsung", []string{"samsung", "samsung electronics", "samsung electronics co ltd", "samsung electro mechanics thailand"}},
	{"LG", "lg", []string{"lg", "lg electronics", "lg electronics inc"}},
	{"Apple", "apple", []string{"apple", "apple inc", "apple computer inc"}},
	{"Xiaomi", "xiaomi", []string{"xiaomi", "xiaomi communications co ltd", "xiaomi inc"}},
	{"Huawei", "huawei", []string{"huawei", "huawei technologies", "huawei technologies co ltd"}},
	{"TP-Link", "tplink", []string{"tp link", "tplink", "tp link technologies co ltd", "tp link corporation limited", "tp link systems inc", "tp link systems incorporated"}},
	{"ASUS", "asus", []string{"asus", "asustek", "asustek computer inc"}},
	{"NETGEAR", "netgear", []string{"netgear", "netgear inc"}},
	{"Ubiquiti", "ubiquiti", []string{"ubiquiti", "ubiquiti inc", "ubiquiti networks", "ubiquiti networks inc"}},
	{"Cisco", "cisco", []string{"cisco", "cisco systems", "cisco systems inc"}},
	{"HP", "hp", []string{"hp", "hp inc", "hewlett packard", "hewlett packard company"}},
	{"Lenovo", "lenovo", []string{"lenovo", "lenovo group", "lenovo group limited"}},
	{"Dell", "dell", []string{"dell", "dell inc", "dell technologies"}},
	{"Panasonic", "panasonic", []string{"panasonic", "panasonic corporation", "panasonic entertainment communication co ltd"}},
	{"Synology", "synology", []string{"synology", "synology inc", "synology incorporated"}},
	{"QNAP", "qnap", []string{"qnap", "qnap systems", "qnap systems inc"}},
	{"Nokia", "nokia", []string{"nokia", "nokia corporation", "nokia solutions and networks"}},
	{"Intel", "intel", []string{"intel", "intel corporation", "intel corporate"}},
	{"Google", "google", []string{"google", "google inc", "google llc"}},
}

// deviceCard adds display metadata without changing the inventory or its evidence.
type deviceCard struct {
	// MACLocal identifies local administration without claiming randomization.
	MACLocal bool
	// MACLabel is the uppercase address used in cards and details.
	MACLabel string
	// MACVendorURL is a fixed external lookup URL for a validated global MAC.
	MACVendorURL string
	// OSLabel summarizes OS evidence; tentative TTL guesses remain marked.
	OSLabel string
	// OSSource explains the observation behind OSLabel.
	OSSource string
	// Device preserves the original logical record and its provenance.
	inventory.Device
	// Title is the advertised name or a readable type fallback.
	Title string
	// Vendor is the advertised manufacturer or a recognized canonical label.
	Vendor string
	// VendorLogo is a catalog-controlled local asset path, or empty for fallback.
	VendorLogo string
	// VendorRegistry marks MAC registry evidence rather than an advertised manufacturer.
	VendorRegistry bool
	// VendorInherited identifies presentation inherited from a same-IP ancestor.
	VendorInherited bool
	// Kind is a readable description of the advertised device type.
	Kind string
	// KindIcon is a fixed symbol identifier in the local device sprite.
	KindIcon string
	// KindClass selects a fixed visual color treatment.
	KindClass string
	// Model is the advertised model or a neutral fallback.
	Model string
	// Host keeps host-level Nmap evidence separate from logical services.
	Host inventory.Host
	// TCPServices counts open TCP observations for filtering, excluding closed ports.
	TCPServices int
	// IsWindows requires explicit endpoint or Windows service evidence.
	IsWindows bool
	// Identities retains all original UPnP records grouped at this IP.
	Identities []inventory.Device
	// IsHost marks a host card without a logical UPnP record.
	IsHost bool
}

// inventoryPresentation contains cards and counts for one escaped HTML fragment.
type inventoryPresentation struct {
	// Cards contains one card per IP, sorted by numeric IPv4 address.
	Cards []deviceCard
	// Hosts counts distinct nonempty IP addresses.
	Hosts int
	// Devices counts logical records with a UDN, excluding provisional endpoints.
	Devices int
	// Services counts UPnP entries and TCP observations once per host IP.
	Services int
	// Manufacturers counts distinct known manufacturer labels, including ancestors.
	Manufacturers int
}

// normalizeManufacturer handles punctuation and case without substring guessing.
func normalizeManufacturer(value string) string {
	return strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToLower(r)
		}
		return ' '
	}, value)), " ")
}

// manufacturerFor walks only existing same-IP parent links with bounded cycle checks.
func manufacturerFor(device inventory.Device, byID map[string]inventory.Device) (string, bool) {
	current := device
	seen := map[string]bool{}
	for depth := 0; depth < 64; depth++ {
		if value := strings.TrimSpace(current.Attributes["manufacturer"]); value != "" {
			return value, depth > 0
		}
		if seen[current.ID] {
			break
		}
		seen[current.ID] = true
		parent, ok := byID[current.ParentID]
		if !ok || device.IP == "" || parent.IP != device.IP {
			break
		}
		current = parent
	}
	return "", false
}

// inventoryRecords derives per-record metadata; manufacturer evidence remains untouched.
func inventoryRecords(devices []inventory.Device, hostLists ...[]inventory.Host) inventoryPresentation {
	result := inventoryPresentation{Cards: []deviceCard{}, Devices: 0}
	byID := map[string]inventory.Device{}
	byHost := map[string]inventory.Host{}
	if len(hostLists) > 0 {
		for _, host := range hostLists[0] {
			byHost[host.IP] = host
		}
	}
	hosts, manufacturers := map[string]bool{}, map[string]bool{}
	for _, device := range devices {
		byID[device.ID] = device
	}
	for _, device := range devices {
		if device.UDN != "" {
			result.Devices++
		}
		card := deviceCard{Device: device, Vendor: "Unknown manufacturer", Model: strings.TrimSpace(device.Attributes["model_name"])}
		card.Host = byHost[device.IP]
		if card.Host.ID == "" && device.IP != "" {
			card.Host = inventory.Host{ID: inventory.HostID(device.IP), IP: device.IP, Sources: []string{"ssdp"}}
		}
		card.MACLocal = macvendor.Local(card.Host.MAC)
		card.MACLabel, card.MACVendorURL = macPresentation(card.Host.MAC)
		card.TCPServices = tcpServiceCount(card.Host)
		card.IsWindows = windowsEvidence(card.Host)
		card.OSLabel, card.OSSource = operatingSystem(card.Host)
		card.Kind, card.KindIcon, card.KindClass = deviceKind(device.Attributes["device_type"])
		card.Title = strings.TrimSpace(device.Attributes["friendly_name"])
		if card.Title == "" {
			card.Title = card.Kind
		}
		if card.Model == "" {
			card.Model = "Model not advertised"
		}
		manufacturer, inherited := manufacturerFor(device, byID)
		if manufacturer == "" && !card.MACLocal {
			manufacturer = card.Host.Vendor
			card.VendorRegistry = manufacturer != ""
		}
		if manufacturer != "" {
			card.Vendor, card.VendorInherited = manufacturer, inherited
			normalized := normalizeManufacturer(manufacturer)
			for _, brand := range vendors {
				for _, alias := range brand.aliases {
					if normalized == alias {
						card.Vendor = brand.name
						card.VendorLogo = "/static/icons/vendor-" + brand.slug + ".svg"
						break
					}
				}
				if card.VendorLogo != "" {
					break
				}
			}
			manufacturers[normalizeManufacturer(card.Vendor)] = true
		}
		if device.IP != "" {
			hosts[device.IP] = true
		}
		result.Services += len(device.Services)
		result.Cards = append(result.Cards, card)
	}
	if len(hostLists) > 0 {
		for _, host := range hostLists[0] {
			if host.IP == "" || hosts[host.IP] {
				continue
			}
			vendor := host.Vendor
			if macvendor.Local(host.MAC) {
				vendor = ""
			}
			display := inventory.Device{ID: host.ID, IP: host.IP, Attributes: map[string]string{"manufacturer": vendor, "friendly_name": "LAN host"}}
			card := inventoryRecords([]inventory.Device{display}).Cards[0]
			card.Host = host
			card.MACLocal = macvendor.Local(host.MAC)
			card.MACLabel, card.MACVendorURL = macPresentation(host.MAC)
			card.TCPServices = tcpServiceCount(host)
			card.IsWindows = windowsEvidence(host)
			card.OSLabel, card.OSSource = operatingSystem(host)
			card.IsHost = true
			card.Kind = "LAN host"
			card.KindIcon = "network"
			card.KindClass = "generic"
			card.Model = "Responded to host discovery"
			if host.Vendor != "" {
				manufacturers[normalizeManufacturer(card.Vendor)] = true
			}
			hosts[host.IP] = true
			result.Cards = append(result.Cards, card)
		}
	}
	for _, host := range byHost {
		result.Services += tcpServiceCount(host)
	}
	result.Hosts, result.Manufacturers = len(hosts), len(manufacturers)
	return result
}

// deviceKind uses advertised UPnP types; unknown types keep a neutral network icon.
func deviceKind(value string) (string, string, string) {
	switch serviceName(value) {
	case "InternetGatewayDevice":
		return "Router", "router", "network"
	case "WANDevice":
		return "WAN device", "router", "network"
	case "WANConnectionDevice":
		return "WAN connection", "router", "network"
	case "LANDevice":
		return "LAN device", "network", "network"
	case "WLANAccessPointDevice":
		return "Access point", "wifi", "network"
	case "MediaRenderer":
		return "Media renderer", "display", "media"
	case "MediaServer":
		return "Media server", "server", "storage"
	case "Printer", "PrinterEnhanced":
		return "Printer", "printer", "office"
	case "StorageDevice":
		return "Storage device", "server", "storage"
	default:
		return "Network device", "network", "generic"
	}
}

// serviceName extracts the type label from a UPnP URN without treating URLs as markup.
func serviceName(value string) string {
	parts := strings.Split(value, ":")
	if len(parts) >= 5 && parts[0] == "urn" && (parts[len(parts)-3] == "device" || parts[len(parts)-3] == "service") {
		return parts[len(parts)-2]
	}
	return value
}

// tcpServiceCount reports listening TCP observations rather than closed port results.
func tcpServiceCount(host inventory.Host) int {
	count := 0
	for _, port := range host.Ports {
		if port.State == "open" {
			count++
		}
	}
	return count
}

// windowsEvidence avoids inferring an operating system from vendor or port numbers.
func windowsEvidence(host inventory.Host) bool {
	if strings.Contains(strings.ToLower(host.WindowsCaption), "windows") {
		return true
	}
	for _, port := range host.Ports {
		if strings.EqualFold(port.OSType, "windows") {
			return true
		}
		product := strings.ToLower(port.Product)
		if strings.Contains(product, "microsoft windows") || strings.Contains(product, "microsoft httpapi") || strings.Contains(product, "microsoft terminal services") {
			return true
		}
		for _, cpe := range port.CPEs {
			if strings.HasPrefix(strings.ToLower(cpe), "cpe:/o:microsoft:windows") || strings.HasPrefix(strings.ToLower(cpe), "cpe:2.3:o:microsoft:windows") {
				return true
			}
		}
	}
	return false
}

// operatingSystem prefers endpoint and service evidence over ambiguous TTL hints.
func operatingSystem(host inventory.Host) (string, string) {
	if host.WindowsCaption != "" {
		return host.WindowsCaption, "Collected Windows inventory"
	}
	families := map[string]bool{}
	if windowsEvidence(host) {
		families["Windows"] = true
	}
	for _, port := range host.Ports {
		switch strings.ToLower(port.OSType) {
		case "windows":
			families["Windows"] = true
		case "linux":
			families["Linux"] = true
		case "freebsd":
			families["FreeBSD"] = true
		case "mac os x", "macos":
			families["macOS"] = true
		case "unix":
			families["Unix"] = true
		}
		for _, cpe := range port.CPEs {
			if strings.HasPrefix(cpe, "cpe:/o:linux:") || strings.HasPrefix(cpe, "cpe:2.3:o:linux:") {
				families["Linux"] = true
			}
		}
	}
	if len(families) > 1 {
		return "OS uncertain", "Conflicting service OS evidence; inspect collected results"
	}
	for family := range families {
		return family, "Nmap service or OS CPE evidence; not a verified endpoint inventory"
	}
	if host.TTL >= 120 && host.TTL <= 128 {
		return "Windows?", fmt.Sprintf("TTL %d: weak hint only; defaults can be changed", host.TTL)
	}
	if host.TTL >= 56 && host.TTL <= 64 {
		return "Unix-like?", fmt.Sprintf("TTL %d: shared by Linux, macOS and other systems", host.TTL)
	}
	if host.TTL > 0 {
		return "OS unknown", fmt.Sprintf("Response TTL %d is insufficient to identify the OS", host.TTL)
	}
	return "", ""
}

// macPresentation keeps display separate from evidence and suppresses registry links
// for private, multicast, zero, malformed and non-Ethernet addresses.
func macPresentation(value string) (string, string) {
	label := strings.ToUpper(value)
	mac, err := net.ParseMAC(value)
	if err != nil || len(mac) != 6 || mac[0]&3 != 0 || value == "00:00:00:00:00:00" {
		return label, ""
	}
	return label, "https://api.macvendors.com/" + strings.ToUpper(mac.String())
}

// inventoryView groups IP-level cards without discarding logical inventory or source evidence.
func inventoryView(devices []inventory.Device, hostLists ...[]inventory.Host) inventoryPresentation {
	view := inventoryRecords(devices, hostLists...)
	sort.SliceStable(view.Cards, func(i, j int) bool {
		a, b := view.Cards[i], view.Cards[j]
		x, xe := netip.ParseAddr(a.IP)
		y, ye := netip.ParseAddr(b.IP)
		if xe == nil && ye == nil && x != y {
			return x.Compare(y) < 0
		}
		if a.IP != b.IP {
			return a.IP < b.IP
		}
		ar, br := cardPriority(a), cardPriority(b)
		if ar != br {
			return ar > br
		}
		return a.ID < b.ID
	})
	cards := []deviceCard{}
	indexes := map[string]int{}
	for _, card := range view.Cards {
		key := card.IP
		if key == "" {
			key = "unknown:" + card.ID
		}
		index, ok := indexes[key]
		if !ok {
			indexes[key] = len(cards)
			card.Services = append(card.Services[:0:0], card.Services...)
			if card.UDN != "" {
				card.Identities = []inventory.Device{card.Device}
			}
			cards = append(cards, card)
			continue
		}
		target := &cards[index]
		if card.UDN != "" {
			target.Identities = append(target.Identities, card.Device)
		}
		target.Services = append(target.Services, card.Services...)
	}
	view.Cards = cards
	return view
}

// cardPriority prefers the gateway and then root logical identity over embedded components.
func cardPriority(card deviceCard) int {
	if serviceName(card.Attributes["device_type"]) == "InternetGatewayDevice" {
		return 100
	}
	if card.UDN != "" && card.ParentID == "" {
		return 80
	}
	if card.UDN != "" {
		return 60
	}
	if !card.IsHost {
		return 40
	}
	return 0
}
