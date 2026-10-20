// Package upnp parses bounded UPnP descriptions without fetching advertised links.
package upnp

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// MaxDocumentSize limits XML input independently of its HTTP origin.
const MaxDocumentSize = 1 << 20

// Service records an advertised UPnP service. URLs are untrusted metadata only.
type Service struct {
	// Type is the advertised serviceType URN.
	Type string `xml:"serviceType" json:"type"`
	// ID is the advertised serviceId.
	ID string `xml:"serviceId" json:"id"`
	// SCPDURL is the service description reference.
	SCPDURL string `xml:"SCPDURL" json:"scpd_url,omitempty"`
	// ControlURL is the control reference; parsing never invokes it.
	ControlURL string `xml:"controlURL" json:"control_url,omitempty"`
	// EventSubURL is the event subscription reference.
	EventSubURL string `xml:"eventSubURL" json:"event_sub_url,omitempty"`
}

// Device describes one logical UPnP device, including embedded devices.
type Device struct {
	// UDN is the advertised device UUID, used as correlation evidence.
	UDN string `xml:"UDN" json:"udn"`
	// DeviceType is the advertised deviceType URN.
	DeviceType string `xml:"deviceType" json:"device_type"`
	// FriendlyName is the human-readable label; it is not an identity key.
	FriendlyName string `xml:"friendlyName" json:"friendly_name"`
	// Manufacturer is the advertised manufacturer name.
	Manufacturer string `xml:"manufacturer" json:"manufacturer,omitempty"`
	// ManufacturerURL is the untrusted manufacturer link.
	ManufacturerURL string `xml:"manufacturerURL" json:"manufacturer_url,omitempty"`
	// ModelDescription is the advertised model description.
	ModelDescription string `xml:"modelDescription" json:"model_description,omitempty"`
	// ModelName is the advertised model name.
	ModelName string `xml:"modelName" json:"model_name,omitempty"`
	// ModelNumber is the advertised model number.
	ModelNumber string `xml:"modelNumber" json:"model_number,omitempty"`
	// ModelURL is the untrusted model link.
	ModelURL string `xml:"modelURL" json:"model_url,omitempty"`
	// SerialNumber is the optional serial number.
	SerialNumber string `xml:"serialNumber" json:"serial_number,omitempty"`
	// PresentationURL is the untrusted presentation reference.
	PresentationURL string `xml:"presentationURL" json:"presentation_url,omitempty"`
	// Services belong to this logical device, not automatically to its children.
	Services []Service `xml:"serviceList>service" json:"services"`
	// Children retains embedded-device hierarchy.
	Children []Device `xml:"deviceList>device" json:"children,omitempty"`
}

// Description represents a UPnP root document. URLBase is untrusted metadata;
// it never changes the safe HTTP policy or authorizes a second request.
type Description struct {
	// XMLName requires the root element name during decoding.
	XMLName xml.Name `xml:"root" json:"-"`
	// URLBase is the optional reference base advertised by the document.
	URLBase string `xml:"URLBase" json:"url_base,omitempty"`
	// Device is the root logical device.
	Device Device `xml:"device" json:"device"`
}

// Parse validates a single XML root and decodes its UPnP device hierarchy.
// It rejects documents larger than 1 MiB, depth above 32, more than 8192 XML
// elements, directives such as DOCTYPE, unsupported entities, and malformed XML.
// It requires distinct, nonempty UUID UDNs and device types throughout the tree,
// with at most 64 devices and 256 services in total. No URLs are fetched.
func Parse(data []byte) (Description, error) {
	description, err := decode(data)
	if err != nil {
		return Description{}, err
	}
	devices, services := 0, 0
	if err := validateDevice(&description.Device, map[string]bool{}, &devices, &services, false); err != nil {
		return Description{}, err
	}
	return description, nil
}

// ParseWithWarnings tolerates repeated UDN claims by keeping the first device
// and omitting later duplicate branches with explicit warnings. Distinct device
// types never authorize merging a repeated identity. All input branches remain
// subject to XML, identity, and device/service limits before any pruning.
func ParseWithWarnings(data []byte) (Description, []string, error) {
	description, err := decode(data)
	if err != nil {
		return Description{}, nil, err
	}
	devices, services := 0, 0
	if err := validateDevice(&description.Device, map[string]bool{}, &devices, &services, true); err != nil {
		return Description{}, nil, err
	}
	warnings := []string{}
	seen := map[string]bool{strings.ToLower(description.Device.UDN): true}
	pruneDuplicates(&description.Device, "root", seen, &warnings)
	return description, warnings, nil
}

// pruneDuplicates preserves the first occurrence and its hierarchy without
// inventing identities for malformed duplicate branches.
func pruneDuplicates(device *Device, path string, seen map[string]bool, warnings *[]string) {
	children := device.Children[:0]
	for i, child := range device.Children {
		childPath := fmt.Sprintf("%s/deviceList/device[%d]", path, i)
		key := strings.ToLower(child.UDN)
		if seen[key] {
			*warnings = append(*warnings, fmt.Sprintf("duplicate UPnP UDN %s at %s ignored (device type %s)", child.UDN, childPath, child.DeviceType))
			continue
		}
		seen[key] = true
		pruneDuplicates(&child, childPath, seen, warnings)
		children = append(children, child)
	}
	device.Children = children
}

// decode applies XML safety limits before interpreting any device claims.
func decode(data []byte) (Description, error) {
	if len(data) > MaxDocumentSize {
		return Description{}, fmt.Errorf("UPnP XML exceeds size limit")
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	depth, elements, roots := 0, 0, 0
	type element struct {
		name string
		seen map[string]bool
	}
	stack := []element{}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Description{}, fmt.Errorf("UPnP XML: %w", err)
		}
		switch value := token.(type) {
		case xml.StartElement:
			if len(stack) > 0 {
				parent := &stack[len(stack)-1]
				if singletonField(parent.name, value.Name.Local) {
					if parent.seen[value.Name.Local] {
						return Description{}, fmt.Errorf("duplicate UPnP field %s", value.Name.Local)
					}
					parent.seen[value.Name.Local] = true
				}
			}
			stack = append(stack, element{name: value.Name.Local, seen: map[string]bool{}})
			if depth == 0 {
				roots++
			}
			depth++
			elements++
			if depth > 32 || elements > 8192 || roots > 1 {
				return Description{}, fmt.Errorf("UPnP XML structural limit exceeded")
			}
		case xml.EndElement:
			depth--
			stack = stack[:len(stack)-1]
		case xml.Directive:
			return Description{}, fmt.Errorf("XML directives are not allowed")
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(value)) != "" {
				return Description{}, fmt.Errorf("text outside XML root")
			}
		}
	}
	if depth != 0 || roots != 1 {
		return Description{}, fmt.Errorf("incomplete UPnP XML")
	}
	var description Description
	if err := xml.Unmarshal(data, &description); err != nil {
		return Description{}, err
	}
	return description, nil
}

// validateDevice bounds every input branch and validates identity claims.
func validateDevice(device *Device, seen map[string]bool, devices, services *int, allowDuplicates bool) error {
	device.UDN = strings.TrimSpace(device.UDN)
	device.DeviceType = strings.TrimSpace(device.DeviceType)
	key := strings.ToLower(device.UDN)
	if !strings.HasPrefix(key, "uuid:") || len(key) <= 5 || (seen[key] && !allowDuplicates) || device.DeviceType == "" {
		return fmt.Errorf("invalid or duplicate UPnP device identity")
	}
	for i := range device.Services {
		service := &device.Services[i]
		service.ID = strings.TrimSpace(service.ID)
		service.Type = strings.TrimSpace(service.Type)
		if service.ID == "" || service.Type == "" {
			return fmt.Errorf("missing UPnP service identity")
		}
	}
	seen[key] = true
	*devices++
	*services += len(device.Services)
	if *devices > 64 || *services > 256 {
		return fmt.Errorf("UPnP device/service limit exceeded")
	}
	for i := range device.Children {
		if err := validateDevice(&device.Children[i], seen, devices, services, allowDuplicates); err != nil {
			return err
		}
	}
	return nil
}

// singletonField identifies profile fields whose repeated values would be ambiguous.
func singletonField(parent, name string) bool {
	switch parent {
	case "root":
		return name == "device" || name == "URLBase"
	case "device":
		switch name {
		case "UDN", "deviceType", "friendlyName", "manufacturer", "manufacturerURL", "modelDescription", "modelName", "modelNumber", "modelURL", "serialNumber", "presentationURL", "serviceList", "deviceList":
			return true
		}
	case "service":
		switch name {
		case "serviceType", "serviceId", "SCPDURL", "controlURL", "eventSubURL":
			return true
		}
	}
	return false
}
