package upnp

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestParseDescription(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/minidlna-rootdesc.xml")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	d := got.Device
	if d.UDN != "uuid:fixture-server" || d.FriendlyName != "Fixture Media Server" || d.Manufacturer == "" || d.ModelName == "" || d.ModelNumber == "" || d.SerialNumber == "" || d.PresentationURL != "/status" || len(d.Services) != 1 || d.Services[0].ControlURL != "/control" || len(d.Children) != 1 {
		t.Fatalf("%+v", got)
	}
}

func TestRejectUnsafeXML(t *testing.T) {
	valid := "<root><device><UDN>uuid:test</UDN><deviceType>urn:test</deviceType></device></root>"
	for _, data := range []string{"", "<root>", valid + valid, valid + "trailing", strings.Replace(valid, "uuid:test", "", 1), strings.Replace(valid, "<deviceType>urn:test</deviceType>", "", 1), "<!DOCTYPE root [<!ENTITY ext SYSTEM 'file:///etc/passwd'>]>" + valid, strings.Replace(valid, "uuid:test", "&unknown;", 1), strings.Repeat("<a>", 33) + strings.Repeat("</a>", 33), strings.Repeat("x", MaxDocumentSize+1), strings.Replace(valid, "</device>", "<deviceList><device><UDN>uuid:test</UDN><deviceType>urn:child</deviceType></device></deviceList></device>", 1)} {
		if _, err := Parse([]byte(data)); err == nil {
			t.Errorf("accepted unsafe XML length %d", len(data))
		}
	}
}

func TestStructuralLimitsAndDuplicates(t *testing.T) {
	valid := "<root><device><UDN>uuid:test</UDN><deviceType>urn:test</deviceType></device></root>"
	children := ""
	for i := 0; i < 64; i++ {
		children += fmt.Sprintf("<device><UDN>uuid:child-%d</UDN><deviceType>urn:child</deviceType></device>", i)
	}
	services := strings.Repeat("<service><serviceId>id</serviceId><serviceType>urn:service</serviceType></service>", 257)
	for _, data := range []string{
		strings.Replace(valid, "</device>", "<deviceList>"+children+"</deviceList></device>", 1),
		strings.Replace(valid, "</device>", "<serviceList>"+services+"</serviceList></device>", 1),
		strings.Replace(valid, "</UDN>", "</UDN><UDN>uuid:other</UDN>", 1),
		strings.Replace(valid, "</root>", "<device><UDN>uuid:other</UDN><deviceType>urn:other</deviceType></device></root>", 1),
		strings.Replace(valid, "</device>", "<serviceList><service/></serviceList></device>", 1),
	} {
		if _, err := Parse([]byte(data)); err == nil {
			t.Fatal("accepted invalid UPnP structure")
		}
	}
}

func TestDuplicateUDNRecovery(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/duplicate-udn-rootdesc.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(data); err == nil {
		t.Fatal("strict parser accepted duplicate identity")
	}
	description, warnings, err := ParseWithWarnings(data)
	if err != nil || len(warnings) != 1 || !strings.Contains(warnings[0], "fixture-connection") || !strings.Contains(warnings[0], "LANDevice:1") {
		t.Fatalf("warnings=%v err=%v", warnings, err)
	}
	root := description.Device
	if root.FriendlyName != "Fixture Gateway" || len(root.Children) != 1 || len(root.Children[0].Children) != 1 {
		t.Fatal("valid hierarchy lost", root)
	}
	connection := root.Children[0].Children[0]
	if connection.DeviceType != "urn:schemas-upnp-org:device:WANConnectionDevice:2" || len(connection.Services) != 1 {
		t.Fatal("duplicate types were merged", connection)
	}
}

func TestRecoveryStillRejectsUnsafeDescriptions(t *testing.T) {
	valid := "<root><device><UDN>uuid:test</UDN><deviceType>urn:test</deviceType></device></root>"
	duplicate := "<device><UDN>uuid:test</UDN><deviceType>urn:duplicate</deviceType></device>"
	for _, data := range []string{
		"<!DOCTYPE root>" + valid,
		strings.Replace(valid, "uuid:test", "&unknown;", 1),
		strings.Replace(valid, "</UDN>", "</UDN><UDN>uuid:other</UDN>", 1),
		strings.Replace(valid, "</device>", "<deviceList>"+strings.Repeat(duplicate, 64)+"</deviceList></device>", 1),
		strings.Replace(valid, "</device>", "<deviceList>"+strings.Replace(duplicate, "</device>", "<serviceList>"+strings.Repeat("<service><serviceId>id</serviceId><serviceType>urn:service</serviceType></service>", 257)+"</serviceList></device>", 1)+"</deviceList></device>", 1),
		strings.Replace(valid, "</device>", "<deviceList><device><UDN></UDN><deviceType>urn:invalid</deviceType></device></deviceList></device>", 1),
	} {
		if _, _, err := ParseWithWarnings([]byte(data)); err == nil {
			t.Fatal("recovery bypassed input safety limits")
		}
	}
}
