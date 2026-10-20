package mdns

import (
	"golang.org/x/net/dns/dnsmessage"
	"testing"
)

func TestBoundedAdvertisementEvidence(t *testing.T) {
	name := dnsmessage.MustNewName("_device-info._tcp.local.")
	msg := dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.TXTResource{TXT: []string{"model=Fixture", "password=ignored"}}}}}
	packet, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	details := Parse(packet)
	if len(details) != 1 || details[0] != "model=Fixture" {
		t.Fatal(details)
	}
	for _, data := range [][]byte{{}, {0xc0, 0}, make([]byte, 9001), packet[:len(packet)-1]} {
		if len(Parse(data)) != 0 {
			t.Fatal("invalid packet accepted")
		}
	}
	msg.Header.Response = false
	packet, err = msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if len(Parse(packet)) != 0 {
		t.Fatal("query accepted as evidence")
	}
}
