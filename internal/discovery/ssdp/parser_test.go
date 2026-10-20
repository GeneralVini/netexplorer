package ssdp

import (
	"os"
	"strings"
	"testing"
)

func TestParseFixture(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/ssdp-responses.txt")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Location != "http://192.0.2.10:8200/rootDesc.xml" || got.USN != "uuid:fixture-server::upnp:rootdevice" || got.ST != "upnp:rootdevice" || got.CacheControl != "max-age=1800" || !got.EXT || got.Server == "" {
		t.Fatalf("unexpected response: %+v", got)
	}
}

func TestParseInvalid(t *testing.T) {
	valid := "HTTP/1.1 200 OK\r\nLOCATION: http://192.0.2.1/root.xml\r\nUSN: uuid:test\r\nST: ssdp:all\r\n\r\n"
	for _, data := range []string{"", "garbage\r\n\r\n", strings.Replace(valid, "200 OK", "404 Missing", 1), strings.Replace(valid, "USN: uuid:test\r\n", "", 1), strings.Replace(valid, "USN: uuid:test", "USN: uuid:test\r\nusn: uuid:other", 1), strings.TrimSuffix(valid, "\r\n"), strings.Repeat("x", MaxPacketSize+1)} {
		if _, err := Parse([]byte(data)); err == nil {
			t.Fatalf("accepted invalid response of length %d", len(data))
		}
	}
}
