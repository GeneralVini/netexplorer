package network

import (
	"strings"
	"testing"
)

func TestSelect(t *testing.T) {
	items := []Interface{{Name: "lo", Up: true, Loopback: true, IPv4: []string{"127.0.0.1/8"}}, {Name: "first", Up: true, Multicast: true, IPv4: []string{"192.0.2.1/24"}}, {Name: "route", Up: true, IPv4: []string{"198.51.100.1/24"}}, {Name: "down", IPv4: []string{"203.0.113.1/24"}}}
	for _, tc := range []struct{ request, preferred, want string }{{"", "route", "route"}, {"first", "route", "first"}, {"", "missing", "first"}} {
		got, err := Select(items, tc.request, tc.preferred)
		if err != nil || got.Name != tc.want {
			t.Fatalf("selection: %+v %v", got, err)
		}
	}
	for _, name := range []string{"lo", "down", "missing"} {
		if _, err := Select(items, name, ""); err == nil {
			t.Fatalf("accepted %s", name)
		}
	}
	if _, err := Select(nil, "", ""); err == nil {
		t.Fatal("accepted empty interfaces")
	}
}
func TestParseRoutes(t *testing.T) {
	routes := "Iface Destination Gateway Flags RefCnt Use Metric Mask\neth1 00000000 0102A8C0 0003 0 0 100 00000000\neth0 00000000 0100000A 0003 0 0 10 00000000\nbad 00000000 garbage 0003 0 0 0 00000000\n"
	name, gateway := ParseRoutes(strings.NewReader(routes))
	if name != "eth0" || gateway != "10.0.0.1" {
		t.Fatalf("%s %s", name, gateway)
	}
	name, gateway = ParseRoutes(strings.NewReader("invalid"))
	if name != "" || gateway != "" {
		t.Fatal("accepted invalid route")
	}
}
