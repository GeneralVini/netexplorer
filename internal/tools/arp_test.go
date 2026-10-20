package tools

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestARPInstallInstructions(t *testing.T) {
	for _, item := range []struct{ goos, release, want string }{
		{"linux", "ID=ubuntu", "apt install"}, {"linux", "ID=custom\nID_LIKE=\"debian ubuntu\"", "apt install"},
		{"linux", "ID=fedora", "dnf install"}, {"linux", "ID=arch", "pacman -S"},
		{"linux", "ID=alpine", "apk add"}, {"linux", "ID=opensuse-tumbleweed", "zypper install"},
		{"darwin", "", "brew install"}, {"windows", "", "no native Windows support"}, {"linux", "ID=unknown", "distribution package manager"},
	} {
		if got := arpInstall(item.goos, item.release); !strings.Contains(got, item.want) {
			t.Fatalf("%+v: %s", item, got)
		}
	}
}
func TestARPMissingIsNotPermissionFailure(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	info := InspectARP(context.Background())
	if info.Available || info.Status != "not installed" || info.Install == "" {
		t.Fatal(info)
	}
}

func TestARPStartupReportsExplicitHelperMode(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv("NETEXPLORER_ARP_SUDO_HELPER", "1")
	info := InspectARP(context.Background())
	expected := "restricted sudo helper"
	if os.Geteuid() == 0 {
		expected = "direct"
	}
	if info.Mode != expected {
		t.Fatalf("mode=%s expected=%s", info.Mode, expected)
	}
}
