package tools

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ARPInfo records startup availability and installation guidance without network probing.
type ARPInfo struct {
	// Mode records direct execution or explicit restricted-helper use.
	Mode string `json:"mode"`
	// Available reports executable presence, not raw-socket permission.
	Available bool `json:"available"`
	// Version contains bounded version output, when the version probe succeeds.
	Version string `json:"version,omitempty"`
	// Status distinguishes absence, a failed version probe and untested permissions.
	Status string `json:"status"`
	// Install is a platform-specific instruction, never executed automatically.
	Install string `json:"install,omitempty"`
}

// InspectARP checks the optional tool once at startup; it never scans or elevates privileges.
func InspectARP(ctx context.Context) ARPInfo {
	data, _ := os.ReadFile("/etc/os-release")
	mode := "direct"
	if os.Getenv("NETEXPLORER_ARP_SUDO_HELPER") == "1" && os.Geteuid() != 0 {
		mode = "restricted sudo helper"
	}
	info := ARPInfo{Mode: mode, Status: "not installed", Install: arpInstall(runtime.GOOS, string(data))}
	_, err := exec.LookPath("arp-scan")
	if err != nil {
		return info
	}
	info.Available = true
	info.Status = "installed; raw-socket permission checked when discovery runs"
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	// Fixed executable and version flag; no network target or user arguments.
	command := exec.CommandContext(ctx, "arp-scan", "--version")
	command.WaitDelay = time.Second
	output := &versionOutput{}
	command.Stdout = output
	command.Stderr = output
	if command.Run() != nil {
		info.Status = "installed; version check failed"
		return info
	}
	info.Version = strings.SplitN(strings.TrimSpace(output.text), "\n", 2)[0]
	return info
}

// versionOutput bounds stored bytes while draining subprocess output.
type versionOutput struct{ text string }

func (out *versionOutput) Write(data []byte) (int, error) {
	n := len(data)
	room := 4096 - len(out.text)
	if room > 0 {
		if len(data) > room {
			data = data[:room]
		}
		out.text += string(data)
	}
	return n, nil
}

// arpInstall maps trusted OS identities to display-only installation instructions.
func arpInstall(goos, release string) string {
	if goos == "darwin" {
		return "brew install arp-scan"
	}
	if goos == "windows" {
		return "arp-scan has no native Windows support. Use Nmap; WSL must have direct LAN access to perform ARP discovery."
	}
	if goos != "linux" {
		return "Install arp-scan using your operating system package manager: https://github.com/royhills/arp-scan"
	}
	values := map[string]string{}
	for _, line := range strings.Split(release, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok && (key == "ID" || key == "ID_LIKE") {
			values[key] = strings.Trim(value, "\"'")
		}
	}
	for _, id := range append([]string{values["ID"]}, strings.Fields(values["ID_LIKE"])...) {
		switch id {
		case "ubuntu", "debian", "linuxmint", "kali", "pop":
			return "sudo apt update && sudo apt install arp-scan"
		case "fedora", "rhel", "centos", "rocky", "almalinux":
			return "sudo dnf install arp-scan (an additional repository may be required)"
		case "arch", "manjaro", "endeavouros":
			return "sudo pacman -S arp-scan"
		case "opensuse", "opensuse-tumbleweed", "opensuse-leap", "suse":
			return "sudo zypper install arp-scan"
		case "alpine":
			return "sudo apk add arp-scan"
		}
	}
	return "Install arp-scan with your distribution package manager: https://github.com/royhills/arp-scan"
}
