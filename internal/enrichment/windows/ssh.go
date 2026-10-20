package windows

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"netexplorer/internal/discovery/network"
)

var userPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidateSSHUser permits a local account name, never an option or remote command.
func ValidateSSHUser(user string) error {
	if !userPattern.MatchString(user) {
		return fmt.Errorf("use a local Windows account name of 1–64 letters, digits, dots, underscores or hyphens")
	}
	return nil
}

// CollectSSH runs the fixed read-only collector on one known peer using existing keys.
// Host keys must already be trusted. Passwords, interactive prompts and forwarding are disabled.
func CollectSSH(ctx context.Context, selected network.Interface, ip, user string) (Snapshot, error) {
	if err := ValidateSSHUser(user); err != nil {
		return Snapshot{}, err
	}
	address, err := netip.ParseAddr(ip)
	if err != nil || !address.Is4() || address.String() != ip || !address.IsGlobalUnicast() || !selected.Up || selected.Loopback || len(selected.IPv4) == 0 {
		return Snapshot{}, fmt.Errorf("invalid remote LAN peer")
	}
	prefix, err := netip.ParsePrefix(selected.IPv4[0])
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 22 || prefix.Bits() > 30 || !prefix.Contains(address) || address == prefix.Masked().Addr() || !prefix.Contains(address.Next()) {
		return Snapshot{}, fmt.Errorf("remote peer must belong to the selected IPv4 /22–/30 LAN")
	}
	interfaces, err := network.List()
	if err != nil {
		return Snapshot{}, fmt.Errorf("unable to enumerate local addresses")
	}
	for _, item := range append(interfaces, selected) {
		for _, value := range item.IPv4 {
			local, e := netip.ParsePrefix(value)
			if e == nil && local.Addr() == address {
				return Snapshot{}, fmt.Errorf("local machine addresses are excluded")
			}
		}
	}
	return runSSH(ctx, ip, user)
}

// runSSH executes only a previously validated peer and fixed collection payload.
func runSSH(ctx context.Context, ip, user string) (Snapshot, error) {
	if _, err := exec.LookPath("ssh"); err != nil {
		return Snapshot{}, fmt.Errorf("openssh client unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	args := sshArgs(ip, user)
	// #nosec G204 -- Fixed ssh executable and command; canonical inventory IPv4, bounded username, fixed options, no user command/path/password. Strict host trust and key-only authentication.
	command := exec.CommandContext(ctx, "ssh", args...)
	command.WaitDelay = 2 * time.Second
	// Send only the fixed collector through stdin; no user text becomes a command.
	command.Stdin = strings.NewReader(sshCollector())
	output := &limitedOutput{limit: 262144}
	errors := &limitedOutput{limit: 16384}
	command.Stdout = output
	command.Stderr = errors
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return Snapshot{}, ctx.Err()
		}
		return Snapshot{}, fmt.Errorf("ssh collection failed: verify trusted host key, existing public-key access and Windows PowerShell availability")
	}
	if output.overflow || errors.overflow {
		return Snapshot{}, fmt.Errorf("ssh collector output limit exceeded")
	}
	return Decode(bytes.NewReader(output.data), ip, time.Now())
}

// sshArgs ignores client configuration to prevent inherited proxies and local commands.
func sshArgs(ip, user string) []string {
	return []string{"-F", "/dev/null", "-T", "-p", "22", "-l", user, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no", "-o", "CheckHostIP=no", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no", "-o", "PreferredAuthentications=publickey", "-o", "NumberOfPasswordPrompts=0", "-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=1", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2", "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "PermitLocalCommand=no", "-o", "ProxyCommand=none", "-o", "ProxyJump=none", ip, "powershell.exe -NoLogo -NoProfile -NonInteractive -Command -"}
}

// sshCollector stages the fixed script in a unique remote temporary folder.
// It executes the file/export flow, returns JSON and removes temporary files.
func sshCollector() string {
	encoded := base64.StdEncoding.EncodeToString([]byte(Collector))
	return "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)\n& {\n" +
		"$ErrorActionPreference = 'Stop'\n" +
		"$work = Join-Path ([IO.Path]::GetTempPath()) ('netexplorer-' + [Guid]::NewGuid().ToString('N'))\n" +
		"$null = [IO.Directory]::CreateDirectory($work)\ntry {\n" +
		"$script = Join-Path $work 'collect-windows.ps1'\n$output = Join-Path $work 'windows-inventory.json'\n" +
		"[IO.File]::WriteAllBytes($script, [Convert]::FromBase64String('" + encoded + "'))\n" +
		"$log = & powershell.exe -NoProfile -NonInteractive -File $script -OutputPath $output 2>&1\n" +
		"if ($LASTEXITCODE -ne 0) { throw 'Windows collector failed.' }\n" +
		"[IO.File]::ReadAllText($output, [Text.Encoding]::UTF8)\n" +
		"} finally { Remove-Item -LiteralPath $work -Recurse -Force }\n}\n\n"
}

// limitedOutput drains excess subprocess output while keeping memory bounded.
type limitedOutput struct {
	data     []byte
	limit    int
	overflow bool
}

func (w *limitedOutput) Write(data []byte) (int, error) {
	count := len(data)
	remaining := w.limit - len(w.data)
	if len(data) > remaining {
		w.overflow = true
		data = data[:remaining]
	}
	w.data = append(w.data, data...)
	return count, nil
}
