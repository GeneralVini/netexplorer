package windows

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"netexplorer/internal/discovery/network"
)

// TestMain substitutes the test executable for SSH; fixtures never contact a LAN.
func TestMain(m *testing.M) {
	if mode := os.Getenv("NETEXPLORER_SSH_TEST_HELPER"); mode != "" {
		if !reflect.DeepEqual(os.Args[1:], sshArgs("192.0.2.20", "Administrator")) {
			os.Exit(3)
		}
		payload, _ := io.ReadAll(os.Stdin)
		if string(payload) != sshCollector() {
			os.Exit(4)
		}
		switch mode {
		case "cancel":
			time.Sleep(time.Minute)
		case "flood":
			_, _ = os.Stdout.Write(bytes.Repeat([]byte("x"), 262145))
		case "error":
			os.Exit(5)
		default:
			data, _ := json.Marshal(fixture(time.Now().UTC()))
			_, _ = os.Stdout.Write(data)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestSSHArgumentsAndScopeRejection(t *testing.T) {
	for _, user := range []string{"Administrator", "Administrador", "local_user"} {
		if err := ValidateSSHUser(user); err != nil {
			t.Fatal(err)
		}
	}
	for _, user := range []string{"", "-oProxyCommand=evil", "user;whoami", "user\ncommand", "user@peer", "domain\\user"} {
		if ValidateSSHUser(user) == nil {
			t.Fatal("accepted unsafe username", user)
		}
	}
	selected := network.Interface{Name: "fixture", Up: true, IPv4: []string{"192.0.2.10/24"}}
	for _, ip := range []string{"127.0.0.1", "192.0.2.0", "192.0.2.255", "192.0.3.20", "peer.invalid", "192.0.2.20;cmd"} {
		if _, err := CollectSSH(context.Background(), selected, ip, "Administrator"); err == nil {
			t.Fatal("accepted peer", ip)
		}
	}
}

func TestSSHControlledProcessBoundsAndCancellation(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(executable, filepath.Join(dir, "ssh")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	for _, mode := range []string{"valid", "flood", "error", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("NETEXPLORER_SSH_TEST_HELPER", mode)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if mode == "cancel" {
				ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()
			}
			snapshot, err := runSSH(ctx, "192.0.2.20", "Administrator")
			if mode == "valid" {
				if err != nil || snapshot.SchemaVersion != 1 {
					t.Fatal(snapshot, err)
				}
			} else if err == nil {
				t.Fatal("accepted failing process", mode)
			}
		})
	}
}

func TestCollectorPowerShellRuntimeWithControlledCommands(t *testing.T) {
	path, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("pwsh unavailable: controlled PowerShell runtime validation skipped")
	}
	mock := `
function Get-CimInstance { param($ClassName,$Filter)
 switch ($ClassName) {
 'Win32_OperatingSystem' { [pscustomobject]@{CSName='fixture';Caption='Microsoft Windows 7';Version='6.1.7601';BuildNumber='7601';ProductType=1;ServicePackMajorVersion=1} }
 'Win32_NetworkAdapterConfiguration' { [pscustomobject]@{IPAddress=@('192.0.2.20')} }
 'Win32_Service' { [pscustomobject]@{State='Running'} }
 }
}
function Get-HotFix { [pscustomobject]@{HotFixID='KB4499164'} }
function Get-ItemProperty { param($Path,$Name,$LiteralPath) throw 'fixture unavailable' }
function Get-MpComputerStatus { throw 'fixture unavailable' }
function Get-BitLockerVolume { param($MountPoint) throw 'fixture unavailable' }
function powershell.exe { param([switch]$NoProfile,[switch]$NonInteractive,$File,$OutputPath) & $File -OutputPath $OutputPath; $global:LASTEXITCODE=0 }
`
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, path, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-")
	command.Stdin = strings.NewReader(mock + sshCollector())
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := Decode(bytes.NewReader(output), "192.0.2.20", time.Now())
	if err != nil {
		t.Fatalf("%v: %s", err, output)
	}
	if snapshot.Spooler != "running" || len(snapshot.Hotfixes) != 1 || len(snapshot.Errors) == 0 {
		t.Fatal(snapshot)
	}
}
