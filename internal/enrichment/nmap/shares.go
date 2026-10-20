package nmap

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"time"

	"netexplorer/internal/discovery/network"
)

// Share describes a publicly listed disk share without accessing its contents.
type Share struct {
	// Name is the server-announced share name.
	Name string `json:"name"`
	// Comment is optional server-announced metadata.
	Comment string `json:"comment,omitempty"`
}

// ListShares requests only anonymous share-list metadata from one validated peer.
// It never connects to disk shares, guesses names, supplies passwords or reads files.
func (p *Provider) ListShares(ctx context.Context, selected network.Interface, target string, port int) ([]Share, error) {
	s, err := p.scopeFor(selected)
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(target)
	if err != nil || !s.allows(ip) || (port != 445 && port != 139) {
		return nil, fmt.Errorf("invalid SMB peer or port")
	}
	if _, err := p.lookup("smbclient"); err != nil {
		return nil, fmt.Errorf("smbclient is unavailable on PATH")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// #nosec G204 -- Fixed smbclient executable and metadata-only flags; validated literal remote IP and fixed SMB ports, no shell or caller flags.
	command := exec.CommandContext(ctx, "smbclient", "-L", ip.String(), "-I", ip.String(), "-p", fmt.Sprint(port), "-N", "-U", "%", "-g", "-t", "5", "--use-kerberos=off", "--option=client min protocol=SMB2", "--option=interfaces="+s.source.String(), "--option=bind interfaces only=yes")
	command.WaitDelay = 2 * time.Second
	stdout, stderr := &boundedBuffer{limit: 256 << 10}, &boundedBuffer{limit: 16 << 10}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("anonymous share listing unavailable; the server may require authentication")
	}
	if stdout.overflow || stderr.overflow {
		return nil, fmt.Errorf("share listing exceeds size limit")
	}
	return parseShares(stdout.String()), nil
}

// parseShares accepts grepable disk metadata, excluding hidden/admin shares.
func parseShares(output string) []Share {
	result := []Share{}
	seen := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.SplitN(strings.TrimSpace(line), "|", 3)
		if len(fields) != 3 || fields[0] != "Disk" || fields[1] == "" || len(fields[1]) > 255 || strings.HasSuffix(fields[1], "$") || seen[fields[1]] {
			continue
		}
		seen[fields[1]] = true
		result = append(result, Share{Name: fields[1], Comment: fields[2]})
		if len(result) == 256 {
			break
		}
	}
	return result
}
