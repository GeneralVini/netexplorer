// Package ssdp discovers and parses SSDP announcements on a selected IPv4 LAN.
// Advertised URLs remain untrusted evidence and are never fetched by this package.
package ssdp

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// MaxPacketSize bounds the accepted SSDP datagram size in bytes.
const MaxPacketSize = 16 * 1024

// Response contains one SSDP announcement rather than a merged physical device.
// Parse fills header fields; discovery supplies the source IP and observation time.
type Response struct {
	// IP is the UDP source address; it does not prove device identity.
	IP string `json:"ip"`
	// Location is the advertised description URL and requires validation before use.
	Location string `json:"location"`
	// USN is the advertised unique service name.
	USN string `json:"usn"`
	// ST is the advertised search target, such as a device or service type.
	ST string `json:"st"`
	// Server is the optional advertised server identification string.
	Server string `json:"server,omitempty"`
	// CacheControl preserves the optional cache policy without interpreting its lifetime.
	CacheControl string `json:"cache_control,omitempty"`
	// EXT reports presence of the EXT header, including an empty header value.
	EXT bool `json:"ext"`
	// SeenAt is the UTC observation time, or zero when only parsed.
	SeenAt time.Time `json:"seen_at"`
}

// Parse reads a complete HTTP-like SSDP response no larger than MaxPacketSize.
// It requires status 200 and exactly one nonempty LOCATION, USN, and ST header.
// Header names are case-insensitive. Malformed or ambiguous responses return an
// error. IP and SeenAt remain unset; LOCATION is not validated or fetched.
func Parse(data []byte) (Response, error) {
	if len(data) > MaxPacketSize {
		return Response{}, fmt.Errorf("SSDP datagram exceeds %d bytes", MaxPacketSize)
	}
	if !bytes.HasSuffix(data, []byte("\r\n\r\n")) && !bytes.HasSuffix(data, []byte("\n\n")) {
		return Response{}, fmt.Errorf("incomplete SSDP headers")
	}
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), nil)
	if err != nil {
		return Response{}, fmt.Errorf("parse SSDP: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Response{}, fmt.Errorf("unexpected SSDP status %d", response.StatusCode)
	}
	// Ambiguous identity headers must not silently overwrite evidence.
	for _, name := range []string{"Location", "USN", "ST"} {
		if len(response.Header.Values(name)) != 1 || strings.TrimSpace(response.Header.Get(name)) == "" {
			return Response{}, fmt.Errorf("missing or duplicate SSDP %s", name)
		}
	}
	_, ext := response.Header["Ext"]
	return Response{Location: strings.TrimSpace(response.Header.Get("Location")), USN: strings.TrimSpace(response.Header.Get("USN")), ST: strings.TrimSpace(response.Header.Get("ST")), Server: response.Header.Get("Server"), CacheControl: response.Header.Get("Cache-Control"), EXT: ext}, nil
}
