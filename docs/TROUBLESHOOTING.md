# Troubleshooting

- Missing Go: check `command -v go` and `go version`; install Go on the system and ensure its bin directory is on PATH.
- Wrong interface/VPN: use --interface; the default route may select a virtual network.
- Missing gateway: current detection depends on Linux /proc/net/route.
- IPv6: the system may have IPv6 addresses, but selection and SSDP currently use IPv4 only.
- Permissions: health and interface enumeration do not require root; future capabilities may have their own requirements.
- Missing Nmap: build and serve still work; doctor reports it as unavailable.
- Port in use: use --listen 127.0.0.1:8081.
- SSDP/multicast/firewall: scan with the correct --interface; check multicast support, Wi-Fi/AP isolation, UDP firewall rules, and UPnP devices. Empty results can mean no announcements. Use at least 5s to avoid stopping before MX 3.
- Enrichment warnings: inspect the report warnings; blocked LOCATION, mismatched UUID, invalid XML, TLS certificate failures, timeouts, and disappearing devices preserve SSDP evidence. URLs must point to the announcing peer, including after DNS resolution and redirects.
- Missing inventory in the browser: start an authorized scan from the page. The latest scan replaces the previous inventory; restarting the server clears sessions. An empty scan does not prove the LAN has no devices.
- HTTP 403: open the configured localhost/listener address and use the current page token for POST requests. Unexpected Host/port and cross-origin POST requests are rejected. A server restart invalidates previous tokens; reload the page.
- HTTP 409: another scan is running. Wait for completion or cancel it before starting another.
- SSE reconnection/reset: refresh scan state after reset; history is bounded to 512 events. Streams expire after two minutes and reconnect. Expired scan IDs return 404.

- Few results: current discovery is SSDP/UPnP, not a complete host census. A router can expose several logical devices on one IP; the page counts unique remote hosts separately. Devices without UPnP, sleeping devices, and multicast-isolated clients may not respond. Local machine addresses are intentionally excluded.
- Duplicate UDN warning: some firmware assigns the same UDN to distinct embedded types. Enrichment keeps the first identity and valid hierarchy, drops the later duplicate branch, and reports the conflict rather than rejecting all router metadata.
