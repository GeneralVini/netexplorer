# Protocols

Native SSDP and bounded UPnP description fetching/parsing are implemented; UPnP control and the other protocols remain planned.

- SSDP: UPnP discovery, IPv4 multicast 239.255.255.250:1900/UDP.
- UPnP: XML descriptions over HTTP and SOAP services on advertised ports.
- DLNA: media profiles over UPnP, ContentDirectory, and MediaRenderer.
- mDNS/DNS-SD: local announcements and service discovery, 5353/UDP.
- ARP: IPv4/MAC association on the link; neighbor tables also cover IPv6.
- SMB: file sharing, usually 445/TCP.
- NFS: file sharing, usually 2049 and related RPC services.
- WebDAV: HTTP/HTTPS extensions; ports depend on the server.
- Nmap: TCP/UDP probes and service identification according to arguments; the MVP will allow only explicit actions for individual IPs and XML output.

Ports are references, not an automatic scanning list.
