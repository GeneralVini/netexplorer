# Offline MAC identification and registry maintenance

The U/L bit (`firstByte & 0x02`) classifies a locally administered Ethernet MAC. This is not proof of randomization: administrators and virtual interfaces can also assign local addresses. Cards show a lock icon and a tooltip explaining this distinction. Local addresses never receive an OUI-derived vendor or a MacVendors lookup link. UPnP manufacturer announcements and OS/service evidence remain independent.

The application queries IEEE MA-L (24-bit), MA-M (28-bit) and MA-S (36-bit) assignments using the longest matching prefix. An interface registrant is not necessarily the manufacturer of the complete device. Explicit custom entries override IEEE entries. The ARP helper collects IP/MAC data with both vendor inputs set to `/dev/null`; updated databases are parsed by the normal application process, without extending sudo permissions.

## Storage and updates

The default application directory is `/var/lib/netexplorer/vendors`, owned by the existing netexplorer account. `NETEXPLORER_VENDOR_DIR` overrides it for development. The application first loads its own `ieee-oui.txt`, then falls back to standard arp-scan system locations. It also reads `/etc/arp-scan/mac-vendor.txt` and the application's `mac-vendor.txt`; application custom entries take precedence. Custom files are loaded at startup. System files are never overwritten. All files must be regular files and are bounded to 16 MiB.

Open **Vendor database** in the discovery controls. **Update database** starts one background worker, with visible status and errors. It downloads only these fixed HTTPS sources:

- https://standards-oui.ieee.org/oui/oui.csv
- https://standards-oui.ieee.org/oui28/mam.csv
- https://standards-oui.ieee.org/oui36/oui36.csv

No device MAC is sent during registry updates. Redirects are rejected. Each response is limited to 16 MiB and 30 seconds; the complete operation has a 90-second deadline. All three datasets must pass CSV/header, prefix-length, vendor-string and minimum-count checks. Ambiguous duplicate assignments are excluded and counted; excessive conflicts reject the update. The generated arp-scan-compatible TXT is written to a temporary file, synchronized and atomically renamed. Any download or validation failure retains the last active file and immutable lookup snapshot. Discovery continues offline during updates.

**Update automatically every 30 days** is off by default and persists in `settings.json`. While the application is running it checks age hourly, refreshes when older than 30 days, and waits a day after failures. It does not install cron jobs or system timers. Last-attempt metadata and errors are persisted in `status.json`. Missing data is stale. System file modification times are age estimates, not authoritative publication dates. Newly discovered hosts use the new registry; previous inventory evidence is not rewritten retrospectively.

`GET /api/vendors` reports counts, source, file date, last attempt/success and errors. `POST /api/vendors/update` returns 202 after reserving the worker; concurrent updates return 409. `POST /api/vendors/settings` accepts only `{"automatic":true|false}`. Write routes use the existing same-origin/CSRF controls. App shutdown cancels background downloads.

## Complementary identity evidence

Other LAN host discovery also sends a bounded mDNS/DNS-SD query for HTTP, HTTPS, SMB, workstation, device-info, AirPlay, Google Cast and IPP services. The selected interface and source address are used, with unicast responses requested. Collection lasts at most three seconds, accepts at most 256 packets, and retains at most 16 hints per host. Only allowed nonlocal LAN senders on UDP 5353 are accepted; announced IPs cannot expand scan scope. Malformed DNS, oversized records and expired records are ignored.

mDNS names, model and manufacturer TXT hints appear under **Identity and sources** as unverified hints, and are included in Host JSON. Proxy advertisements can refer to other devices, so the application does not convert these hints into verified manufacturer or OS identities. UPnP metadata, MAC registrants, Windows inventory and Nmap service/CPE evidence keep their separate origins. TTL remains a tentative OS-family hint. MacVendors remains an optional manual external lookup for globally administered addresses.

References: [IEEE registration authority](https://standards.ieee.org/products-programs/regauth/), [arp-scan get-oui](https://github.com/royhills/arp-scan/blob/master/get-oui), [RFC 9724](https://datatracker.ietf.org/doc/html/rfc9724), [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762.html).
