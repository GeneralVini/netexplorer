# Changelog

Format inspired by Keep a Changelog.

## [Unreleased]

### Security

- Updated x/net to 0.56.0 and x/text to 0.39.0 for GO-2026-5942 and GO-2026-5970.

- Fixed subprocess output limits by preventing io.Copy from bypassing the bounded writer through embedded bytes.Buffer methods.

- Added isolated, pinned staticcheck, gosec, and govulncheck tooling, local gates, SARIF, CI, optional CodeQL, and weekly dependency updates.
- Handled SSDP cancellation and HTTP forced-shutdown close errors.
- Updated quic-go from v0.59.0 to v0.59.1 for GO-2026-5676 reported by govulncheck.

### Changed

- Added private/local MAC indicators, offline IEEE MA-L/MA-M/MA-S lookup and application-owned registry updates with optional 30-day refresh.
- Separated privileged ARP collection from vendor lookup and preserved custom registry entries and last-valid data on failed updates.
- Added bounded LAN mDNS identity hints with explicit unverified provenance.

- Added reviewed manual RDP metadata, SMB signing/time and MS17-010 NSE actions with scoped execution, cancellation and reload recovery.
- Retained bounded structured NSE evidence, run versions and script-reported CVEs; separated execution status from assessment and treated SMB connection errors as inconclusive.

- Added fixed common/notable and full TCP 1–65535 inspection profiles with T4 timing, recorded coverage and bounded deadlines.
- Replaced visible port-state text with colored accessible icons; kept cards to four TCP observations and added a searchable 50-row services dialog.
- Added protocol-aware web links, endpoint copying, RDP downloads and explicit anonymous SMB share-metadata listing.
- Added sourced historical TCP associations, conservative potential CVE version matches and manual NVD product/version references.

- Default inventory to one card per IP, preserving embedded identities in an expandable list and the logical-device view.
- Removed duplicate fallback headings, shortened scan consent, and styled close/cancel actions in red.
- Added sticky JSON modal headers, safe syntax highlighting, line numbers, and concise duplicate-identity notes with original technical details.

- Returned to three desktop columns, compact scan labels, and visible discovery-duration controls.
- Added accessible JSON dialogs, visual TCP progress, and service lists without nested scrolling.
- Tuned TCP discovery concurrency/retries/timeouts and explained deadline failures while retaining collected evidence.

- Moved scan controls into the header and enabled four columns on wide screens.
- Distinguished UDN-bearing logical devices from provisional endpoints and included inspected TCP observations in the service view.
- Expanded host discovery with fixed TCP liveness probes and a bounded unprivileged ICMP supplement; retained partial verified evidence on process failure.

- Compact responsive inventory cards, reduced explanatory text, and accessible missing-metadata tooltips.
- Clickable inventory totals, name/IP/model/brand search, manufacturer selection, and pagination retained during live updates.

- Project documentation now uses English.
- Source packages, exported declarations, fields, and internal contracts have Go doc comments.

### Fixed

- Excluded every local IPv4 address from SSDP results and progress before inventory/enrichment.
- Preserved valid UPnP profiles when firmware repeats an embedded UDN, with explicit duplicate-branch warnings and unchanged safety limits.
- Displayed unique remote host counts alongside logical device counts.

- The root route now serves a home page instead of returning 404.

### Added

- Optional browser/CLI discovery of other responding LAN hosts, excluding local IPs and bounded to the selected IPv4 subnet.
- Manual Nmap TCP inspection of known host IPs, retained/cancellable jobs, host APIs, and separate TCP evidence tables.
- Bounded Nmap XML parsing and controlled subprocess, manager, HTTP, and browser verification.

- Visual inventory cards with 20 local manufacturer logos, device-type illustrations, summary counts, and responsive styling.
- Explicit manufacturer alias matching and labeled same-IP parent inheritance in the presentation layer.

- Browser scan controls, cancellation, inventory and scan APIs, live SSE replay, and locally embedded Bootstrap/HTMX assets.
- Bounded scan sessions/event journals, immutable snapshots, CSRF/cross-origin/Host protection, and HTTP/SSE lifecycle tests.

- Optional scan --enrich with safe UPnP description downloads and structured device/warning reports.
- Bounded XML parsing, logical-device registry, embedded parent links, field provenance, and conflict retention.
- SSRF, DNS rebinding, redirect, TLS, XML, inventory, and worker regression tests.

- Native SSDP discovery through the selected interface and a scan command with JSON output.
- SSDP parsing, datagram/response limits, subnet filtering, timeouts, and cancellation.
- An SSDP fixture and loopback UDP tests.
- Go bootstrap, serve/doctor/version CLI, and flag/environment configuration.
- IPv4 interfaces and automatic/manual selection; gateway detection through /proc/net/route.
- Gin health and interface endpoints with controlled shutdown.
- Makefile, LAN-independent tests, and initial documentation.

- Add read-only Windows PowerShell evidence export and inventory-scoped JSON import.
- Show Windows CVE/advisory assessments with accessible status icons, evidence and references.
- Retain bounded imported reports and reject stale, oversized or mismatched host exports.

- Add inventory navigation to Nmap completion messages, including hidden cards/pages.
- Add opt-in recurring discovery windows, new-host counts and serial automatic common TCP inspection.
- Preserve host evidence across windows and avoid repeated automatic IP inspection.
- Display prominent structured vulnerability verdicts in manual check dialogs.

- Add explicit key-only SSH collection to Windows assessment, requiring an observed inventory SSH service and existing trusted host identity.
- Add collector stdout mode and controlled PowerShell/SSH process regression tests.

- Show timed discovery phases with a visual countdown, round badge and TCP queue progress.
- Enable Auto TCP by default in the authorized scan form and process peers with two bounded workers.
- Restrict Windows assessment to Windows evidence and make remote file collection/import the primary action.

- Add optional bounded ARP discovery, MAC/vendor evidence merging, permission-aware fallback, and startup tool/version diagnostics with OS-specific installation guidance.

- Add an explicit dedicated-account runtime with a root-owned, validated ARP helper and narrowly scoped passwordless sudo policy; retain direct unprivileged development mode.

- Make `make run` use the dedicated account and restricted ARP helper by default; retain `run-dev`, expose ARP execution mode and separate UPnP technical details visually.

- Keep ignored duplicate UPnP identity diagnostics in inventory JSON while excluding them from user-facing scan notes.
