# Security

Use only your own or an authorized LAN. Only the explicit scan command sends SSDP discovery requests. --enrich additionally fetches validated LOCATION documents. There are no port probes. Do not attempt passwords, bypass authentication, exploit vulnerabilities, or access private shares.

HTTP binds to localhost by default and has header limits and timeouts. POST actions require a process-local random CSRF token, standard-library cross-origin checks, and explicit LAN authorization for scans. Host validation rejects unexpected DNS names and ports; wildcard listeners accept literal IP hosts. Templates escape LAN metadata, and the browser uses textContent for warnings. CSP restricts scripts/connections to the same origin, disables framing and objects, and HTMX evaluation is disabled. Authentication is still absent: keep the listener local. CSRF protection is not access control for other local processes or exposed LAN clients.

Scan requests are capped at 4 KiB and validated before reserving a single execution slot. Managers retain eight sessions, 512 events per session, and bounded inventories. Discovery windows are 1–60 seconds, enrichment has a 30-second deadline, and an outer deadline bounds each browser scan. Cancellation and shutdown join workers. SSE is limited to 16 connections, two-minute streams, and five-second write deadlines. Replay overrun sends reset; slow readers never hold producer queues.

SSDP snapshots all local IPv4 addresses and rejects announcements from those sources before creating records or sending SSE notifications. This prevents the scanner host and its local aliases from appearing as remote targets.

All UPnP description downloads use internal/security/safehttp. It accepts only HTTP/HTTPS, rejects URL credentials/fragments and invalid ports, and requires all resolved addresses to match the announcing peer within the selected subnet. Connections use a literal pinned IP and selected local source address, with no environment proxy. Local-address snapshots, loopback, link-local, multicast, network and broadcast addresses are blocked. Redirects retain that policy, permit at most three hops, and reject HTTPS downgrade. TLS verification stays enabled. Requests have five-second total deadlines, bounded headers, no automatic decompression, and a 1 MiB body limit. Advertised service links do not authorize new connections.

UPnP XML uses encoding/xml without external entity resolution, with byte, depth, element, device, and service limits. DTD directives, unknown entities, duplicate singleton fields, and invalid identities are rejected. Nmap service inspection is explicit and targets individual known remote IPs. The separately selected all-host discovery option uses host discovery only within the selected subnet, limited to /22 or smaller. Both exclude local addresses and validate interfaces, subnet membership, literal IPs, timeouts, concurrency, and output limits. Subprocesses use exec.CommandContext without a shell or caller-supplied flags. Network data is untrusted and must be escaped before rendering as HTML.

SSDP uses the selected interface, multicast TTL 1, and accepts only sources in the first IPv4 address's subnet. Datagrams are limited to 16 KiB and collected announcements to 4096. The discovery window is limited to 1 minute; Ctrl+C cancels the operation. UDP source addresses do not prove identity or authorization; LOCATION validation is mandatory whenever --enrich fetches a description.

## Secure development lifecycle

Changes are checked with gofmt, go vet, staticcheck, gosec, govulncheck, and tests through make check. CodeQL is configured for GitHub when Code Scanning is enabled. Code review and security regression tests remain necessary, especially for network URLs, redirects, XML, and subprocesses. Fix findings at their cause; suppressions require a specific rule and documented justification, never blanket exclusions. See [SAST](SAST.md) for the gate, SARIF, and tool update policy.

## Remaining trust limits

SSDP source addresses and UUIDs can be forged on a LAN. Matching a URL to a peer prevents arbitrary cross-host fetching but does not authenticate that peer or guarantee that its HTTP endpoints are harmless. Only GET descriptions are fetched; service, manufacturer, and presentation links are metadata. HTTPS peers with untrusted certificates fail rather than weakening TLS. DNS names with additional IPv6 or other-IP results are rejected conservatively. Inventory identity is logical and based on claims, not proof of physical equipment ownership.

Enrichment can recover valid profiles from descriptions with repeated UDN claims. It keeps the first occurrence and drops later duplicate branches with explicit warnings, without merging different device types or inventing identities. Every input branch is validated and counted against existing XML/device/service limits before pruning. Other XML or identity failures still reject the description.

The optional ICMP supplement uses unprivileged datagram sockets, bounded concurrency, selected-source binding, cancellation, and one-second request deadlines. Only source/sequence/random-payload matched echo replies add evidence; a timeout, socket error, or cached address cannot establish liveness. IPv4 subnet/local-address exclusions are applied before either TCP or ICMP probes.

## Reviewed manual NSE actions

NSE checks use a fixed four-script allowlist, compatible open observations on default RDP/SMB ports, current inventory scope and fresh local-address/interface validation. Unknown scripts, broad categories, script paths, arbitrary peers and credential fields are rejected. Each job performs fixed script-help availability lookup, then one target/port/script with bounded runtime/output/XML evidence. Guest fallback is disabled; only anonymous SMB metadata is allowed, and MS17-010 fixes IPC$ without disk-share access. No exploit, password attempts, brute force or denial-of-service profiles are enabled. MS12-020 remains deferred.

Structured evidence and script-specific adapters preserve positive/negative/inconclusive/not-applicable distinctions. The MS17-010 adapter does not trust NOT VULNERABLE after network/authentication errors: only an exact patched-system result can become negative. Missing output and unrecognized/ambiguous evidence never imply safety. Eight retained detached job snapshots share admission and cancellation with existing network actions. See [implementation details and bounds](NSE-INTEGRATION.md).
