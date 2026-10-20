# Architecture

Current flow: CLI → configuration / interfaces / SSDP → scanner → safehttp + UPnP → inventory report; CLI also provides diagnostics and HTTP. Gin is restricted to internal/web. The core uses the standard library and golang.org/x/net/ipv4 for multicast control.

Planned pipeline: interface → SSDP (0.1), mDNS/ARP (0.2) → registry → UPnP → optional Nmap → profile → Web/API.

The registry distinguishes SSDP announcements and logical UPnP devices. An IP address is not a permanent identity: UDN/USN claims correlate logical devices, while embedded-device links preserve the XML hierarchy. IP-level host records group current-scan evidence and TCP results without merging logical UUID identities. Permanent physical-equipment correlation remains future work. Field provenance includes source, time, value, and originating URL, preserving conflicts.

The HTTP server has limits and context-driven shutdown. A Gin-free scanner.Manager owns one active scan, eight retained sessions, and immutable state snapshots. The web layer validates requests, renders escaped templates, and delivers bounded SSE replay. Persistence and confidence scoring remain outside the current scope.

SSDP binds a UDP socket to the selected interface's first IPv4 address. The multicast output interface and TTL are set explicitly. One goroutine reads responses; context.AfterFunc closes the socket on cancellation. Announcements are deduplicated by IP/USN/ST/LOCATION and sorted for JSON output. No goroutine or subprocess is created per response.

## Phase 3 pipeline

Plain scan remains SSDP-only. With --enrich, scanner records all announcements, deduplicates IP/LOCATION work, then uses four workers and a caller-bound 30-second context. Every download goes through safehttp; there is no generic HTTP client in the enrichment coordinator. Fetch/XML failures become report warnings and do not erase discovery evidence. Source UUID claims must match a root or embedded XML UDN; non-UUID announcements can be promoted using the validated endpoint description.

The registry is synchronized and snapshots are deep copies sorted by ID. IDs hash normalized UUID keys or provisional IP/LOCATION keys. UUID claims are not authentication. Same-name or same-IP devices with different UUIDs remain separate. Enrichment keeps raw URL references and URLBase as metadata; future actions must resolve and revalidate them through safehttp.

For current fields, UPnP metadata outranks SSDP, followed by observation time and a deterministic lexical tie-break. IP always follows observation time. Conflicting values remain in evidence, capped at 16 claims per field. The registry caps logical records at 4096 and retained services at 256 per record. Requests are capped at 256 per scan. Limit errors preserve previously collected data. There is no persistence or confidence heuristic yet.

## Phase 4 browser pipeline

Explicit authorized POST → interface selection → Manager → SSDP progress → optional UPnP progress → final report. The manager starts background work from the server lifetime context, not the POST request context. Cancelling a browser request therefore does not accidentally cancel an accepted scan. Explicit cancellation and server shutdown do. Inventory is reset per scan, with partial snapshots while running. Discovery snapshot publication is batched during packet bursts.

Each session has a 512-event journal and a close-and-replace notification channel. SSE handlers copy events and wait on notifications without blocking workers; cursor overruns trigger reset. The web layer limits stream connections and applies individual write deadlines through ResponseController while retaining ordinary HTTP write limits. HTML, Bootstrap CSS, HTMX, and application JavaScript are compiled into the binary under internal/web. HTMX refreshes the escaped inventory fragment after coalesced EventSource notifications. No Gin imports are introduced into the core.

## Nmap integration

The optional internal/enrichment/nmap provider validates the selected interface, first IPv4 subnet, local addresses, and literal targets before starting a fixed executable with exec.CommandContext. Explicit all-host discovery enumerates at most 1024 subnet addresses and excludes local/network/broadcast targets. Manual service inspection accepts only an IP already present in the latest scan. The manager shares one execution slot between discovery and manual jobs, keeps eight job snapshots, and cancels subprocesses during shutdown. XML output is limited to 32 MiB, depth 32, 400000 elements, 1024 hosts, and 65535 TCP ports per host. Product/state/CPE metadata has additional length and count limits. Manual common/full profiles have fixed TCP ranges, `-T4`, and two/five-minute host deadlines. Cards render only four observations; the services dialog renders 50 filtered rows per page. Requested coverage is stored only after successful completion. Anonymous SMB listing also uses the shared network slot and revalidates current peer/subnet/local-address exclusions before execution. Host metadata and TCP ports are stored separately from logical UPnP services. Controlled parser, subprocess, manager, and HTTP fixtures do not probe the current LAN.

Host discovery combines fixed TCP liveness probes and a parallel ICMP echo sweep within a shared 60-second deadline. ICMP uses 64 bounded workers, two one-second requests per target, selected-source binding, and nonce/sequence/source correlation. It does not use raw-socket elevation or treat cached ARP entries as live. Partial verified ICMP observations survive a Nmap failure. Inventory views distinguish UDN-bearing logical identities from provisional SSDP endpoints and count open host TCP observations once per IP.

## NSE check integration

The existing Nmap package owns reviewed script metadata, bounded XML evidence, fixed process arguments and per-script interpretation. The scanner coordinates a separate retained CheckJob whose execution status is distinct from CheckResult assessment; it shares the network slot and joins workers on shutdown. Web handlers accept strict authorized selectors into current observed services and expose detached status/results. The browser's services modal offers manual actions, progress, cancellation and retained evidence; reload performs status reads only. No Gin dependency enters core packages. See [NSE integration](NSE-INTEGRATION.md).
