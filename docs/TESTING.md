# Testing

`make check` validates gofmt, go vet, staticcheck, gosec, govulncheck, and tests. Configuration tests use a controlled environment; interface and route tests use synthetic data; API tests use httptest recorders and controlled loopback servers.

The testdata/ssdp-responses.txt fixture verifies case-insensitive headers and advertised fields. SSDP tests also cover invalid datagrams, deduplication, sources outside the subnet, deadlines, and cancellation through loopback sockets without relying on the LAN. `go test -race ./internal/discovery/ssdp` checks concurrent cancellation behavior.

Phase 3 adds testdata/minidlna-rootdesc.xml and tests for root/embedded parsing, fields, malformed XML, DTD/entities, duplicate fields, structural limits, merging, provenance conflicts, snapshot isolation, and cancellation. Safe HTTP tests use loopback servers with injected DNS/dial functions under a documentation-only IPv4 subnet: no real LAN targets are contacted. They verify literal-IP pinning, DNS rebinding/mixed results, redirect policy, proxies, local/subnet exclusions, TLS certificate verification, response limits, and cancellation.

Phase 4 tests inject a runner using synthetic devices and no LAN discovery. They cover single-scan admission, cancellation, shutdown, state/event snapshot isolation, journal bounds, cursor replay, session expiry, CSRF, cross-origin/Host rejection, strict request parsing, escaped device metadata, embedded assets, and real loopback SSE flushing/deadlines. Future phases will add Nmap XML fixtures. Mocks should represent relevant failures and limits. LAN integration tests will be opt-in, require an explicit interface, and never run automatically through make test.

## Static analysis and vulnerability analysis

Staticcheck and vet inspect correctness; gosec and CodeQL perform SAST. Govulncheck inspects known dependency vulnerabilities and call reachability. These checks do not replace dynamic tests. Security regression tests should cover rejected input, subnet boundaries, cancellation, malformed packets, and future SSRF/redirect/XML/subprocess policies. make security runs gosec and govulncheck; make security-report writes SARIF. See [SAST](SAST.md).

Run `go test -race ./internal/security/safehttp ./internal/inventory ./internal/scanner` to check concurrent policy use, snapshots, and worker coordination. Fixtures use synthetic names and identifiers rather than captured private device data.

Run `go test -race ./internal/scanner ./internal/web ./internal/discovery/ssdp` for scan coordination, HTTP/SSE, and socket cancellation checks. Browser JavaScript can be checked with `node --check internal/web/assets/app.js` if Node is available; Node is not required to build or run the application.

The Phase 4 browser smoke check was run with headless Chrome against a controlled loopback fixture runner. It verified local asset loading, disabled HTMX evaluation, form submission, EventSource completion, HTMX inventory updates, and cancellation without JavaScript/CSP errors. It did not send SSDP or contact a LAN device.

Local-source exclusion tests use three controlled loopback addresses and an injected local-address set, verifying that only the simulated remote source reaches both results and progress callbacks. The synthetic duplicate-udn-rootdesc.xml fixture reproduces a gateway hierarchy with conflicting WAN/LAN UDN claims; tests cover partial enrichment, preserved hierarchy/services, explicit warnings, and safety limits applied to pruned branches.

Visual presentation tests cover explicit manufacturer aliases, unknown/spoofed manufacturer names, same-IP ancestor inheritance, cross-IP/cycle rejection, unchanged evidence, escaped metadata, and local asset availability/allowlisting. Browser validation uses synthetic inventories and checks both desktop and mobile layouts without performing LAN discovery.

## TCP services and reference verification

Controlled fixtures cover all 65535 individual TCP observations, common/full enum arguments, metadata/CPE bounds, icon fallback, bounded card previews, protocol-aware web links and exact-version CVE references with negative cases. Historical TCP/UDP confusion, Windows/445-only CVE inference, unknown ports and patched/ambiguous version strings are negative cases. A fake smbclient executable verifies metadata-only anonymous arguments, hidden-share exclusion, cancellation and output flooding without LAN traffic. HTTP tests reject missing authorization/CSRF, passwords, unknown flags/profiles and unobserved SMB ports. Controlled Chrome checks use 65535 synthetic ports and verify 50-row pagination, filters, web actions, sticky modal header, Escape dismissal and desktop/mobile width without browser errors.

## Manual NSE checks

NSE tests use structured hostscript/port XML and fake executables, never a current-LAN target. They distinguish a recognized patched response from an upstream NOT VULNERABLE label caused by authentication or connection failure. Negative fixtures include raw text claims, duplicate/conflicting states, unexpected CVEs, absent results, unknown/disabled script IDs, mismatched peers/ports, oversized output/evidence and unsupported metadata. Scanner fixtures verify shared admission with scans/TCP/SMB, cancellation, shutdown, detached nested snapshots, eight-job retention and preservation of earlier successful results on failure. HTTP fixtures reject credential/target fields, unauthorized/CSRF-less calls and incompatible observations. Chrome fixtures verify no execution on dialog opening, explicit Run check, visual progress, script-reported CVE links, safe text rendering, cancellation, reload polling and retained results on desktop/mobile.

Windows import tests use controlled JSON and inventory fixtures. They cover input
bounds, freshness, unknown fields, multiple documents, host IP binding, exact
patch applicability, inconclusive missing evidence, policy warnings, detached
storage, stale scan rejection, HTTP CSRF and collector download. No Windows or
current LAN is required. PowerShell runtime behavior must also be checked on a
controlled Windows endpoint; Linux Go tests do not establish that validation.

Monitor fixtures cover hosts appearing in later windows, preservation of prior
TCP evidence and missing device identities, one automatic attempt per IP, fixed
common inspection, shared admission, cancellation and invalid public intervals.
HTTP regression tests reject out-of-range and overflowing interval values before
conversion to durations. Browser verification uses a controlled synthetic
inventory, including paginated host navigation and positive/negative/inconclusive
verdict rendering; it never scans the current LAN.

Windows SSH tests replace the ssh executable with a controlled helper process,
verifying fixed arguments/payload, success, failure, output flooding and cancellation.
The installed `pwsh` runs the collector with mocked Windows inventory commands,
validating stdout JSON and optional collection errors without accessing Windows or
a LAN. The runtime test skips explicitly when pwsh is unavailable. This does not
establish real Windows/OpenSSH compatibility; endpoint verification remains pending.

Monitor regressions also enforce two TCP workers, expose queued card states and
verify cancelled backlog counts. Windows presentation tests require explicit
Windows product/CPE or imported identity rather than vendor/port guesses. The
PowerShell fixture exercises the temporary file/export/import collector flow
with a controlled powershell.exe function and verifies the returned JSON.
