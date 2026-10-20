# Static analysis and security gates

## Purpose and threat model

NetExplorer consumes untrusted LAN announcements and exposes a local HTTP API. Priorities are SSDP LOCATION URLs, SSRF, redirects/DNS, XML, subprocess arguments, file paths and permissions, TLS, HTTP input, cancellation, timeouts, and resource cleanup. LAN origin is not proof of trust. SAST complements review and runtime regression tests; it does not prove that the application is secure.

## Tools and pinned versions

| Category | Tool | Version / purpose |
| --- | --- | --- |
| Format | gofmt | System Go 1.27.1 in CI; formatting |
| Correctness | go vet | System Go 1.27.1 in CI; compiler-related diagnostics |
| Correctness | staticcheck | v0.8.1 (2026.2.1) |
| SAST | gosec | v2.29.0 |
| Vulnerabilities | govulncheck | v1.1.4; Go vulnerability database and call analysis |
| Tests | go test | Dynamic regression tests, independent of the LAN |
| SAST | CodeQL | SHA-pinned official v4 Action, Go security-extended queries |

The separate devtools/go.mod uses Go tool directives and fixed versions. Its go.sum verifies tool dependencies. The main application module does not import these tools or share their dependency graph. Make builds their commands from the isolated module into build/devtools and executes them from the application root, so analyzers load the application go.mod. The system Go compiler remains outside the repository.

A locally built gosec prints `Version: dev`; verify the actual module version with `go version -m build/devtools/gosec`. Do not interpret this display as an unpinned build. Tool dependencies are not linked into NetExplorer. No AI-assisted gosec analysis is enabled and no API keys are required.

## Local checks

```sh
make tools
make fmt
make check
make security
make security-report
```

Individual checks: `make fmt-check`, `make vet`, `make lint`, `make sast`, `make vuln`, and `make test`. Tools are built automatically when missing or when devtools/go.mod/go.sum change; no global installation occurs. Cold builds and vulnerability checks require network access. `make clean` removes generated binaries and reports, not Go or its cache.

For manual tool execution, use the build/devtools executables from the root. Running `go -C devtools tool ... ./...` would analyze the tools module rather than the application and is not the project check command.

## Quality gate

`make check` is the local gate: formatting verification, vet, staticcheck, gosec, govulncheck, and tests. It never reformats silently. Failures remain failures: no blanket rule exclusions, nonzero exit suppression, or severity filters are configured. All unsuppressed gosec and staticcheck findings block. Govulncheck blocks on reported reachable vulnerabilities, not merely the presence of a vulnerable module. Any proposed exception requires documented review of the exact finding and affected use.

Govulncheck uses conservative static call analysis; reported reachability is not proof of exploitability. `build/devtools/govulncheck -show verbose ./...` also displays package/module findings without known call paths. Lack of a call path is not a permanent exemption: future code or tags can change reachability. Its database changes independently of pinned tool versions. Record scan date and database version for investigations. Failed database access is an incomplete check, never a clean result.

## CI, CodeQL, and SARIF

.github/workflows/ci.yml runs on PRs, main pushes, weekly schedules, and manual dispatch. Quality checks and security checks have separate jobs, timeouts, read-only contents permissions, and dependency caches. The security job generates gosec SARIF and runs govulncheck even if SAST fails. Artifact upload runs after failures without masking their status. Reports remain artifacts for 14 days and are excluded from Git under build/.

The CodeQL workflow is configured separately. Set the repository variable ENABLE_CODE_SCANNING to `true` only after confirming GitHub Code Scanning availability. Until then the job is explicitly skipped and CodeQL has not analyzed the project. Only that job has security-events: write. Gosec SARIF upload to Code Scanning is not required; its downloadable artifact remains available independently.

Actions are pinned to official commit SHAs with version comments. GitHub runner images and external vulnerability databases evolve. No remote exists yet, so workflows are locally validated but GitHub execution and repository protection rules remain pending. Maintainers should require the appropriate CI checks before merging once published.

## Suppressions and false positives

Investigate findings before changing code or suppressing them. Prefer fixing the cause. A justified gosec exception must specify the exact rule and a nearby reason, for example `// #nosec Gxxx -- reviewed invariant and why the operation is safe.` Never add a bare nosec or global exclusion simply to pass CI. Do not suppress SSRF or command injection without resolving the underlying issue. Staticcheck exceptions also need a narrow scope and explicit justification. One narrow G204 exception exists in internal/enrichment/nmap/nmap.go at execute: the executable is the fixed name "nmap", and arguments come only from private fixed-profile builders after interface-name and literal in-subnet IP validation. No shell, caller flags, arbitrary executable, or discovered URL is accepted. Fixture tests cover invalid targets, argument injection, cancellation, and output bounds. This exception does not apply to other subprocess calls.

## Updates and troubleshooting

Dependabot checks the application module, devtools module, and Actions weekly, with bounded PR counts. Update tool versions using `go -C devtools get -tool PACKAGE@VERSION`, review devtools/go.mod/go.sum, and run `make check`, `make security-report`, and `make build`. Inspect the main go.mod separately; tool updates must not modify runtime dependencies. Review Go and CodeQL compatibility before changing the CI toolchain.

- Missing tool binary: run make tools; inspect build errors and Go compatibility.
- Missing vulnerability database/network: retry after connectivity is restored; distinguish this from a finding.
- Gosec SARIF with a nonzero exit: inspect results; report generation does not imply a clean scan.
- CodeQL skipped: check ENABLE_CODE_SCANNING and account/repository support.
- A newly failing check with unchanged code: compare tool, database, runner, and dependency changes.
- RTK output is insufficient: obtain complete diagnostics; analysis takes priority over token savings.

## Future policies

security/semgrep documents planned shell-invocation rules. Semgrep is optional, and no unvalidated rule has been enabled. Phase 3 implements internal/security/safehttp for SSDP/UPnP description URLs with subnet, DNS, pinned-address, redirect, timeout, and response-size enforcement backed by regression tests. All future discovered URL requests must continue using that policy, including service actions.

## Validation snapshot — 2026-10-02

Formatting, vet, staticcheck, gosec, tests, make check, and build passed locally. The initial SARIF 2.1.0 contained zero findings and no suppressions; the Nmap integration adds the reviewed G204 exception described above. Workflows passed actionlint v1.7.12; workflow and Dependabot YAML parsed successfully. The binary served health and shut down gracefully with an empty PATH, without development tools. GitHub execution and CodeQL analysis remain pending because no remote is configured.

Initial gosec G104 findings concerned ignored close errors in the SSDP cancellation callback and HTTP forced shutdown. Both were corrected without suppressions. Initial govulncheck reported GO-2026-5676 as reachable through quic-go v0.59.0; the runtime now uses the patched v0.59.1. The current server uses net/http rather than HTTP/3, so the conservative call traces did not prove exploitation; upgrading removed the vulnerable dependency version without relying on that distinction.

The final govulncheck scan reports zero reachable vulnerabilities, three package-level records, and 24 module-level records without identified vulnerable calls. Package records are GO-2026-5970 (x/text invalid input), GO-2026-5026 (x/net/idna), and GO-2026-4918 (x/net HTTP/2). Other module records include SSH/agent, OpenPGP, HTML, and DNS functionality not used by the current discovery flow. These records are not suppressed or represented as fixed. Reassess them when adding HTTP clients, hostname resolution, or new protocols in Phase 3 and later. The gate follows the documented reachable-call policy; dependency maintenance remains necessary.

The complete verbose scan is generated locally at build/security/govulncheck.txt and is intentionally outside Git. Reproduce it with `build/devtools/govulncheck -show verbose ./...`. A transient database network failure was retried successfully and was not treated as a clean result.

### Nmap integration validation — 2026-10-02

make fmt, make check, make build, and go test -race ./... passed after adding the provider. Gosec reports zero issues and one reviewed G204 exception. Controlled Chrome desktop/mobile checks verified extra-host cards, manual TCP results, reload recovery, no horizontal overflow, and no browser errors. No current-LAN scans were performed during verification.

### Expanded discovery and header validation — 2026-10-02

Controlled ICMP fixtures cover retry, cancellation, socket denial, source/sequence/payload correlation, and unrelated replies. Provider fixtures cover selected-source binding, local/network/broadcast exclusions, TCP probe arguments, combined provenance, and retained ICMP evidence on process failure. Browser checks with 110 synthetic hosts verified header controls, four desktop columns, distinct logical/service views, pagination, filter retention, service expansion after refresh, and mobile layout without horizontal overflow. No current-LAN probes were performed.

### UI polish validation — 2026-10-02

make fmt, make check, and make build passed. Controlled Chrome checks verified three desktop columns, readable number input on desktop/mobile, unwrapped duration labels, service expansion without nested scroll, JSON modal loading and Escape dismissal, plain-text handling of script-like metadata, animated TCP progress, and explained timeout notes. No current-LAN scans were performed.

### TCP service and SMB listing review — 2026-10-02

A second narrow G204 exception covers the fixed `smbclient` executable in `internal/enrichment/nmap/shares.go`. Only `ListShares` constructs its arguments after validating current interface, literal remote IP and fixed SMB ports. Flags are metadata-only; there is no shell, caller-supplied flags, passwords, private-share access or protocol downgrade. Process timeout/output bounds and shutdown/request cancellation apply. The original Nmap exception now also covers the enum-selected fixed full/common port profiles. Parser limits were raised for a single full TCP range with bounded service/CPE metadata. CVE associations are offline informational references, not active vulnerability scans.

Final validation passed: make fmt, make check (vet, staticcheck, gosec with zero issues and two reviewed exceptions, govulncheck with zero reachable vulnerabilities, fixture tests), make build and race tests for Nmap, service references, scanner and web packages. Controlled Chrome desktop/mobile checks passed with 65535 synthetic observations, 50 rendered rows per page, working filters/actions, sticky header and no JavaScript errors. No current-LAN actions ran during verification. A subprocess flooding fixture exposed an io.Copy optimization bypass through embedded bytes.Buffer.ReadFrom; replacing embedding with a private buffer and bounded forwarding methods fixed it, with direct-copy and real fake-subprocess regression coverage.

### Manual NSE integration validation — 2026-10-02

Reviewed the installed Nmap 7.98 RDP/SMB scripts and relevant smbauth/vulns behavior. The fixed Check builder now uses the existing reviewed nmap G204 exception; no new suppression was added. Script names/arguments remain catalog-only, LAN scope is revalidated, Guest fallback is disabled, and credentials/private disk-share access/exploitation are excluded. The MS17-010 adapter treats upstream NOT VULNERABLE connection failures as inconclusive and accepts a negative finding only with a recognized patched-system response.

make fmt, make check (vet, staticcheck, gosec with zero issues and two reviewed exceptions, govulncheck with no reachable vulnerabilities, controlled tests), make build and race tests for Nmap, services, scanner and web passed. Fixtures cover host/port structured XML, positive/negative/ambiguous/missing evidence, bounds, scope mismatch, script absence, fake subprocess argument validation/cancellation, shared admission, detached snapshots, retention, shutdown and protected HTTP actions. Chrome desktop/mobile checks passed for manual-only execution, authorization, progress, CVE links, escaped evidence, cancellation, reload recovery, retained results and Escape dismissal without JavaScript errors. No current-LAN checks ran during verification.

## Windows SSH collector

A narrow G204 exception in `internal/enrichment/windows/ssh.go` covers the fixed
system `ssh` executable after inventory-backed canonical LAN IPv4 and local-account
username validation. The remote command and stdin script are fixed. Password,
keyboard-interactive, prompts, forwarding, proxies, local commands and SSH config
are disabled. Strict host trust is required; host key enrollment/rotation is disabled.
Subprocess deadlines, cancellation, WaitDelay and drained bounded output apply.
Regression fixtures verify argument invariants, failed/flooding processes,
cancellation, username/scope rejection and HTTP CSRF/unknown credential fields.
No real Windows SSH connection was validated: trusted host identity and authorized
public-key access have not been configured by the user.

The ARP discovery adapter adds a reviewed G204 exception for the fixed `arp-scan`
executable. Its private builder receives the same validated interface/subnet and
literal remote targets as Nmap; it accepts no user flags, shell, sudo, vendor-file
paths or spoofing parameters. Fixed system vendor paths are opened through
`os.Root`, with null-device fallback. Fixtures cover subprocess argument scope,
permission denial, cancellation, malformed/oversized vendor rows, local/outside
addresses, multicast/zero MACs, duplicate/conflicting responses, random MAC vendor
suppression and ARP-only/fallback discovery. Startup version probing uses the fixed
executable and `--version`, bounded output, a timeout and no network action.

An explicitly requested dedicated-account installation adds a second narrow G204
exception in the ARP adapter: fixed `/usr/bin/sudo -n --` and fixed root-owned
`/usr/local/libexec/netexplorer-arp`, with only the validated interface name. The
helper independently re-enumerates interfaces and constrains active IPv4 LAN
scope to /22–/30, builds fixed ARP arguments and excludes local addresses. The
sudoers rule permits only the installed Wi-Fi interface and was validated by
`visudo`. Controlled tests reject malformed interfaces and broad/narrow unsupported
subnets. Deployment validation confirmed root-owned binaries, a nonprivileged
server account, rejection of unrelated commands/interfaces, successful ARP access
and a separate loopback HTTP instance. No `NOPASSWD: ALL`, privilege-bearing group,
arbitrary shell or general-purpose elevated arp-scan entry was installed.

## Offline MAC registries and mDNS

Vendor refresh uses fixed IEEE HTTPS endpoints, rejects redirects, bounds bodies and duration, validates every dataset and atomically publishes a temporary TXT. CSRF-protected actions reserve one worker and cannot accept arbitrary URLs, files, subprocess flags or targets. App-owned databases are parsed without elevating privileges; the root ARP helper uses null vendor files. Custom system files remain read-only. Local/private MACs suppress OUI attribution across discovery and manual TCP enrichment.

mDNS uses the selected interface, bounded DNS parsing and allowed LAN packet senders, with no automatic actions from advertised names or addresses. Tests cover malformed packets, discarded queries, prefix specificity, local/multicast MACs, invalid registry rows, failed downloads, reload and worker exclusion. The DNS integration requires x/net 0.56.0 or newer (GO-2026-5942); x/text is pinned to 0.39.0 to address GO-2026-5970.

## Saved inventory imports

Snapshots have a fixed version, typed strict JSON decoding, a 16 MiB body limit, bounded host/device/port/check collections and validated IPv4/identifier/MAC fields. Imported inventories stay separate from the scan manager; same-origin/CSRF-protected imports cannot resume scanners or enqueue inspections. Write actions are rejected in saved-analysis mode. LAN-controlled and file-controlled text remains escaped by templates or browser text nodes; logo paths come only from the fixed local catalog. Regression tests cover round trips, invalid files/endpoints, CSRF and blocked network writes.
