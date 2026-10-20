# Manual NSE integration plan

Status: first delivery implemented and validated with controlled fixtures. Existing TCP inspection and offline CVE references remain available. The project now permits reviewed, explicit vulnerability checks on authorized LAN inventory hosts. Password attempts, brute force, cracking tools, private-share access, exploitation and denial-of-service tests remain outside scope.

## 1. Reviewed script catalog

Add a catalog in the existing Nmap enrichment package, with fixed IDs, script names, applicable protocols, expected services, port constraints, timeout, impact notes, references and interpretation rules. Users select a catalog ID rather than supplying a script path, expression or arguments. Review script code and relevant library calls, not just category labels.

Initial candidates:

| Script | Purpose | Review decision |
| --- | --- | --- |
| rdp-ntlm-info | RDP host/build metadata from NTLM negotiation | Enabled; null-credential negotiation only |
| smb2-security-mode | SMB2/SMB3 signing configuration | Enabled |
| smb2-time | SMB2 system/start time | Enabled |
| smb-vuln-ms17-010 | SMBv1 patch-state indications for MS17-010 | Enabled manually; anonymous IPC$ metadata, Guest fallback disabled |
| rdp-vuln-ms12-020 | MS12-020 protocol check | Deferred; not in the executable catalog |

Use scripts provided by the system Nmap installation. Record the Nmap version for reproducibility and report missing scripts clearly. Do not download from GitHub master or install tools automatically. Do not expose broad selections such as --script vuln, all, default or arbitrary user expressions.

Sources: [RDP metadata](https://nmap.org/nsedoc/scripts/rdp-ntlm-info.html), [SMB signing](https://nmap.org/nsedoc/scripts/smb2-security-mode.html), [SMB time](https://nmap.org/nsedoc/scripts/smb2-time.html), [MS17-010](https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html), [MS12-020](https://nmap.org/nsedoc/scripts/rdp-vuln-ms12-020.html).

## 2. Bounded XML evidence

Extend internal/enrichment/nmap XML decoding to retain script results under both hostscript/script and ports/port/script. Preserve script ID, output and nested table/elem evidence, with byte, node, depth and per-result limits. Treat every value as untrusted text. Match known structured fields with script-specific adapters; do not infer a negative result from missing output or substring matches.

Model execution outcome separately from assessment. Execution can be completed, failed, timed out or cancelled. Assessment can be positive, negative, inconclusive or not applicable. Retain reported CVE IDs, source script, target IP/port, observation time, Nmap version and relevant evidence. A positive script result is an active-check indication, not proof of exploitation or malware infection. Never replace offline potential matches with unsupported certainty.

## 3. Manual execution and job coordination

Add a fixed-profile provider action using exec.CommandContext, XML output, explicit script selection and bounded host/script deadlines. Revalidate the selected live interface, subnet, all local addresses and literal target immediately before execution. Require an observed open compatible service, supporting reviewed nonstandard ports only when the script can target them safely.

Extend scanner job coordination to share the existing network slot with discovery, TCP inspection and SMB listing. Keep cancellation, shutdown joining and bounded job retention. Preserve existing successful evidence on failure. Never retry with passwords, guessed shares, weaker authentication or more intrusive scripts.

## 4. HTTP and UI

Add POST /api/hosts/:id/checks with a strict small body containing authorized and check_id. Resolve targets and ports from current inventory; reject extra fields, arbitrary targets and flags. Reuse CSRF and same-origin protections. Provide job status and cancellation routes, with a read-only endpoint for retained results.

In the services popup, expose compatible checks per service. Informational collection and vulnerability verification should have distinct labels. Display impact notes before higher-impact manual checks and require a deliberate user action; never start them during discovery, TCP inspection or page loading. Show visual progress and compact assessment icons with accessible tooltips. Details include CVE links, timestamp, evidence, source script and execution errors. Inconclusive results must not look like a clean bill of health.

## 5. Validation and delivery

Implement in order: catalog and result model, XML fixtures/adapters, bounded provider execution, manager jobs, protected API, then UI. Start with informational scripts and MS17-010. Enable MS12-020 only after its protocol behavior and cleanup paths have been reviewed; the category label alone is insufficient.

Tests must use controlled XML and fake executables: positive/negative/inconclusive results, host-level results, absent scripts, malformed/oversized output, script/argument injection rejection, peer exclusions, cancellation, shared admission, shutdown, API authorization and escaped evidence. Browser fixtures verify desktop/mobile layout, progress, retained results and tooltip states. Run make fmt, make check, make build and relevant race tests. No current-LAN checks run automatically during development tests.

## Implemented behavior

The catalog in `internal/enrichment/nmap/checks.go` enables four explicit IDs: `rdp-ntlm-info`, `smb2-security-mode`, `smb2-time` and `smb-vuln-ms17-010`. Compatibility currently requires an observed open TCP port 3389 for RDP or 139/445 for SMB, with a compatible or unknown detected service. Nonstandard ports and MS12-020 are not enabled in this delivery.

Each action first runs fixed `--script-help <catalog-id>` to check the installed script, then TCP connect scanning of that one port with `-Pn -n`, the selected interface, exactly one script, a 30-second script deadline and 45-second host deadline. The provider has a 55-second total deadline and the manager a 60-second deadline. SMB arguments fix `smbnoguest=true` and the observed SMB port. MS17-010 additionally fixes `vulns.showall=true` and `IPC$`; usernames, passwords, hashes and caller-supplied arguments are never accepted. No disk-share access, exploit or cracking tool is involved. Review covered the installed Nmap 7.98 scripts and relevant smbauth/vulns library behavior. Reassess after tool/script upgrades; unfamiliar output remains inconclusive.

The XML adapter retains both host-level and port-level scripts and records the run's Nmap version. Check XML is limited to 2 MiB within the shared subprocess stdout limit of 32 MiB. Evidence limits are 32 scripts per container, 64 KiB readable output per script, 1024 structured nodes, depth 12, 128-byte keys, 4096-byte scalar values and 128 KiB total evidence per script. A manual check rejects results for other peers, ports, duplicate/unrequested scripts or oversized evidence. Only its selected script is interpreted.

MS17-010 interpretation deliberately differs from blindly trusting the script's label: upstream also reports NOT VULNERABLE after connection/authentication errors. A positive result requires structured VULNERABLE evidence and the script-reported CVE-2017-0143 identifier. A negative result additionally requires the exact structured check result `This system is patched.` Ambiguous/missing fields, duplicate states, connection failures and plain output strings stay inconclusive. Reported IDs are retained rather than relabeled as CVE-2017-0144. Informational actions use not_applicable with an explicit metadata-only summary when recognized fields are collected; it does not mean the service is secure. A port that is no longer open is not applicable.

The scanner retains eight check jobs in memory across sessions. Results endpoints filter by the latest inventory session. Completed checks do not replace TCP observations; failed/cancelled attempts do not overwrite earlier retained successful jobs. A result can expire through the documented bounded retention or server restart. Nested result snapshots are detached before HTTP use. Shutdown joins workers; recovery polls existing jobs and never launches a new check automatically.

API:

- `GET /api/checks/catalog`: enabled metadata; no execution.
- `POST /api/hosts/:id/checks`: `{"authorized":true,"check_id":"smb-vuln-ms17-010","port":445}`. Port is only a selector into existing compatible open observations, not an arbitrary scan target. Returns HTTP 202 and a status Location.
- `GET /api/checks/:id`: detached execution state and result.
- `POST /api/checks/:id/cancel`: cancel a retained action.
- `GET /api/hosts/:id/checks`: jobs for the current inventory host/session.

All writes reuse CSRF/same-origin protections. Discovery, TCP inspection, SMB listing and NSE checks share one execution slot. The services popup displays compatible actions; opening an action shows its protocol interaction note before Run check. Progress, red cancellation/close buttons, retained assessment badges, CVE links, timestamps, Nmap version and escaped structured evidence are available. Reload resumes status polling; closing a dialog does not implicitly cancel a server job.
