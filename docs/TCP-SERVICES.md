# TCP services and reference policy

Inspection is manual and targets one existing inventory IP on the currently selected authorized LAN. Local addresses and out-of-subnet peers are excluded again before execution. Profile values are an enum (`common`, `full`); users cannot supply flags, scripts or port expressions.

## Coverage and runtime

Common coverage is TCP 1–1024 plus 1080, 1243, 1433, 1521, 1723, 1883, 2049, 2375–2376, 3306, 3389, 5000–5001, 5357, 5432, 5900–5903, 5985–5986, 6200, 6379, 8000, 8008, 8080–8081, 8443, 8883, 9000, 9090, 9100, 9200, 11211, 12345–12346, 20034, 27017, 27374, 31337 and 54320–54321. This explicit range is not Nmap's frequency-ranked top 1000. Full coverage requests every TCP port from 1 through 65535.

Both use TCP connect scanning and light version detection with T4 timing, no DNS, bounded parallelism and one retry. Host deadlines are two/five minutes; manager deadlines add ten seconds for process completion and cleanup. A failed/timed-out/cancelled job does not replace the last successful result. Coverage describes the requested range, not proof that every port responded. Nmap may summarize closed/filtered ports rather than return individual rows. Printer port 9100 remains excluded from version probes by Nmap's default policy.

`-A` was intentionally not enabled: it bundles OS detection, default scripts and traceroute. TCP inspection does not request default/custom NSE profiles, SMB vulnerability scripts, exploit checks or password attempts. Separate manual NSE actions are described in [NSE integration](NSE-INTEGRATION.md). Nmap may run version-category probes automatically under `-sV`. See [Nmap options](https://nmap.org/book/man-misc-options.html), [timing](https://nmap.org/book/man-performance.html) and [version detection](https://nmap.org/book/man-version-detection.html).

## Presentation and actions

| State | Icon | Color |
| --- | --- | --- |
| Open | ✓ | Green |
| Closed | × | Red |
| Filtered | ◆ | Amber |
| Open or filtered | ◈ | Amber |
| Unfiltered | ○ | Blue |
| Closed or filtered | ⊗ | Amber |
| Unknown | ? | Gray |

The state stays available through a tooltip and accessible name, without visible state text in rows. Cards prioritize open ports and show at most four results. The modal searches arbitrary TCP port numbers, products, services and reference labels, filters states/references and displays at most 50 rows per page. Unknown services remain visible and their endpoint can be copied.

HTTP-like detected services produce literal-IP HTTP links; detected TLS selects HTTPS. Ports 80/443 are defaults only when the detected service is absent/unknown. Filtered web links warn that a connection may fail. Links open only after a user click; the server does not fetch advertised web URLs. RDP files contain the IP/port and prompt for credentials in the external client. NetExplorer stores no credentials.

SMB listing requires explicit authorization and an observed open port 139/445 on the current inventory host. The optional fixed `smbclient -L <IP> -I <IP> -p <port> -N -U % -g` command requests anonymous metadata, requires SMB2 or later, disables Kerberos and restricts interface configuration. It has a ten-second deadline, 256 KiB stdout/16 KiB stderr limits, 256-share result limit and cancellation on request/server shutdown. Only announced disk-share names/comments are shown; hidden/admin shares are omitted. No disk-share connection, content listing, guessed share names, password attempts or mounts occur. Servers requiring authentication return an explanatory result. No fallback to credentials or SMB1 occurs. See the [Samba manual](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html).

## Reviewed references — 2026-10-02

| TCP ports | Historical association | Source |
| --- | --- | --- |
| 12345, 12346 | NetBus | [Nmap service database](https://github.com/nmap/nmap/blob/master/nmap-services) |
| 27374 | SubSeven | [Nmap service database](https://github.com/nmap/nmap/blob/master/nmap-services) |
| 54320 | Back Orifice 2000 | [Nmap service database](https://github.com/nmap/nmap/blob/master/nmap-services) |
| 6200 | Compromised vsftpd distribution | [NVD CVE-2011-2523](https://nvd.nist.gov/vuln/detail/CVE-2011-2523) |

These are historical associations, not a malware detector. Ports are configurable and can be shared by legitimate applications. No malware-specific protocol probes run. Back Orifice's classic 31337 and BO2K's 54321 associations in the referenced database are UDP; they are not labeled as TCP malware findings. Other notable ports remain generic unless reviewed protocol-specific evidence supports a reference. No service database is copied or bundled.

Potential CVEs require an open port with an exact detected product/version match:

- `vsftpd` 2.3.4 → [CVE-2011-2523](https://nvd.nist.gov/vuln/detail/CVE-2011-2523). Only the compromised distribution downloaded June 30–July 3, 2011 was affected; download provenance is unknown.
- `Apache httpd` 2.4.49 → [CVE-2021-41773](https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-41773) and [CVE-2021-42013](https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-42013).
- `Apache httpd` 2.4.50 → [CVE-2021-42013](https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-42013).

This initial offline catalog is limited. Patch/backport status, configuration and banner accuracy are unknown, so every match is explicitly potential. Port 445 or a Windows OS hint alone must never imply a CVE. Versioned products offer a manual NVD search link for broader research; search results are not automated applicability judgments. CPEs are retained as evidence for inspection, without wildcard/range inference. No-match results are not security assessments.

To extend the catalog, research primary/vendor sources, record TCP versus UDP, date and applicability conditions, add conservative product/version rules and negative fixtures, and update this document. Keep offline references separate from explicit active checks. See [the NSE integration plan](NSE-INTEGRATION.md) for the planned manual check workflow.

## API

- `POST /api/hosts/:id/nmap`: `{"authorized":true,"profile":"common"}` or `"full"`; existing device-ID alias is also supported. Returns a cancellable job with its profile.
- `GET /api/hosts/:id/services`: detached port evidence, coverage, observation date and offline references; no network request.
- `POST /api/hosts/:id/shares`: `{"authorized":true,"port":445}`; returns announced public disk-share metadata.

Writes require the existing CSRF token and same-origin policy. Discovery, TCP inspection, SMB listing and explicit NSE checks share one network slot. Optional tools are discovered through PATH and are never installed by the application.

## Continuous discovery and automatic TCP

The scan form supports **Keep discovering** with a minimum interval of 10–3600
seconds (30 by default). Discovery windows run sequentially, each with its own
existing deadline. A slow window delays the next start; windows do not overlap.
The session accumulates host and logical-device evidence rather than removing
peers absent from a later response. Window SSE notifications include new and total
host counts. Reloading the page resumes the same retained monitor without starting
another network action. **Stop** cancels discovery and any automatic inspection.

**Auto TCP** is selectable in the form and covered by the scan authorization. Two bounded workers
process queued new inventory peers and use only the fixed **common + notable** profile.
There is no automatic NSE vulnerability check. Previously enriched hosts are
skipped; each IP is attempted at most once per session, including failed attempts.
A manual inspection can retry after monitoring is stopped. Provider scope checks
still exclude local addresses and reject out-of-subnet targets. Automatic TCP
requires an IPv4 /22 or narrower subnet.

The monitor reserves shared network admission. It permits one discovery pass and
at most two TCP inspections concurrently; other manual network actions require stopping
monitoring first. Long-running inventory is bounded to 1024 hosts, 2048 device
identities, 64 deduplicated notes and the existing 512-event journal. Hosts remain
historical observations, not a claim that every retained peer is currently online.
A new scan starts a new inventory and deduplication session.

Manual and automatic Nmap completion expose **Go to host**, which reveals the card
through active filters and pagination. The check popup displays a prominent
vulnerable/non-vulnerable/inconclusive/information verdict from the existing
structured adapter. A timeout, missing evidence or connection error never becomes
a non-vulnerable verdict.

The form enables Auto TCP by default when Nmap is available; explicit scan
authorization still applies. Session progress includes scheduled, completed,
failed/cancelled and active peers. Cards show queued/running/completed/failed
inspection status. Cancellation marks remaining queued peers as cancelled.
Discovery phases emit UTC deadlines so the browser can draw a countdown and
progress meter, recover after reload, and distinguish discovery, host discovery,
waiting and final TCP work. A concise round badge highlights new hosts.

OS badges prefer collected Windows inventory, then Nmap service `ostype` and OS
CPE evidence. Conflicting families display an uncertain verdict. Response TTL is
retained when Nmap provides it: values near 128 or 64 produce only tentative
Windows/Unix-like hints. A TTL guess never enables Windows assessment. TCP connect
and ARP discovery often provide no response TTL; no extra ping, privilege elevation
or unrestricted OS/NSE scan is started automatically. See [Nmap XML metadata](https://nmap.org/book/output-formats-xml-output.html)
and [fingerprinting methods](https://nmap.org/book/osdetect-methods.html).

Scan notes suppress routine cancellation and deduplicate displayed messages after
normalization. Missing interfaces have an actionable reconnect/reselect message;
SSDP resolves the selected interface by name on each discovery window so a changed
interface index after reconnect does not select an obsolete interface.

Manual SMB/check dialogs expose an explicit **Stop discovery & run** action when
monitoring owns network admission. This cancels discovery, waits for its terminal
state and then sends the authorized manual request; it never silently starts NSE.
Folder listing displays activity and elapsed time, with **Cancel request** aborting
the HTTP request and its context-bound subprocess. Checks display activity, elapsed
time and their 60-second manager limit, with sticky cancellation controls. Polling
has an 8-second HTTP timeout and retries without treating a lost connection as a
completed check. Indeterminate meters indicate activity, not measured percentages.

HTTP endpoints are direct links in card port rows and the service dialog, opening
in a new tab. RDP endpoints download a connection file for a local RDP client;
RDP is not an HTTP website. Filtered endpoints may fail to connect.

## ARP discovery and startup diagnostics

Every application startup checks `arp-scan` availability and performs a bounded,
non-network `--version` probe. The home page's **ARP** disclosure and
`GET /api/tools/arp` report installed/missing/version-check failure independently
of raw-socket permission. `doctor` also prints the result. Missing tools show
installation instructions based on the OS and Linux `/etc/os-release` ID/ID_LIKE:
APT, DNF, Pacman, Zypper, APK, or Homebrew. Unknown systems receive upstream/package
manager guidance; native Windows support is unavailable. No package installation,
capability grant, sudo invocation or global configuration change is automatic.

Authorized **Other LAN hosts** discovery runs ARP alongside Nmap/ICMP, within the
same window deadline. ARP has a 15-second limit, two attempts, a 5ms send interval,
fixed interface and tab-separated output, 2MiB stdout/16KiB stderr limits and
context cancellation. Explicit validated remote addresses replace `--localnet`
to exclude every local alias, network/broadcast addresses and targets beyond the
selected /22-or-narrower subnet. ARP vendor inputs use the null device. The normal application process performs
offline registry lookup, using its updated base or fixed system fallbacks.
The Linux paths are `/usr/share/arp-scan/ieee-oui.txt` and
`/etc/arp-scan/mac-vendor.txt` (the extension is `.txt`, not `.tx`).

ARP IP/MAC/vendor records merge with other live observations by IP; ARP registry
vendor labels take precedence during the same discovery pass. Duplicate identical
responses are ignored; conflicting MAC responses produce a warning. Locally
administered MACs retain the observed address but have no inferred registry vendor.
ARP vendor identifies a network interface registrant, not a verified device brand
or operating system. No ARP fingerprinting or OS inference from vendor is added.
Successful discovery queues new hosts for Auto TCP using the existing per-session
deduplication. ARP can discover hosts without Nmap installed, but TCP inspection
continues to require Nmap. ARP permission failures preserve other inventory and
show a warning; administrators must separately authorize raw-socket access.

Package references: [Ubuntu](https://packages.ubuntu.com/arp-scan),
[Fedora](https://packages.fedoraproject.org/pkgs/arp-scan/arp-scan/),
[Arch](https://archlinux.org/packages/extra/x86_64/arp-scan/),
[Homebrew](https://formulae.brew.sh/formula/arp-scan),
and [upstream](https://github.com/royhills/arp-scan).

## Dedicated Linux account and restricted sudo helper

Run `make setup` during initial Linux installation (or `make setup INTERFACE=eth0`).
The setup first checks runtime tools and installs missing Nmap, arp-scan, smbclient
and OpenSSH client packages from configured distribution repositories.
`make setup-tools-check` previews the tool stage without modifying the machine.
The idempotent setup provisions and verifies a dedicated
`netexplorer` system account (locked password, `nologin` shell, home
`/var/lib/netexplorer`). The server binary is root-owned in `/opt/netexplorer`;
the account cannot replace it or the root-owned ARP helper in
`/usr/local/libexec/netexplorer-arp`. No password/key credentials are copied from
the developer account. Windows SSH collection needs keys and trusted identities
provisioned separately for this account.

This host's reviewed `/etc/sudoers.d/netexplorer` policy grants only:

```sudoers
netexplorer ALL=(root) NOPASSWD: /usr/local/libexec/netexplorer-arp wlx78bdbc5e68fd
```

The helper accepts exactly one interface name, requires elevated execution,
re-enumerates current local interfaces and excludes every local IPv4 address. It
restricts discovery to an active /22–/30 LAN, generates fixed ARP arguments and
null vendor files, and enforces a 15-second deadline. No shell, arbitrary
executable, flags, target list, packet spoofing or user file path is accepted.
Changing the allowed interface requires an administrator-reviewed sudoers update.

`NETEXPLORER_ARP_SUDO_HELPER=1` explicitly selects the fixed `sudo -n` helper
invocation. Password prompts are disabled, SIGTERM cancellation is forwarded, and
the helper independently enforces its timeout. Default development mode still
executes arp-scan directly without sudo. Use the dedicated account after stopping
any existing server on the same port:

```sh
make run-app
# Optional listener for a separate instance:
make run-app ARGS='--listen 127.0.0.1:18084'
```

`run-app` builds and updates the two root-owned installed binaries through the
administrator, then launches only the server as the dedicated user. Account creation, locked password, nologin shell, private data directories and
restricted sudoers provisioning belong to the explicit initial `make setup` step. `make run` now selects the dedicated account by default. `make run-dev`
retains direct development mode under the current user. `make install-app` updates installed binaries without
starting the server. The repository remains in the developer workspace and is
not made accessible to the service account.

To revoke elevated ARP permission, an administrator removes only the dedicated
sudoers drop-in and validates with `visudo -c`. Disabling the opt-in environment
variable returns to direct execution/fallback. Account/helper removal should be
performed separately after stopping its processes and preserving wanted data.

See [MAC registry maintenance](MAC-VENDORS.md) for periodic updates, private MAC classification and complementary mDNS identity hints.
