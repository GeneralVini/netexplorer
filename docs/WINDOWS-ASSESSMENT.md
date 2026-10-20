# Windows endpoint assessment

Each inventory card offers **Windows assessment**. Download the fixed read-only
PowerShell collector, execute it locally on the Windows endpoint, and import its
JSON export into the matching card:

```powershell
powershell.exe -NoProfile -File .\collect-windows.ps1 -OutputPath .\windows-inventory.json
```

The collector uses local CIM, registry and component metadata. It does not probe
peers, request credentials, access shares, change execution policy or system
settings. It creates a new output file and refuses to overwrite existing files.
PowerShell 5.1 and CIM cmdlets are required; optional Defender/BitLocker failures
are recorded. Some optional reads need elevation. The collector runs under installed Linux PowerShell with controlled fixture commands.
It has not been executed on a real Windows endpoint in development; validate deployment on a
controlled Windows machine before wider distribution.

## Evidence and results

Exports contain Windows edition, version, build, UBR, product type, service pack,
IPv4 addresses, observed KBs, Spooler state, Point and Print policies, VBScript and
Defender versions, BitLocker protection/encryption state, and collection errors.
No BitLocker recovery passwords or secrets are collected. Get-HotFix is not a
complete update history. The JSON is user-supplied evidence, not an authenticated
attestation; IP binding cannot establish ownership when an address is reassigned.

The initial catalog includes BlueKeep, PrintNightmare, CVE-2018-8174 and the six
named issues in the May 2026 CISC advisory. BlueKeep can report an unaffected
modern client or explicit KB4499164/KB4499175/KB4512506 correction on Windows 7 /
Server 2008 R2 SP1. PrintNightmare flags unsafe policy values independently of its
patch assessment. Other assessments remain inconclusive pending reviewed vendor
component thresholds and product/update supersedence rules. Missing KBs, stopped
Spooler and missing components never produce a clean result. No exploit or remote
vulnerability test is performed by importing a file.

The May advisory's unpatched status and unassigned CVE names are historical.
GreenPlasma and MiniPlasma remain advisory names in this catalog until a current
vendor mapping is reviewed. Automatic MSRC/CSAF synchronization and comprehensive
cumulative-update evaluation are not implemented. Catalog version is included in
reports; all nine entries retain their evidence and references.

## API and boundaries

- `GET /api/windows/collector`: embedded collector attachment.
- `GET /api/hosts/:id/windows`: current inventory's imported report, or null.
- `POST /api/hosts/:id/windows`: schema 1 JSON import; same-origin CSRF protection.

Imports are bounded to 256 KiB, reject unknown fields/multiple documents and
require the selected host's exact canonical IPv4 in the export. Collection must
be within 30 days, allowing five minutes of clock skew. Collection sizes and
strings are bounded. At most eight reports remain in memory; results are hidden
on a new scan and lost on process restart. Import does not acquire the network
execution slot because it performs no network activity. Browser output uses text
nodes, including raw evidence; references come only from the fixed catalog.

## Reviewed sources

- [Microsoft BlueKeep guidance](https://www.microsoft.com/en-us/msrc/blog/2019/05/prevent-a-worm-by-updating-remote-desktop-services-cve-2019-0708/)
- [Microsoft legacy RDP patch table](https://www.microsoft.com/en-us/msrc/blog/2019/11/rdpvulnerabilities)
- [Microsoft PrintNightmare policy guidance](https://support.microsoft.com/help/5005010)
- [Microsoft VBScript advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2018-8174)
- [CISC May 2026 advisory](https://www.gov.br/cisc/pt-br/alertas-de-ciberseguranca/seis-vulnerabilidades-zero-day-no-microsoft-windows)
- [Microsoft CSAF directory](https://msrc.microsoft.com/csaf)

## Manual SSH collection

**Run assessment** appears only for hosts with explicit Windows service/CPE or
validated endpoint evidence. It stages the embedded collector in a unique temporary
folder on an existing Windows SSH peer, executes Windows PowerShell with `-File`
and `-OutputPath`, imports the generated JSON and removes temporary files. Manual
download/import is an optional fallback. The action is disabled without an observed
open SSH port 22. The local `ssh`
client is required; local `pwsh` is used only for development validation. This is
SSH command execution of a fixed read-only collector, not a configured PowerShell
remoting subsystem. Windows PowerShell 5.1 must be available on the Windows peer.

`POST /api/hosts/:id/windows/ssh` accepts only `{"authorized":true,"user":"Administrator"}`.
The host must already have an observed open TCP 22 service compatible with SSH.
The interface and literal remote IPv4 are revalidated, including all local address
exclusions. The action reserves shared network admission; stop monitoring first.
HTTP disconnect/closing the dialog, application shutdown and a 45-second deadline
cancel the SSH process. Stdout is limited to 256 KiB, stderr to 16 KiB.

Only existing public-key authentication is permitted, with strict host-key checking.
Missing or changed host trust fails; host keys are not enrolled or updated. Blank
passwords are not attempted. Client configuration, proxies, forwarding, local
commands, arbitrary scripts, key paths and custom options are not accepted. The
process uses the server account's default identities or existing SSH agent. Configure
and verify access separately with the Windows administrator; the app does not
install SSH, create credentials or alter machine settings.

- [Microsoft Windows SSH sessions](https://github.com/PowerShell/Win32-OpenSSH/wiki/SSH-remote-sessions-on-Windows)
- [Microsoft public-key setup](https://github.com/PowerShell/Win32-OpenSSH/wiki/Setup-public-key-based-authentication-for-windows)
- [OpenSSH options](https://man.openbsd.com/ssh_config.5)
