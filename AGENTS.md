@~/.codex/RTK.md

# NetExplorer agent instructions

- Preserve user files and instructions. Never overwrite this file during integration.
- Go core packages must not import Gin; Gin belongs only in internal/web.
- Use standard library where practical, small functions, and comments explaining decisions.
- Write project documentation and code comments in English. Use Go doc comments for packages, exported declarations, fields, and relevant internal contracts.
- Use context cancellation, bounded concurrency, timeouts and slog.
- No password attempts or private-share access. Network actions require an authorized LAN. Reviewed vulnerability checks must be explicit, manual actions scoped to known inventory hosts; do not run exploits or denial-of-service tests.
- Subprocesses use exec.CommandContext with validated arguments; never use a shell for user input.
- Do not alter global settings, install global hooks, or commit without explicit instruction.
- RTK is development tooling, never a runtime dependency. Inspect dry-run before local integration.
- Run make fmt, make check and make build before concluding changes. Run staticcheck if installed.
- Tests use controlled fixtures and must not depend on the current LAN.
- Important directories: cmd/netexplorer, internal/config, internal/discovery/network, internal/tools, internal/web, docs.
- Create future protocol packages only when needed. Preserve ini.txt as the original specification.

@RTK.md

## Security validation

- Run make check for relevant changes and make build before completion.
- For HTTP, SSDP, UPnP, XML, subprocesses, Nmap, files, and authentication changes, review gosec findings and security regression tests carefully.
- Analysis tools are pinned in devtools/go.mod; use Make targets to analyze the main application module.
- Never suppress findings solely to make CI pass. Narrow exceptions need the rule ID, context, and justification.
- Report unavailable tools/database access separately from source findings. CodeQL configuration is not evidence of a completed remote scan.
