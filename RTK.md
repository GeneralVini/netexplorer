# RTK — Rust Token Killer

Official RTK repository: https://github.com/rtk-ai/rtk. RTK reduces development output and token usage; it is never a dependency of the NetExplorer executable.

## Verification

```sh
command -v rtk
which rtk
rtk --version
rtk gain
```

`rtk gain` checks the expected Rust Token Killer interface and reports token savings. During initialization, RTK 0.50.0 was located at /home/dexter/.local/bin/rtk and gain succeeded. Statistics are global, not exclusive to this project.

## Local integration

`rtk init --codex --dry-run` and `rtk -v init --codex --dry-run` were executed. The preview proposed RTK.md, a reference in AGENTS.md, and .codex/hooks.json. Integration was applied manually according to the preview, preserving the user's global reference and project rules. No global files were changed.

This version rejects `rtk init --codex --no-patch`; do not combine these options. For future changes, inspect the dry-run and merge carefully. The local hook is configured; automatic execution depends on the Codex client's support and has not been verified in this session.

When needed, use explicit commands: `rtk go test ./...`, `rtk git status`, and `rtk git diff`. Ensure Go is on PATH. Treat condensed output as complete; if unexpectedly empty, contradictory, or unreadable, retry with `rtk proxy <command>`.

To disable integration temporarily, remove only the RTK PreToolUse entry from .codex/hooks.json, preserving other hooks. Back up before editing. Normal commands remain available outside the hook.

If RTK is missing, follow installation instructions in the official repository, review the installation destination, and verify the commands above. Do not install or configure it globally automatically. `make rtk-check` only verifies RTK; it never installs it.

If the hook fails, check PATH, `rtk hook --help`, and the hooks JSON. The legacy tee configuration warning was left unchanged; no global recall migration was performed.

In this version, `rtk init --show` reports Claude-focused diagnostics and does not confirm the local Codex hook. Validate the local JSON and references directly.

## Security analysis output

Security analysis uses Make targets and the pinned build/devtools executables. Do not assume RTK has dedicated wrappers for these analyzers. Keep full diagnostics when investigating findings; use normal commands or rtk proxy when necessary. RTK remains optional and does not affect the executable or security gate.
