# Future Semgrep rules

Semgrep is optional and is not part of the current gate. Add and validate rules with positive and negative fixtures before enabling them.

Planned policy: prohibit shell command strings through exec.Command or exec.CommandContext, including sh/bash/dash with -c and platform equivalents. Require context-aware subprocesses with validated explicit arguments. Do not rely on a narrow literal-shell rule alone to prove safety.

With UPnP description enrichment implemented, URLs advertised through SSDP/UPnP must be fetched through the central internal/security/safehttp component. Direct http.Get calls for discovered URLs will violate that policy. The component exists in Phase 3 and is used by description enrichment. Future service actions must also use and test its policy.

No unvalidated rule or mandatory Semgrep installation is added at this stage.
