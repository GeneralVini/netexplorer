# Development

Install Go from https://go.dev/dl/. On this machine, Go is installed in /usr/local/go; /usr/local/bin/go and /usr/local/bin/gofmt make the commands available through PATH. The Makefile uses the system Go installation.

Available targets: `make build`, `make run`, `make doctor`, `make fmt`, `make test`, `make vet`, `make check`, and `make clean`. Pass CLI flags with `ARGS`. `make rtk-check` only checks RTK. Staticcheck, gosec, and govulncheck are project-pinned; Make builds them from devtools into build/devtools without a global installation. For debugging, run the binary in the foreground and inspect slog output.

Nmap is optional and currently only located through PATH. RTK reduces development output; see [RTK](../RTK.md). There is no Node build pipeline. Gin and golang.org/x/net are pinned in go.mod.

## Code documentation

Write documentation and code comments in English. Follow the official [Go doc comment conventions](https://go.dev/doc/comment): place a comment immediately before a declaration, start symbol comments with the symbol name, and use complete sentences. Document every package and exported type, function, constant, and relevant field. Explain non-obvious internal contracts and decisions without repeating the implementation.

Go comments describe parameters and results in prose; do not use PHPDoc tags such as @param or @return. Describe validation errors, cancellation, partial results, side effects, and resource ownership when relevant. Package comments start with “Package name”; command documentation describes the command itself.

```go
// Discover locates executable names through PATH without running them.
// The returned entries preserve the order of names, including unavailable tools.
func Discover(names ...string) []Info
```

Read the generated documentation locally:

```sh
go doc ./internal/discovery/ssdp
go doc ./internal/discovery/ssdp.Discover
go doc -all ./internal/discovery/network
```

## Reproducible analysis tools

Run make tools to build all pinned tools, or use make lint, make sast, and make vuln to build and execute individual tools. Versions and checksums are in devtools/go.mod/go.sum. Their dependency graph is separate from the runtime module. make check includes all three tools; make security-report generates SARIF. See [SAST](SAST.md) for versions, updates, CI, and troubleshooting.
