# Contributing

Create a branch per change and small commits with descriptive messages. Preserve existing changes. Use idiomatic Go, keep Gin in the web layer, and update documentation alongside behavior.

Write documentation and code comments in English. Use Go doc comments for packages, exported declarations, and relevant internal contracts; see [Development](docs/DEVELOPMENT.md).

Before proposing changes, run `make fmt`, `make check`, `make build`, and staticcheck when available. Automated tests must use fixtures and must not depend on a real LAN. Network changes must follow docs/SECURITY.md. Do not include credentials, personal data, or aggressive scans.
