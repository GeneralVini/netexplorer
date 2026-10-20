GO ?= go
GOFMT ?= gofmt
VERSION := $(shell cat VERSION)
GOFILES := $(shell find cmd internal -name '*.go')
TOOLS_DIR := $(CURDIR)/build/devtools
STATICCHECK := $(TOOLS_DIR)/staticcheck
GOSEC := $(TOOLS_DIR)/gosec
GOVULNCHECK := $(TOOLS_DIR)/govulncheck
TOOLS_DEPS := devtools/go.mod devtools/go.sum

.PHONY: build run run-dev test vet fmt fmt-check lint sast vuln security security-report check doctor clean rtk-check tools
build:
	$(GO) build -ldflags '-X main.version=$(VERSION)' -o bin/netexplorer ./cmd/netexplorer
	$(GO) build -o bin/netexplorer-arp ./cmd/netexplorer-arp
run: run-app
run-dev:
	$(GO) run ./cmd/netexplorer serve $(ARGS)
test:
	$(GO) test ./...
vet:
	$(GO) vet ./...
fmt:
	$(GOFMT) -w $(GOFILES)
fmt-check:
	@test -z "$$($(GOFMT) -l $(GOFILES))" || { echo 'Run make fmt'; exit 1; }
check: fmt-check vet lint security test
lint: $(STATICCHECK)
	$(STATICCHECK) ./...
sast: $(GOSEC)
	$(GOSEC) ./...
vuln: $(GOVULNCHECK)
	$(GOVULNCHECK) ./...
security: sast vuln
security-report: $(GOSEC)
	mkdir -p build/security
	$(GOSEC) -fmt sarif -out build/security/gosec.sarif ./...
tools: $(STATICCHECK) $(GOSEC) $(GOVULNCHECK)
$(STATICCHECK): $(TOOLS_DEPS)
	mkdir -p $(TOOLS_DIR)
	$(GO) -C devtools build -o $@ honnef.co/go/tools/cmd/staticcheck
$(GOSEC): $(TOOLS_DEPS)
	mkdir -p $(TOOLS_DIR)
	$(GO) -C devtools build -o $@ github.com/securego/gosec/v2/cmd/gosec
$(GOVULNCHECK): $(TOOLS_DEPS)
	mkdir -p $(TOOLS_DIR)
	$(GO) -C devtools build -o $@ golang.org/x/vuln/cmd/govulncheck
doctor:
	$(GO) run ./cmd/netexplorer doctor $(ARGS)
clean:
	rm -rf bin build
rtk-check:
	rtk --version
	rtk gain

# Run the installed application as its dedicated account; only ARP can use sudo.
.PHONY: setup setup-tools-check run-app install-app
setup-tools-check:
	/bin/sh scripts/setup-tools-linux.sh --dry-run
# Account provisioning is an explicit initial administrative step.
setup: build
	sudo /bin/sh scripts/setup-linux.sh "$(INTERFACE)"
install-app: build
	sudo install -o root -g root -m 0755 bin/netexplorer /opt/netexplorer/netexplorer
	sudo install -o root -g root -m 0755 bin/netexplorer-arp /usr/local/libexec/netexplorer-arp
run-app: install-app
	sudo -H -u netexplorer env --chdir=/var/lib/netexplorer NETEXPLORER_ARP_SUDO_HELPER=1 /opt/netexplorer/netexplorer serve $(ARGS)
