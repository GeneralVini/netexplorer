// NetExplorer provides LAN discovery, diagnostics, and a local HTTP interface.
// Network discovery is performed only by an explicit scan command.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"netexplorer/internal/config"
	"netexplorer/internal/discovery/network"
	"netexplorer/internal/enrichment/macvendor"
	"netexplorer/internal/scanner"
	"netexplorer/internal/tools"
	"netexplorer/internal/web"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

// version identifies the build and can be set by the Makefile linker flags.
var version = "0.1.0-dev"

// main connects operating system signals to cancellation and reports command failures.
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		slog.Error("command failed", "error", err)
		os.Exit(1)
	}
}

// run dispatches CLI arguments and writes user output and flag diagnostics to
// the supplied writers. The serve command blocks until cancellation or a server
// failure, then attempts a bounded graceful shutdown. Help is successful.
func run(ctx context.Context, args []string, out, errOut io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(out, "Usage: netexplorer <serve|scan|doctor|version> [--interface NAME] [--listen ADDRESS]\nscan: [--interface NAME] [--timeout 5s] [--enrich] [--all-hosts]")
		return nil
	}
	command := args[0]
	if command == "version" {
		if len(args) != 1 {
			return fmt.Errorf("version does not accept arguments")
		}
		fmt.Fprintln(out, "NetExplorer", version)
		return nil
	}
	if command == "scan" {
		return runScan(ctx, args[1:], out, errOut)
	}
	if command != "serve" && command != "doctor" {
		return fmt.Errorf("unknown command %q", command)
	}
	cfg, err := config.Parse(args[1:], errOut)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	items, err := network.List()
	if err != nil {
		return err
	}
	preferred, _ := network.DefaultRoute()
	selected, selectErr := network.Select(items, cfg.Interface, preferred)
	if command == "doctor" {
		fmt.Fprintln(out, "NetExplorer diagnostics\n\nNetwork")
		if selectErr != nil {
			fmt.Fprintln(out, "[--]", selectErr)
		} else {
			fmt.Fprintf(out, "[OK] Interface: %s\n[OK] IPv4: %v\n", selected.Name, selected.IPv4)
			if selected.Gateway != "" {
				fmt.Fprintln(out, "[OK] Gateway:", selected.Gateway)
			} else {
				fmt.Fprintln(out, "[--] Gateway unavailable (Linux /proc route detection)")
			}
			fmt.Fprintf(out, "[INFO] Multicast supported: %t\n", selected.Multicast)
		}
		fmt.Fprintln(out, "\nNative capabilities\n[OK] HTTP / JSON\n[OK] SSDP implementation (not a connectivity test)\n[OK] UPnP description parsing / safe HTTP implementation\n\nOptional runtime tools")
		printTools(out, tools.Discover("nmap", "arp-scan", "smbclient", "ssh"))
		arp := tools.InspectARP(ctx)
		fmt.Fprintln(out, "ARP:", arp.Status, arp.Version)
		if !arp.Available {
			fmt.Fprintln(out, "Install:", arp.Install)
		}
		fmt.Fprintln(out, "\nDiagnostic reference tools")
		printTools(out, tools.Discover("showmount", "pwsh", "gssdp-discover", "gupnp-av-cp"))
		fmt.Fprintln(out, "\nDevelopment\n[OK] Build toolchain:", runtime.Version())
		printTools(out, tools.Discover("go", "rtk"))
		return selectErr
	}
	if selectErr != nil {
		return selectErr
	}
	go macvendor.Default.Run(ctx)
	manager := scanner.NewManager(ctx, nil)
	defer manager.Close()
	server := &http.Server{Addr: cfg.Listen, Handler: web.Router(version, network.List, web.Options{Context: ctx, Manager: manager, DefaultInterface: selected.Name, Listen: cfg.Listen}), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	slog.Info("HTTP server started", "listen", cfg.Listen, "interface", selected.Name)
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return errors.Join(err, server.Close())
		}
		err := <-done
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// printTools renders lookup availability without executing the listed tools.
func printTools(out io.Writer, items []tools.Info) {
	for _, item := range items {
		if item.Available {
			fmt.Fprintf(out, "[OK] %s: %s\n", item.Name, item.Path)
		} else {
			fmt.Fprintf(out, "[--] %s unavailable\n", item.Name)
		}
	}
}
