package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"netexplorer/internal/discovery/network"
	"netexplorer/internal/discovery/ssdp"
	"netexplorer/internal/scanner"
	"netexplorer/internal/security/safehttp"
	"os"
	"time"
)

// runScan parses scan options, selects the LAN interface, and writes SSDP JSON to out.
// It honors NETEXPLORER_INTERFACE, validates the discovery window, and treats
// help as success. Collection errors still emit any partial evidence before
// returning the error; output failures take precedence over collection failures.
// With --enrich it instead emits a device/warning report, using safe HTTP and a
// thirty-second enrichment window. Without the flag, no description is fetched.
func runScan(ctx context.Context, args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(errOut)
	name := fs.String("interface", os.Getenv("NETEXPLORER_INTERFACE"), "authorized LAN interface (automatic when empty)")
	allHosts := fs.Bool("all-hosts", false, "also discover responding LAN hosts using optional ARP/Nmap and ICMP (no port scan)")
	enrich := fs.Bool("enrich", false, "fetch safe UPnP descriptions and output a device report")
	duration := fs.Duration("timeout", 5*time.Second, "SSDP discovery window (1s to 1m)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected scan arguments: %v", fs.Args())
	}
	if *duration < time.Second || *duration > time.Minute {
		return fmt.Errorf("scan timeout must be between 1s and 1m")
	}
	items, err := network.List()
	if err != nil {
		return err
	}
	preferred, _ := network.DefaultRoute()
	selected, err := network.Select(items, *name, preferred)
	if err != nil {
		return err
	}
	if *allHosts {
		return runHostScan(ctx, selected, *duration, *enrich, out)
	}
	results, scanErr := ssdp.Discover(ctx, selected, *duration)
	// Keep any evidence collected before cancellation or another scan error.
	if results == nil {
		results = []ssdp.Response{}
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	var output any = results
	if *enrich {
		client, err := safehttp.New(selected.IPv4[0])
		if err != nil {
			return err
		}
		enrichmentCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		report, err := scanner.Enrich(enrichmentCtx, results, client)
		cancel()
		output = report
		scanErr = errors.Join(scanErr, err)
	}
	if err := encoder.Encode(output); err != nil {
		return err
	}
	return scanErr
}

// runHostScan uses the browser coordinator for identical bounds and host provenance.
func runHostScan(ctx context.Context, selected network.Interface, duration time.Duration, enrich bool, out io.Writer) error {
	manager := scanner.NewManager(ctx, nil)
	defer manager.Close()
	id, err := manager.StartWithOptions(selected, duration, scanner.ScanOptions{Enrich: enrich, AllHosts: true})
	if err != nil {
		return err
	}
	for {
		_, notify, done, _, ok := manager.Events(id, 0)
		if !ok {
			return fmt.Errorf("scan session expired")
		}
		if done {
			state, _ := manager.State(id)
			encoder := json.NewEncoder(out)
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(state.Report); err != nil {
				return err
			}
			if state.Error != "" {
				return fmt.Errorf("scan failed: %s", state.Error)
			}
			return nil
		}
		<-notify
	}
}
