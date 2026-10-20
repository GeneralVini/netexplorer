// Command netexplorer-arp exposes only validated local ARP discovery to sudo policy.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"netexplorer/internal/discovery/network"
	"netexplorer/internal/enrichment/nmap"
)

func main() {
	if len(os.Args) != 2 || os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "one LAN interface argument and elevated execution are required")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	interfaces, err := network.List()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	selected, err := network.Select(interfaces, os.Args[1], "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	hosts, err := nmap.New().ARPOnly(ctx, selected)
	for _, host := range hosts {
		fmt.Printf("%s\t%s\t%s\n", host.IP, host.MAC, host.Vendor)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
