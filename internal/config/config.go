// Package config parses server and diagnostic settings from flags and environment variables.
package config

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
)

// Config holds the HTTP listener and network interface settings.
type Config struct {
	// Listen is the explicit host:port address used by the HTTP server.
	Listen string
	// Interface names the network interface; an empty value requests automatic selection.
	Interface string
}

// Parse applies command-line flags over environment variables and defaults.
// It writes flag diagnostics to output and rejects positional arguments and invalid
// listener addresses. Help requests return flag.ErrHelp.
func Parse(args []string, output io.Writer) (Config, error) {
	c := Config{Listen: "127.0.0.1:8080", Interface: os.Getenv("NETEXPLORER_INTERFACE")}
	if v := os.Getenv("NETEXPLORER_LISTEN"); v != "" {
		c.Listen = v
	}
	fs := flag.NewFlagSet("netexplorer", flag.ContinueOnError)
	fs.SetOutput(output)
	fs.StringVar(&c.Listen, "listen", c.Listen, "HTTP listen address")
	fs.StringVar(&c.Interface, "interface", c.Interface, "network interface (automatic when empty)")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if fs.NArg() != 0 {
		return c, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil || host == "" || port == "" {
		return c, fmt.Errorf("invalid listen address: %q", c.Listen)
	}
	p, err := net.LookupPort("tcp", port)
	if err != nil || p < 1 || p > 65535 {
		return c, fmt.Errorf("invalid listen port: %q", port)
	}
	return c, nil
}
