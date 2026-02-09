package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"shushtls/internal/server"
)

func main() {
	var (
		stateDir     = flag.String("state-dir", "./state", "directory for persistent state")
		httpAddr     = flag.String("http-addr", ":8080", "HTTP listen address (setup mode)")
		httpsAddr    = flag.String("https-addr", ":8443", "HTTPS listen address (normal mode)")
		serviceHosts = flag.String("service-hosts", "shushtls.local,localhost", "comma-separated DNS names for ShushTLS's own cert")
	)
	flag.Parse()

	cfg := server.Config{
		StateDir:     *stateDir,
		HTTPAddr:     *httpAddr,
		HTTPSAddr:    *httpsAddr,
		ServiceHosts: splitHosts(*serviceHosts),
	}

	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(cfg server.Config) error {
	srv, err := server.New(cfg)
	if err != nil {
		return err
	}
	return srv.Run(context.Background())
}

// splitHosts splits a comma-separated host list, trimming whitespace.
func splitHosts(s string) []string {
	var hosts []string
	for _, h := range strings.Split(s, ",") {
		h = strings.TrimSpace(h)
		if h != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts
}
