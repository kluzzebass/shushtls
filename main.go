package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"shushtls/internal/server"
	"shushtls/internal/version"
)

func main() {
	var (
		showVersion  = flag.Bool("version", false, "print version and exit")
		stateDir     = flag.String("state-dir", server.DefaultStateDir(), "directory for persistent state")
		httpAddr     = flag.String("http-addr", ":8080", "HTTP listen address (setup mode)")
		httpsAddr    = flag.String("https-addr", ":8443", "HTTPS listen address (normal mode)")
		serviceHosts = flag.String("service-hosts", "shushtls.local,localhost", "comma-separated DNS names for ShushTLS's own cert")
		noTLS        = flag.Bool("no-tls", false, "disable HTTPS; serve app over HTTP only (e.g. behind a reverse proxy)")
	)
	flag.Parse()

	// Env vars override flag defaults (e.g. for Docker). SHUSHTLS_NO_TLS is truthy (1, true, yes, on).
	noTLSVal := *noTLS || isEnvTruthy("SHUSHTLS_NO_TLS")
	stateDirVal := envOrFlag("SHUSHTLS_STATE_DIR", *stateDir)
	httpAddrVal := envOrFlag("SHUSHTLS_HTTP_ADDR", *httpAddr)
	httpsAddrVal := envOrFlag("SHUSHTLS_HTTPS_ADDR", *httpsAddr)
	serviceHostsVal := envOrFlag("SHUSHTLS_SERVICE_HOSTS", *serviceHosts)

	if *showVersion {
		fmt.Println(version.Version)
		os.Exit(0)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg := server.Config{
		Logger:       logger,
		StateDir:     stateDirVal,
		HTTPAddr:     httpAddrVal,
		HTTPSAddr:    httpsAddrVal,
		ServiceHosts: splitHosts(serviceHostsVal),
		NoTLS:        noTLSVal,
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

// envOrFlag returns the env var value if set, otherwise the flag default.
func envOrFlag(envKey, flagVal string) string {
	if v := strings.TrimSpace(os.Getenv(envKey)); v != "" {
		return v
	}
	return flagVal
}

// isEnvTruthy returns true if the environment variable is set to a truthy
// value (1, true, yes, on), case-insensitive. Used for SHUSHTLS_NO_TLS in Docker.
func isEnvTruthy(name string) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	return v == "1" || v == "true" || v == "yes" || v == "on"
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
