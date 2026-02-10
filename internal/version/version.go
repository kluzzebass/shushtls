// Package version holds application version and about info, set at build time.
// Build with: go build -ldflags "-X shushtls/internal/version.Version=v1.0.0 -X shushtls/internal/version.RepoURL=... -X shushtls/internal/version.Author=..."
package version

// Version is the application version. Defaults to "dev" when not set via ldflags.
var Version = "dev"

// RepoURL is the source code repository URL. Change this or override with ldflags.
var RepoURL = "https://github.com/kluzzebass/shushtls"

// Author is the author or copyright holder name shown on the About page. Optional.
var Author = ""

// Copyright is the copyright notice shown on the About page. Override with ldflags if needed.
var Copyright = "Copyright (c) 2026 Jan Fredrik Leversund"
