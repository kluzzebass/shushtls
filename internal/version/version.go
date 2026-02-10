// Package version holds the application version, set at build time.
// Build with: go build -ldflags "-X shushtls/internal/version.Version=v1.0.0"
package version

// Version is the application version. Defaults to "dev" when not set via ldflags.
var Version = "dev"
