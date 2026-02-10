# Future Me: ShushTLS maintenance

For the person (possibly you, years later) who needs to operate or modify this system without remembering how it works.

## Where state lives

- **Default:** Platform config directory, e.g.  
  - Linux: `~/.config/shushtls` (or `$XDG_CONFIG_HOME/shushtls`)  
  - macOS: `~/Library/Application Support/shushtls`  
  - Windows: `%AppData%\shushtls`  
- **Override:** Run with `-state-dir /path/to/dir` to use another directory.

Layout under the state directory:

```
<stateDir>/
  ca/
    ca-key.pem      # Root CA private key (keep secret)
    ca-cert.pem     # Root CA certificate (this is what you install on devices)
  certs/
    <sanitized-SAN>/   # One dir per issued cert, e.g. nas.home.arpa or _wildcard_.home.arpa
      key.pem
      cert.pem
  service-host       # Text file: primary SAN of the cert used for ShushTLS’s own HTTPS
  auth.json          # Optional; present if auth was ever enabled (credentials / enabled flag)
  shushtls.lock      # Lock file while the server is running; removed on exit
```

Do not run two ShushTLS instances with the same state directory. The lock file prevents that; the second process will exit with an error.

## Regenerating or re-issuing certificates

- **Leaf certs (services like NAS, apps):** Use the web UI or `POST /api/certificates` with `{"dns_names": ["host.example.com"]}`. If a cert for that primary name already exists, the same cert is returned (idempotent). To get a *new* cert for the same name you’d need to remove the existing cert directory under `certs/` and then issue again (not exposed in the UI; for power users only).
- **ShushTLS’s own HTTPS cert (service cert):** Initialized at setup. You can issue another cert (e.g. with different SANs) from the UI and then choose “Use as service” so that cert is used for the ShushTLS UI/API. No restart; the server picks it up via `GetCertificate`.
- **Root CA:** Generated once at initialization. There is no in-app “regenerate root” flow. Replacing the root would mean replacing the `ca/` directory and re-trusting on every device; effectively “start over” with a new state dir or a backup.

## Adding a new device to trust

On the new device, you need to install the **root CA** (`ca/ca-cert.pem` or the PEM downloaded from the UI). The UI offers platform-specific install scripts (e.g. curl-to-bash for macOS/Linux, PowerShell for Windows) that download the root and add it to the system trust store. Run that script on the new device, or manually copy `ca-cert.pem` and add it to the device’s trust store. No need to touch ShushTLS’s state directory.

## If a certificate expires

- **Leaf certs:** Current validity is 200 days (aligned with browser rules). Before expiry, issue a new cert (same or updated DNS names) and deploy it to the service. The UI lists certs and their validity; use that to plan.
- **Root CA:** Default validity is 25 years. If it’s approaching expiry (in the distant future), there is no in-app rotation. You’d generate a new root (e.g. new state dir or manual replacement of `ca/`) and re-install trust on all devices. Plan ahead.

## Rebuilding the binary

- **Build:** `just build` (or `go build -o shushtls .`). Produces a single binary `shushtls`.
- **Test:** `just test` (or `go test ./...`).
- **Run:** `just run` or `./shushtls` with optional flags.

Dependencies are in `go.mod` / `go.sum`. No vendoring. Requires a Go toolchain (version in `go.mod`).

## If something breaks

- **“Another ShushTLS instance is already using …”**  
  Another process is using that state directory, or a previous run exited without releasing the lock. Ensure no other `shushtls` (or `go run` child) is running. If you’re sure nothing is using it, remove `shushtls.lock` in the state directory and try again.
- **“Cannot create state directory” / permission errors**  
  The state path must be writable. Check permissions and that the path isn’t a file. On Linux, `~/.config/shushtls` is typical; create it with the right owner if needed.
- **Browsers still don’t trust my certs**  
  The device must trust the **root** CA. Re-run the install script for that OS, or manually add `ca/ca-cert.pem` to the system/browser trust store. Clearing the browser cache for the site can help after adding trust.
