# ShushTLS

A small, local-first PKI for your home or lab: run it on one machine, issue TLS certificates for your services, and install its root CA on your devices so browsers stop complaining. No public CAs, no cloud, no account.

## Philosophy

- **You own the CA.** The root certificate is generated on your machine and never leaves your control. Trust is established by installing that root on each device (laptop, phone, TV) that should trust your certs.
- **LAN trust model.** ShushTLS assumes a trusted local network. The web UI and API are not locked down by default; optional HTTP Basic Auth is available if you want it. It does not try to be a hardened internet-facing service.
- **No restart after setup.** Start the server, open the UI, initialize (root CA + service cert are created), install the root CA on your devices—HTTPS turns on automatically. No process restart.

## Quick start

```bash
just build
just run
```

Open the URL shown in the log (e.g. `http://localhost:8080`). Click through setup to initialize. Then install the root CA on each device that will use your certs (macOS, Linux, Windows install scripts are in the web UI under Install CA). After that, the server is available over HTTPS and HTTP redirects to it.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-state-dir` | platform config dir (see [State directory](#state-directory)) | Where CA and issued certs are stored |
| `-http-addr` | `:8080` | HTTP listen address (setup and redirect) |
| `-https-addr` | `:8443` | HTTPS listen address |
| `-service-hosts` | `shushtls.local,localhost` | DNS names for ShushTLS’s own TLS cert |

## Certificate model (root vs leaf)

- **Root CA (one per ShushTLS instance).** A long-lived certificate that acts as the trust anchor. You install this in your OS or browser trust store. Once a device trusts it, that device will accept any certificate signed by this root. ShushTLS generates it at initialization and keeps it in the state directory. **Validity:** 25 years by default.
- **Leaf certificates (many).** Certificates signed by your root, each bound to specific DNS names (e.g. `nas.home.arpa` or `*.home.arpa`). You issue these via the UI or API and use them on your services. Browsers accept them because they chain to the root CA you installed. **Validity:** follows the CA/Browser Forum rules below.
- **Why install the root on each device?** Browsers and OSes only trust a fixed set of public CAs. Your ShushTLS root is private, so every device that should accept your certs must be told to trust that root. The install scripts in the web UI do exactly that.

So: one root (you install it once per device), many leaves (you issue as needed).

### Certificate longevity (leaf certs)

Maximum TLS certificate lifetime is set by the **CA/Browser Forum ballot SC-081**. Browsers will reject certs that exceed these limits. ShushTLS issues leaf certs within the current limit.

| From | Maximum leaf validity |
|------|------------------------|
| Until 2026-03-15 | 398 days |
| 2026-03-15 | 200 days |
| 2027-03-15 | 100 days |
| 2029-03-15 | 47 days |

The code may be updated over time to use the shorter validity as the dates take effect. Plan to re-issue leaf certs before they expire; the web UI shows validity dates for all certs.

## Bootstrap flow

1. **First start.** Server starts in HTTP-only mode. Logs show the URL (e.g. `http://localhost:8080`).
2. **Initialize.** Open that URL, complete setup. ShushTLS generates the root CA and its own service certificate (for the ShushTLS UI/API over HTTPS).
3. **Install trust.** On each device (Mac, Linux, Windows, etc.), run the install script or download the root PEM and add it to the system/browser trust store. The UI links to platform-specific one-liners.
4. **HTTPS active.** As soon as initialization completes, the server enables HTTPS and redirects HTTP to it. No restart. Use the HTTPS URL from the logs and continue issuing certs from the UI.

If you start with an empty state directory, you always get step 1 → 2 → 3 → 4. If you start with an existing state dir (already initialized), the server goes straight to HTTPS and redirect.

## Non-goals and tradeoffs

ShushTLS intentionally does **not** do the following. These are conscious limits, not missing features.

- **No public trust.** The root CA is for your network only. Browsers will never trust it by default. You explicitly install it on each device. That keeps the model simple and keeps you in control.
- **No short-lived certs / automatic rotation.** Certificates are issued with validity that meets current browser rules (see [Certificate longevity](#certificate-longevity-leaf-certs)). There is no built-in ACME, no auto-renewal. You re-issue when needed.
- **No revocation.** There is no CRL or OCSP. If you need to revoke a cert, stop using it and (if necessary) re-issue a new one for that name. For a home/lab CA this is usually acceptable.
- **No auth by default.** The UI and API are open on the LAN. Optional HTTP Basic Auth can be enabled in the web UI (Settings). ShushTLS does not implement OAuth, SSO, or fine-grained roles.
- **No HA / clustering.** One instance, one state directory. A lock file prevents running two instances against the same state. For multi-node or replicated setups you’d need something else.
- **No compliance or audit features.** No certificate transparency, no detailed audit log, no FIPS mode. It’s a small tool for people who want a private CA without ceremony.

## API for automation

As certificate validity periods get shorter (see [Certificate longevity](#certificate-longevity-leaf-certs)), automating issuance and fetch is important. All certificate operations are available over HTTP/HTTPS with JSON where applicable. Use the same base URL as the web UI (e.g. `https://shushtls.local:8443`). If you enabled auth in Settings, use HTTP Basic Auth for protected endpoints.

### Certificate endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/certificates` | no | List all issued certificates (JSON). |
| POST | `/api/certificates` | yes | Issue a certificate. Body: `{"dns_names": ["host.example.com", "*.example.com"]}`. Idempotent: same primary name returns existing cert. |
| GET | `/api/certificates/{primary_san}` | no | Download certificate PEM. Example: `GET /api/certificates/nas.home.arpa` |
| GET | `/api/certificates/{primary_san}?type=key` | yes | Download private key PEM. Requires auth when auth is enabled. |
| GET | `/api/ca/root.pem` | no | Download root CA certificate (PEM). |

`{primary_san}` is the first DNS name in the certificate (e.g. `nas.home.arpa` or `*.home.arpa`). For wildcards, the path uses the literal `*` (URL-encode as `%2A` if needed).

### List response (GET /api/certificates)

Returns a JSON array of certificate objects:

```json
[
  {
    "primary_san": "nas.home.arpa",
    "dns_names": ["nas.home.arpa"],
    "not_before": "2026-01-15T12:00:00Z",
    "not_after": "2026-08-03T12:00:00Z",
    "is_service": false
  }
]
```

Use `not_after` to decide when to re-issue. Issuing again with the same `dns_names` returns the existing cert; to get a fresh cert for the same name you must remove the old one from the server state (not exposed in the UI; for automation you may script against the state directory or re-issue before expiry and deploy).

### Issue request/response (POST /api/certificates)

Request body:

```json
{"dns_names": ["nas.home.arpa", "*.home.arpa"]}
```

Success (200) response:

```json
{
  "certificate": {
    "primary_san": "nas.home.arpa",
    "dns_names": ["nas.home.arpa", "*.home.arpa", "home.arpa"],
    "not_before": "2026-01-15T12:00:00Z",
    "not_after": "2026-08-03T12:00:00Z",
    "is_service": false
  },
  "message": "Certificate issued successfully."
}
```

Errors: 400 (invalid body or empty `dns_names`), 409 (not initialized), 500 (issuance failed). Body: `{"error": "message"}`.

### Example: fetch or issue then download cert + key

```bash
# Replace BASE with your ShushTLS URL (e.g. https://shushtls.local:8443)
BASE="https://shushtls.local:8443"
SAN="nas.home.arpa"

# Issue (idempotent); add -u user:pass if auth is enabled
curl -sS -X POST "$BASE/api/certificates" \
  -H "Content-Type: application/json" \
  -d "{\"dns_names\": [\"$SAN\"]}" | jq .

# Download cert and key (key requires auth if enabled)
curl -sS -o cert.pem "$BASE/api/certificates/$SAN"
curl -sS -o key.pem -u user:pass "$BASE/api/certificates/$SAN?type=key"
```

### Other endpoints

- **GET /api/status** — JSON: `state`, `serving_mode`, `root_ca` (if any), `certificates` (same shape as list). Protected when auth is on.
- **POST /api/initialize** — One-time setup (body optional). Protected when auth is on.
- **POST /api/service-cert** — Set which cert is used for ShushTLS’s HTTPS. Body: `{"primary_san": "host.example.com"}`. Protected when auth is on.

## Optional auth

After initialization, you can enable HTTP Basic Auth in the web UI (Settings). When enabled, it protects initialization, certificate issuance, service-cert designation, and status; listing certs and downloading the root PEM remain unauthenticated so install scripts and devices can still get the root. Private key downloads require auth when auth is on.

## State directory

All persistent data lives in the state directory. Only one ShushTLS process may use a given state directory at a time (enforced by a lock file).

**Default location (platform config directory):**

- Linux: `~/.config/shushtls` (or `$XDG_CONFIG_HOME/shushtls`)
- macOS: `~/Library/Application Support/shushtls`
- Windows: `%AppData%\shushtls`

Override with `-state-dir`.

**Layout:**

```
<stateDir>/
  ca/
    ca-key.pem      # Root CA private key (keep secret)
    ca-cert.pem     # Root CA certificate (install this on devices)
  certs/
    <sanitized-SAN>/   # One dir per issued cert (e.g. nas.home.arpa, _wildcard_.home.arpa)
      key.pem
      cert.pem
  service-host       # Primary SAN of the cert used for ShushTLS’s own HTTPS
  auth.json          # Optional; present if auth was ever enabled
  shushtls.lock      # Lock file while the server is running; removed on exit
```

## Maintenance

For whoever returns to this system after a long time.

**Regenerating or re-issuing certificates**

- **Leaf certs:** Use the web UI (Certificates) or `POST /api/certificates` with `{"dns_names": ["host.example.com"]}`. Issuing the same primary name again returns the existing cert (idempotent). To get a *new* cert for the same name you’d need to remove the existing cert directory under `certs/` and issue again (not exposed in the UI).
- **ShushTLS’s own HTTPS cert (service cert):** Issue another cert from the UI and choose “Use as service.” No restart; the server picks it up immediately.
- **Root CA:** Generated once at initialization. There is no in-app “regenerate root.” Replacing it would mean re-trusting on every device (effectively start over with a new state dir or backup).

**Adding a new device:** Install the root CA on the new device using the scripts on the Install CA page (or manually add the root PEM to that device’s trust store). No need to touch ShushTLS’s state directory.

**If a certificate expires**

- **Leaf certs:** Re-issue before expiry from Certificates and deploy the new cert to your service. Use the [longevity table](#certificate-longevity-leaf-certs) to plan; the UI shows each cert’s validity.
- **Root CA:** Default validity is 25 years. If it ever approaches expiry, you’d generate a new root (e.g. new state dir) and re-install trust on all devices.

**Rebuilding the binary:** `just build` (or `go build -o shushtls .`). Tests: `just test`. Run: `just run` or `./shushtls` with optional flags. Dependencies are in `go.mod` / `go.sum`; requires a Go toolchain.

**Troubleshooting**

- **“Another ShushTLS instance is already using …”** — Another process has that state directory, or a previous run didn’t release the lock. Ensure no other `shushtls` (or `go run` child) is running. If you’re sure nothing is using it, remove `shushtls.lock` in the state directory and try again.
- **“Cannot create state directory” / permission errors** — The state path must be writable and must be a directory (not a file).
- **Browsers still don’t trust my certs** — The device must trust the **root** CA. Re-run the install script for that OS, or manually add the root cert to the system/browser trust store. Clearing the browser cache for the site can help after adding trust.
