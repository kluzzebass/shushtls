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

Open the URL shown in the log (e.g. `http://localhost:8080`). Click through setup to initialize. Then install the root CA on each device that will use your certs (macOS, Linux, Windows install scripts are available from the UI). After that, the server is available over HTTPS and HTTP redirects to it.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-state-dir` | platform config dir (e.g. `~/.config/shushtls`) | Where CA and issued certs are stored |
| `-http-addr` | `:8080` | HTTP listen address (setup and redirect) |
| `-https-addr` | `:8443` | HTTPS listen address |
| `-service-hosts` | `shushtls.local,localhost` | DNS names for ShushTLS’s own TLS cert |

## Certificate model (root vs leaf)

- **Root CA (one per ShushTLS instance).** A long-lived certificate that acts as the trust anchor. You install this in your OS or browser trust store. Once a device trusts it, that device will accept any certificate signed by this root. ShushTLS generates it at initialization and keeps it in the state directory.
- **Leaf certificates (many).** Short-lived certificates signed by your root, each bound to specific DNS names (e.g. `nas.home.arpa` or `*.home.arpa`). You issue these via the UI or API and use them on your services (web server, NAS, etc.). Browsers accept them because they chain to the root CA you installed.
- **Why install trust?** Browsers and OSes only trust a fixed set of public CAs. Your ShushTLS root is private, so every device that should accept your certs must be told to trust that root. The “install” scripts from the UI do exactly that (e.g. add to system keychain or trust store).

So: one root (you install it once per device), many leaves (you issue as needed). No cryptography expertise required beyond “install the root where the UI says.”

## Bootstrap flow

1. **First start.** Server starts in HTTP-only mode. Logs show the URL (e.g. `http://localhost:8080`).
2. **Initialize.** Open that URL, complete setup. ShushTLS generates the root CA and its own service certificate (for the ShushTLS UI/API over HTTPS).
3. **Install trust.** On each device (Mac, Linux, Windows, etc.), run the install script or download the root PEM and add it to the system/browser trust store. The UI links to platform-specific one-liners.
4. **HTTPS active.** As soon as initialization completes, the server enables HTTPS and redirects HTTP to it. No restart. Use the HTTPS URL from the logs (e.g. `https://shushtls.local:8443`) and continue issuing certs from the UI.

If you start with an empty state directory, you always get step 1 → 2 → 3 → 4. If you start with an existing state dir (already initialized), the server goes straight to HTTPS and redirect.

## Non-goals and tradeoffs

ShushTLS intentionally does **not** do the following. These are conscious limits, not missing features.

- **No public trust.** The root CA is for your network only. Browsers will never trust it by default. You explicitly install it on each device. That keeps the model simple and keeps you in control.
- **No short-lived certs / automatic rotation.** Certificates are issued with validity that meets current browser rules (e.g. 200 days). There is no built-in ACME, no auto-renewal, no short-lived certs with automatic refresh. You re-issue or re-download when needed.
- **No revocation.** There is no CRL or OCSP. If you need to revoke a cert, stop using it and (if necessary) re-issue a new one for that name. For a home/lab CA this is usually acceptable.
- **No auth by default.** The UI and API are open on the LAN. Optional HTTP Basic Auth can be enabled in Settings. ShushTLS does not implement OAuth, SSO, or fine-grained roles.
- **No HA / clustering.** One instance, one state directory. A lock file prevents running two instances against the same state. For multi-node or replicated setups you’d need something else.
- **No compliance or audit features.** No certificate transparency, no detailed audit log, no FIPS mode. It’s a small tool for people who want a private CA without ceremony.

## Optional auth

After initialization, you can enable HTTP Basic Auth in the web UI (Settings). When enabled, it protects initialization, certificate issuance, service-cert designation, and status; listing certs and downloading the root PEM remain unauthenticated so install scripts and devices can still get the root. Private key downloads require auth when auth is on.

## State directory

Default location is the platform config directory (e.g. `~/.config/shushtls` on Linux, `~/Library/Application Support/shushtls` on macOS). Override with `-state-dir`. All persistent data lives there: root CA, issued certificates, optional auth config. Only one ShushTLS process may use a given state directory at a time.

## For maintainers

See [docs/FUTURE_ME.md](docs/FUTURE_ME.md) for where state lives on disk, how to regenerate certs, add devices, handle expiry, and rebuild the binary. Written for whoever returns to this project after a long time.
