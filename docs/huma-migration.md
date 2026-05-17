# Huma API migration — decisions

Recorded for epic **shushtls-3x6d**. Implementation issues should follow this document; update it if a decision changes.

## Summary

| Topic | Decision |
|-------|----------|
| Framework | [Huma v2](https://huma.rocks/) via `humago` on stdlib `http.ServeMux` |
| Error bodies | RFC 9457 `application/problem+json` (Huma default) |
| OpenAPI spec | `GET /api/openapi.json` (and `GET /api/openapi.yaml`) |
| Interactive API docs | `GET /api/docs` (Huma / Stoplight Elements) |
| Human docs | Keep `GET /docs` (HTML); link to spec + `/api/docs` |
| OpenAPI version | 3.1 (Huma default) |
| Scope | `internal/api` only; ACME not in spec |

---

## 1. Error format

**Decision:** Use Huma’s default — [RFC 9457](https://datatracker.ietf.org/doc/html/rfc9457) Problem Details as `application/problem+json`.

**Rejected:** Keep legacy `{"error":"..."}` for backward compatibility. Scripts and curl examples in README/docs will be updated during the migration (see **shushtls-1cef**). Agents and OpenAPI tooling benefit more from standard problem details than from preserving an ad-hoc shape.

**Implications for implementers:**

- Return errors via `huma.Error4xx` / `huma.Error5xx` (or equivalent) so status, `title`, `detail`, and optional `errors` fields are consistent.
- Map existing user-facing strings into `detail` where possible (e.g. `"root CA does not exist — run POST /api/initialize first"`).
- `WWW-Authenticate: Basic realm="ShushTLS"` on 401 unchanged.
- Server catch-all for unknown `/api/*` paths should also emit problem+json once the API package owns error formatting (or delegate to Huma’s not-found behavior).

---

## 2. OpenAPI and schema URLs

**Decision:** Serve generated OpenAPI under the `/api` prefix, not Huma’s root defaults (`/openapi.json`, `/docs`).

| Resource | Path |
|----------|------|
| OpenAPI (JSON) | `/api/openapi.json` |
| OpenAPI (YAML) | `/api/openapi.yaml` |
| JSON Schemas | `/api/schemas/{schema}` (Huma default pattern, prefixed) |
| Interactive docs | `/api/docs` |

**Config sketch** (implement in **shushtls-3clz**):

```go
cfg := huma.DefaultConfig("ShushTLS API", version.Version)
cfg.DocsPath = "/api/docs"
cfg.OpenAPIPath = "/api/openapi.json"
cfg.SchemasPath = "/api/schemas"
// OpenAPI YAML: register or set per Huma docs if separate from OpenAPIPath
```

Satisfies **shushtls-5ism** / **shushtls-3o84** without a hand-maintained spec file.

**`externalDocs`:** Point to the ACME directory (`/acme/directory` on the same host). ACME routes stay out of the OpenAPI path list.

---

## 3. Documentation UX

**Decision:** Two layers, both kept.

1. **`/docs`** — Existing HTML operator guide (`internal/ui/templates/docs.html`). Add prominent links to `/api/openapi.json` and `/api/docs`.
2. **`/api/docs`** — Huma-generated Stoplight Elements UI for exploring the machine-readable contract.

Agents should prefer **`/api/openapi.json`** (single fetch). Humans can use either `/docs` or `/api/docs`.

---

## 4. Router and integration

**Decision:** `github.com/danielgtaylor/huma/v2/adapters/humago` on the same `http.ServeMux` built in `internal/server/server.go`.

- `Handler.Register(mux)` becomes `Handler.RegisterAPI(mux)` (or equivalent) registering Huma operations.
- ACME and UI registration unchanged; order remains API → ACME → `/api/` catch-all → UI.
- Go version: already 1.25+ in `go.mod`; meets Huma’s requirement.

---

## 5. Auth in OpenAPI

**Decision:** Document optional HTTP Basic auth with OpenAPI `securitySchemes` + per-operation `security`.

Runtime behavior unchanged:

- When auth is disabled or no store: all endpoints behave as today (no challenge).
- When auth is enabled: same endpoints require Basic auth as in `api.go` comments today (including bundle download on `GET /api/certificates/{san}`).

Scheme name: `basicAuth`, realm `ShushTLS` (match current `WWW-Authenticate` header).

---

## 6. Response shapes (parity)

Preserve current JSON shapes unless a later issue explicitly changes them:

| Endpoint | Shape |
|----------|--------|
| `GET /api/certificates` | Bare JSON **array** of cert objects (not wrapped in `{ "certificates": [...] }`) |
| `POST /api/initialize` | Optional or empty body; `CAParams` when body present |
| `POST /api/auth` | `enabled` as optional bool (pointer semantics for “omit vs false”) |
| Error on `GET /api/ca/root.pem` when CA missing | JSON problem response (404), not PEM — same as today |

Binary responses unchanged: PEM, `application/x-tar`, `application/zip`, install scripts with existing `Content-Type` / `Content-Disposition`.

---

## 7. Request limits

**Decision:** Per-operation body limit **1 MiB** (`1 << 20`), matching current `maxRequestBody` in `api.go`.

---

## 8. Out of scope for this migration

- ACME endpoints in OpenAPI (link only).
- New API features (CSR, enriched list metadata, custom CN, etc.) — separate issues under **shushtls-6473** after Huma parity is done.

---

## Issue traceability

| Issue | Uses these decisions |
|-------|----------------------|
| shushtls-3clz | §4, §2 config sketch, §7 |
| shushtls-4bv5 | §1, §5, §6 |
| shushtls-21bw | §6 binary rows |
| shushtls-3o84 | §2, §3, externalDocs |
| shushtls-1cef | §1 README/docs updates, CI validation of `/api/openapi.json` |
