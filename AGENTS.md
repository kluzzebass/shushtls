# Agent guide — ShushTLS

## API discovery

- **`GET /api/openapi.json`** — OpenAPI 3.1 contract for all `/api/*` REST endpoints
- **`GET /api/docs`** — Interactive API explorer (Stoplight Elements)
- **`GET /docs`** — Human-oriented HTML guide (links to the spec)

## Errors

REST API errors use **RFC 9457** `application/problem+json` (not `{"error":"..."}`). See [docs/huma-migration.md](docs/huma-migration.md) for migration decisions.

## ACME

Certificate automation uses **RFC 8555** at `/acme/directory`, not the REST OpenAPI spec. Install the ShushTLS root CA on clients that validate ACME (e.g. cert-manager) per project docs.

## Issue tracking

```bash
dcat prime
dcat list --agent-only
dcat search "query"
```

Huma migration epic: **shushtls-3x6d** — decisions in [docs/huma-migration.md](docs/huma-migration.md).
