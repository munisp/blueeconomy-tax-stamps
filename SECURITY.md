# Security Posture — blueeconomy-tax-stamps

Phase 11 security audit (branch `phase11/security`).

## Controls verified
- **Secrets**: working-tree scan clean.
- **AuthN/Z**: all `/v1` routes bind `IdentityDep` (OIDC identity) or verifier credentials (`/v1/verify*` uses hashed verifier credentials, HMAC compare, fail-closed Redis nonce/rate-limit). PBAC policy enforcement via `require_policy`.
- **Injection**: SQLAlchemy ORM parameterized queries; no string-built SQL.
- **Key handling**: Ed25519 signing key loaded from file-mounted PKCS#8; placeholder markers refused; group/world-readable keys refused.

## Fixes this phase
- **CRITICAL**: `TAXSTAMPS_ALLOW_PERMISSIVE_KEY_FILE` escape hatch now hard-refuses when `ENV=production` (`permissive-key-file-refused`), closing the permissive-key path in prod. Regression test added.

## Residuals
- No tenant RLS migrations in this repo (SQLAlchemy-managed schema); tenant isolation enforced at the application layer — recommend a future migration-side RLS pass if the schema gains tenant-scoped tables.
- pip dependency audit performed manually (current pins); run `pip-audit` in CI.
