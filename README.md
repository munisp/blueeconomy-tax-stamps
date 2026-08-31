# blueeconomy-tax-stamps

Declaration-linked excise tax stamps for imported goods on the NewWave.io
BlueEconomy PPP platform (Nigerian maritime agencies). Each stamp is a
**W3C Verifiable Credential 2.0** signed **eddsa-jcs-2022** (Ed25519 over
RFC 8785 JCS) with revocation via **Bitstring Status List** — not a database
row status, not HMAC. The QR payload *is* the compact VC.

This is a clean-room re-implementation under platform conventions. The
reviewed reference (`munisp/taxstamp`) carries **no license**; only the
domain design was carried over. The small pure algorithms (serial check
digit, Z1.4 sampling, merkle/audit math) are re-implemented here from their
public specifications.

## Domain

Stamp obligation is computed **server-side** from customs declaration line
items (HS chapters 22/24 + sweetened beverages, HS 2202) against an
effective-dated 2026 Nigerian excise tariff table with statutory references
(`src/taxstamps/domain/tariff.py`). Client-supplied totals are rejected
(422; schemas are `extra="forbid"`).

| HS heading | Category | 2026 rate (from 2026-07-01) | Statutory reference |
|---|---|---|---|
| 2402 | tobacco | ₦8.00/stick (was ₦6.00) | 2026 Fiscal Policy Measures |
| 2203 | alcohol (beer) | ₦80.00/l (was ₦72.00) | 2026 Fiscal Policy Measures |
| 2208 | alcohol (spirits) | 30% ad valorem + ₦75.00/l | 2026 Fiscal Policy Measures |
| 2202 | beverages (sweetened) | ₦10.00/l | Finance Act 2021 s.17 |
| ch. 30 | pharmaceuticals | zero-rated (traceability stamp) | — |

Money is integer kobo everywhere; ad valorem uses basis points with half-up
integer rounding. Floating-point money and floating-point geo (integer
micro-degrees only) are prohibited.

## Workflow

```
declaration event (Kafka trade.declarations.v1, envelope v1.0, JWS-verified)
  → TaxStampAssessment (server-side tariff pricing)
  → maker-checker approval (submitter-cannot-approve; risk tiers LOW/STANDARD/HIGH = 1/2/3 approvers)
  → payment intent + rail receipt (financial-controls boundary; EXACT amount+currency match; mismatch QUARANTINED)
  → serial issuance (NG-<CAT3>-<YYYY>-<SEQ10>-<Luhn mod-34>; chunked, resumable, crash-safe; atomic serial-block claim)
  → ANSI/ASQ Z1.4 acceptance sampling (GIL II, AQL 0.65%; failed lot can never activate)
  → activation
  → first-scan-wins verification
```

### Serial format

`NG-<CAT3>-<YYYY>-<SEQ10>-<CHECK>` where CAT3 ∈ {TBC, ALC, PHA, BEV} and
CHECK is a Luhn mod-34 digit over the body (alphabet excludes I and O).
Check-digit validation runs before any database lookup, so mis-transcribed
serials never touch the store. Sequence blocks are claimed atomically
(`INSERT … ON CONFLICT … DO UPDATE … RETURNING`) in the same transaction as
the stamp rows, so concurrent issuers never overlap and a crash mid-chunk
rolls back claim + stamps together (`issued_count` is the durable resume
cursor).

### Verification: first-scan-wins

- The first **credentialed** scan of an ACTIVE stamp **consumes** it
  (ferry-boarding pattern), serialized with `SELECT … FOR UPDATE`; an
  8-device race has exactly one winner (tested). First-scan-wins clone
  detection applies ONLY to credentialed consumption scans.
- Repeat scans return `already_verified` with first-scan evidence; a repeat
  from a **different device** returns `clone_suspect` and sets the stamp's
  `suspect` bit in the published status list.
- **Every attempt** (valid or not) is persisted with verifier identity and
  integer micro-degree geo as audit substrate; velocity analytics (≥3
  distinct devices / 24h) feed clone-suspect flagging.
- `POST /v1/verify` requires a **per-verifier credential** (keyed hash
  stored; no shared fleet secret) + Redis single-use nonce + rate limit.
  Redis outage → 503 (fail-closed, never a fail-open scan).
- `POST /v1/verify/public` is self-service for importers/consumers: no
  device credential and **non-consuming** — it returns validity/outcome and
  status-list state but never transitions ACTIVE → CONSUMED (public serials
  are enumerable; a consuming public path would allow mass stamp-burning).
  Anomaly throttling applies per-IP plus a per-serial scan-rate cap
  (`TAXSTAMPS_PUBLIC_SERIAL_RATE_LIMIT_PER_MINUTE`, default 10) when Redis
  is present; when a full credential is presented it additionally performs
  the offline checks (eddsa-jcs-2022 proof + status-list bits).

### VC profile

- `@context` exactly `["https://www.w3.org/ns/credentials/v2"]`; type
  `["VerifiableCredential", "ExciseTaxStamp"]`.
- `credentialSubject` is **unit-scoped only**: `stampScope` ("unit"),
  serial, hsCode, batchId, assessmentRef; `validFrom`/`validUntil` window.
  Consignment-level data (duty amount, declaration reference, consignee
  TIN) is deliberately NOT in the public credential — it stays resolvable
  via `assessmentRef` for authorized verifiers (policy-gated read path).
- Proof: Data Integrity `eddsa-jcs-2022` (JCS canonicalization, SHA-256 of
  proof options ‖ SHA-256 of document, Ed25519, multibase base58btc
  `proofValue`). No network calls at issue or verify time.
- Status: three `BitstringStatusListEntry` statuses per stamp — purposes
  `void`, `expired`, `suspect` — served as signed status-list VCs at
  `GET /v1/status-list/{purpose}`.
- Issuer key publication: `GET /v1/issuers/{issuer}/key`.

## Controls

- **Double-entry journal** with a DB-enforced balanced invariant:
  `DEFERRABLE INITIALLY DEFERRED` constraint trigger rejects COMMIT of any
  journal whose legs do not balance (migration `0001`).
- **Hash-chained append-only audit**: `sha256(prev_hash || "." || JCS(event))`,
  genesis `"0"*64`, advisory-lock serialization; UPDATE/DELETE rejected by
  triggers; full-recompute verification at `GET /v1/ops/audit-chain`.
- **Idempotency records** on intake POSTs (durable, request-hash checked;
  conflicting replay → 409) plus unique idempotency keys in the domain.
- **Outbox → Kafka**: `stamps.assessed/approved/issued/activated/verified/voided`
  events in canonical envelope v1.0 (FHIR R4 message Bundle wrap, JWS-EdDSA
  over RFC 8785 JCS, kid `blueeconomy-tax-stamps-0`), at-least-once with the
  outbox id as the Kafka key. Kafka unconfigured → messages stay PENDING
  (fail-closed) and capabilities reports the publisher unavailable.
- **Merkle anchoring**: RFC 6962-style root over batch serials at
  finalization.
- **Expiry sweeper** (`taxstamps-expiry-sweeper`, runs alongside the outbox
  publisher): claims expired stamps in `FOR UPDATE SKIP LOCKED` batches,
  flips `status = EXPIRED` and sets the `expired` status-list bit, so the
  signed status list — the verifier-facing truth — reflects expiry even
  when nobody scans.
- **Zero-rated assessments** (e.g. pharmaceuticals): settle through a
  policy-gated, audited zero-rated path (`POST
  /v1/assessments/{id}/zero-rated-settlement`) — never through a rail —
  with a settled zero-amount intent as the durable record. Positive-amount
  assessments still require an exact rail receipt.
- **Quarantine resolution**: a mismatched remittance is resolved only by an
  ops/finance role posting a SUPERSEDING receipt (`POST
  /v1/payments/intents/{id}/quarantine-resolution`) that settles the intent
  (exact match still required) or marks it FAILED with reason; the original
  receipt stays immutable.
- **Maker-checker stamp voids**: a void request (excise-approver tier)
  executes only on approval by a DIFFERENT excise-approver
  (`POST /v1/stamps/{serial}/void` → `POST /v1/stamps/{serial}/void/approve`;
  single-actor → 409), consistent with the assessment pattern.
- **Ops endpoints gated**: `GET /v1/capabilities` and
  `GET /v1/ops/audit-chain` require `ops:read` (auditor role) — anonymous
  401, non-auditor 403, OIDC unconfigured 503 (fail-closed). Probes and
  verifier-facing publications stay public.

## Honesty registry

`GET /v1/capabilities` lists every capability as available or
unavailable-with-reason. Unconfigured integrations (OIDC, Redis, Kafka,
payment rail) return **503** from dependent routes — success is never
fabricated. The service **refuses to boot** with placeholder/dummy signing
key material, an unreadable key/JWKS/policy directory, or missing required
config. Declared-but-absent scope (printer hardware control, image/ML
authenticity, offline field sync) is listed as unavailable, not implied.

## Configuration (12-factor, env only)

Required: `TAXSTAMPS_DATABASE_URL`, `TAXSTAMPS_SIGNING_KEY_PATH` (Ed25519
PKCS#8 PEM, file-mounted, `0600`, never committed),
`TAXSTAMPS_ISSUER_DID`, `TAXSTAMPS_POLICY_DIR`.

Optional (fail-closed consumers when absent): `TAXSTAMPS_REDIS_URL`,
`TAXSTAMPS_KEY_DIRECTORY_PATH` (inbound envelope verification),
`TAXSTAMPS_KAFKA_BOOTSTRAP_SERVERS`,
`TAXSTAMPS_KAFKA_DECLARATIONS_TOPIC_PATTERN` (default
`trade.declarations.v1`, the blueeconomy-port-interoperability producer
topic; `*` wildcard supported), `TAXSTAMPS_OIDC_JWKS_URL` /
`TAXSTAMPS_OIDC_JWKS_PATH` + `TAXSTAMPS_OIDC_ISSUER` (+`_AUDIENCE`),
`TAXSTAMPS_PAYMENT_RAIL` + `TAXSTAMPS_FINANCIAL_CONTROLS_ENDPOINT`,
`TAXSTAMPS_STATUS_LIST_BASE_URL`, plus tuning vars documented in
`src/taxstamps/config.py`.

## Processes

One image, three entrypoints: `taxstamps-api` (HTTP),
`taxstamps-consumer` (`trade.declarations.v1` Kafka consumer, envelope-verified,
deduped on eventId, offset committed after DB commit; maps the
blueeconomy-port-interoperability FHIR Basic / `domain-payload` declaration
payload onto the canonical resource shape — see
`src/taxstamps/events/consumer.py`), `taxstamps-outbox`
(outbox publisher). Migrations: `alembic upgrade head`
(`TAXSTAMPS_DATABASE_URL` required).

## Development

```sh
pip install -e '.[dev]'
pytest tests/unit            # always runnable, no services needed
docker compose up postgres redis kafka   # real dependencies
TAXSTAMPS_TEST_DATABASE_URL=postgresql+asyncpg://taxstamps:taxstamps-local-dev@localhost:5432/taxstamps \
TAXSTAMPS_TEST_REDIS_URL=redis://localhost:6379/15 \
pytest tests                 # full suite incl. integration
```

Without `TAXSTAMPS_TEST_DATABASE_URL`, the integration suite falls back to a
real embedded PostgreSQL via the dev-only `pgserver` package when installed,
and skips otherwise. Redis-gated tests skip without
`TAXSTAMPS_TEST_REDIS_URL`. There are no mocks of production code paths.

A development signing key: `python -c "from taxstamps.crypto.eddsa import generate_pkcs8_pem; open('keys/ed25519_pkcs8.pem','wb').write(generate_pkcs8_pem())" && chmod 600 keys/ed25519_pkcs8.pem` (git-ignored; see `keys/README.md`).

CI: `ci/github-actions.yml.example` — intentionally not under
`.github/workflows/` (push token lacks the `workflow` scope); see
`ci/README.md`.

## License

Apache-2.0. All dependencies are permissively licensed (MIT / Apache-2.0 /
BSD); see `pyproject.toml` comments.
