# Performance Notes (Phase 11 audit)

Scope: index coverage vs. actual query code, unbounded queries, N+1 patterns,
connection-pool sizing, Kafka producer batching. No behavior changes; all
fail-closed invariants preserved.

## Indexes added (migrations/versions/0002_perf_indexes.py)

| Index | Justifying query |
|---|---|
| `ix_outbox_unpublished_created` (partial, `WHERE published_at IS NULL`) | outbox publisher drain: `WHERE published_at IS NULL ORDER BY created_at LIMIT n FOR UPDATE SKIP LOCKED` |

All other hot predicates were already covered: `declarations.declaration_ref`
(unique), `assessments.idempotency_key` (unique), `stamps.serial` (unique),
FK `index=True` columns, `ix_verifications_stamp_time`,
`status_list_snapshots` PK `(purpose, version)`, `audit_events` PK ordering.

## N+1 / per-row loops

- Stamp issuance allocated a status-list index per stamp (advisory lock +
  `MAX(status_list_index)` per row → 2N queries per batch). Added
  `statuslists.allocate_block(session, size)` which takes the same
  transaction-scoped advisory lock once and reserves a contiguous block;
  `allocate_index` is preserved as `allocate_block(1)`. Allocation order and
  exhaustion semantics are unchanged.

## Query caps / pagination

- All API routes are single-resource lookups; the only multi-row reads are the
  bounded outbox drain (`LIMIT _BATCH`) and `.limit(1)` probes. No unbounded
  list endpoint exists, so no cap was required.

## Connection pool sizing (env, opt-in)

`taxstamps.db.init_engine` now reads (defaults = previous hard-coded values):

- `TAXSTAMPS_DB_POOL_SIZE` (default 10)
- `TAXSTAMPS_DB_MAX_OVERFLOW` (default 5)
- `TAXSTAMPS_DB_POOL_TIMEOUT` (default 30s)
- `TAXSTAMPS_DB_POOL_RECYCLE` (default 0 = disabled)

Invalid values fail closed at startup. `pool_pre_ping` remains on.

## Kafka producer batching (env, opt-in)

`TAXSTAMPS_KAFKA_LINGER_MS` (default 0 = unchanged) and
`TAXSTAMPS_KAFKA_MAX_BATCH_SIZE` (default 16384, the aiokafka default) now tune
the outbox producer. `enable_idempotence=True` is untouched, so durability
semantics are unchanged.

## Remaining recommendations (not implemented)

- `audit.record` serializes all writers on one advisory lock per transaction;
  acceptable at current throughput, but a partitioned chain (per-aggregate
  lock key) would raise write concurrency if audit volume grows.
- Consider `pool_recycle` ~1800s in deployments behind a connection
  reaper/NAT.
