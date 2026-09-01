# Database Seeding (demo/development only)

`scripts/seed.py` loads deterministic, idempotent, clearly-synthetic Nigerian
maritime demo data (FIRS/TIN references, NGN kobo amounts, HS-2022 chapters)
into every table of the tax-stamps schema.

## Safety gates

The seeder **refuses** to run when `ENV=production` or `PROFILE=prod`, and
requires explicit acknowledgement via `SEED_DEMO=true`.

## Usage

```sh
# apply migrations
TAXSTAMPS_DATABASE_URL=postgresql+asyncpg://postgres@127.0.0.1:5433/be_tax alembic upgrade head

# seed (idempotent: ON CONFLICT DO NOTHING / guarded inserts, deterministic IDs)
SEED_DEMO=true TAXSTAMPS_DATABASE_URL=postgresql+asyncpg://postgres@127.0.0.1:5433/be_tax python scripts/seed.py
```

## Layout

- `db/seed/seed.sql` — canonical seed data (FK-topological order, single tx).
- `scripts/seed.py` — env-gated runner.
- `db/seed/seed-coverage.json` — proof: every public table × rowcount after seeding.
- `scripts/seed_coverage.py` — regenerates the coverage dump.

## Coverage

21/21 public tables populated (alembic_version excluded), 0 unjustified empty
tables. Journal invariants respected: every seeded journal is balanced
(debits == credits, enforced by the deferred `trg_journal_balanced` trigger)
and each ledger entry is one-sided (`ck_entry_one_side`). Idempotency proven
by double-apply against a fresh database.
