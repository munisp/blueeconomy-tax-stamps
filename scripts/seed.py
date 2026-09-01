#!/usr/bin/env python3
"""Demo/staging database seeder (synthetic data only).

Doctrine:
  - REFUSES to run when ENV=production or PROFILE=prod.
  - Requires explicit SEED_DEMO=true.
  - Idempotent: db/seed/seed.sql uses ON CONFLICT DO NOTHING / guarded
    inserts; safe to run repeatedly (proven by double-apply).
  - Run AFTER `alembic upgrade head` against a dev/staging database.

Usage:
  SEED_DEMO=true TAXSTAMPS_DATABASE_URL=postgresql+psycopg://... python scripts/seed.py
"""
import os
import sys
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parent.parent
SEED_SQL = ROOT / "db" / "seed" / "seed.sql"


def main() -> int:
    env = os.environ.get("ENV", "").lower()
    profile = os.environ.get("PROFILE", "").lower()
    if env == "production" or profile == "prod":
        print("refusing to seed: ENV/PROFILE indicates production", file=sys.stderr)
        return 1
    if os.environ.get("SEED_DEMO", "").lower() != "true":
        print("refusing to seed: set SEED_DEMO=true to acknowledge synthetic demo data", file=sys.stderr)
        return 1
    url = os.environ.get("TAXSTAMPS_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if not url:
        print("TAXSTAMPS_DATABASE_URL is required", file=sys.stderr)
        return 1
    # normalise SQLAlchemy-style URLs to plain libpq conninfo
    for prefix in ("postgresql+asyncpg://", "postgresql+psycopg://", "postgresql://"):
        if url.startswith(prefix):
            url = "postgres://" + url[len(prefix):]
            break
    sql = SEED_SQL.read_text(encoding="utf-8")
    with psycopg.connect(url, autocommit=False) as conn:
        conn.execute(sql)
        n = conn.execute(
            "SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename <> 'alembic_version'"
        ).fetchone()[0]
    print(f"seed applied idempotently: {n} tables present; all demo rows are synthetic Nigerian maritime data")
    return 0


if __name__ == "__main__":
    sys.exit(main())
