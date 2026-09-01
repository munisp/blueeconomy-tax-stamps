#!/usr/bin/env python3
"""Dump per-table rowcounts to seed-coverage.json.
Usage: coverage.py <conninfo> <out.json> [exempt:table=reason ...]"""
import json, sys
import psycopg

conninfo, out = sys.argv[1], sys.argv[2]
exempt = {}
for a in sys.argv[3:]:
    k, v = a.split("=", 1)
    exempt[k] = v
conn = psycopg.connect(conninfo, autocommit=True)
conn.execute("SET client_encoding TO 'UTF8'")
tables = [r[0] for r in conn.execute(
    "SELECT tablename::text FROM pg_tables WHERE schemaname='public' "
    "AND tablename NOT LIKE 'schema_migrations%%' AND tablename NOT LIKE 'alembic_version%%' "
    "AND tablename <> 'spatial_ref_sys' "
    "AND NOT EXISTS (SELECT 1 FROM pg_inherits i JOIN pg_class c ON i.inhrelid=c.oid "
    "JOIN pg_namespace n ON c.relnamespace=n.oid "
    "WHERE n.nspname='public' AND c.relname=tablename) ORDER BY tablename").fetchall()]
cov, total = {}, 0
empty = []
for t in tables:
    n = conn.execute(f'SELECT count(*) FROM "{t}"').fetchone()[0]
    cov[t] = n
    total += n
    if n == 0 and t not in exempt:
        empty.append(t)
doc = {
    "database": conninfo.rsplit("/", 1)[-1],
    "table_count": len(tables),
    "total_rows": total,
    "tables": cov,
    "exemptions": exempt,
    "unjustified_empty_tables": empty,
}
with open(out, "w") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
print(json.dumps({k: doc[k] for k in ("table_count", "total_rows")}))
print("empty:", empty)
sys.exit(1 if empty else 0)
