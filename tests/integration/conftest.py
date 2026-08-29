"""Integration fixtures: REAL PostgreSQL and Redis, no mocks.

Resolution order:
- TAXSTAMPS_TEST_DATABASE_URL when set (CI service container);
- otherwise an embedded but real PostgreSQL via the ``pgserver`` dev package
  (bundled PostgreSQL binaries — a real server, not a stub) when installed;
- otherwise every integration test skips.

Redis tests require TAXSTAMPS_TEST_REDIS_URL and skip without it (Redis has
no embedded equivalent; CI provides a real Redis 7 service container).
"""

from __future__ import annotations

import os
import uuid
from datetime import date
from pathlib import Path

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from taxstamps.config import Settings
from taxstamps.crypto.eddsa import SigningKey


def _resolve_database_url() -> str | None:
    url = os.environ.get("TAXSTAMPS_TEST_DATABASE_URL")
    if url:
        return url
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR", "")
    if not runtime_dir or not os.access(runtime_dir, os.W_OK):
        runtime_dir = "/tmp/.pgserver-runtime"
        os.environ["XDG_RUNTIME_DIR"] = runtime_dir
    Path(runtime_dir).mkdir(parents=True, exist_ok=True)
    try:
        import pgserver  # type: ignore
    except ImportError:
        return None
    srv = pgserver.get_server("/tmp/.taxstamps-itest-pg")
    # pgserver listens on a unix socket; convert its URI for SQLAlchemy+asyncpg.
    return srv.get_uri().replace("postgresql://", "postgresql+asyncpg://")


@pytest.fixture(scope="session")
def database_url() -> str:
    url = _resolve_database_url()
    if url is None:
        pytest.skip("no test PostgreSQL available (set TAXSTAMPS_TEST_DATABASE_URL or install pgserver)")
    return url


@pytest.fixture(scope="session")
def migrated_url(database_url: str) -> str:
    """Apply Alembic migrations once per session against the real database."""
    import subprocess

    env = dict(os.environ, TAXSTAMPS_DATABASE_URL=database_url)
    result = subprocess.run(
        ["python3", "-m", "alembic", "upgrade", "head"],
        capture_output=True, text=True, env=env,
        cwd=str(Path(__file__).resolve().parents[2]),
    )
    if result.returncode != 0:
        pytest.fail(f"alembic upgrade head failed:\n{result.stdout}\n{result.stderr}")
    return database_url


@pytest_asyncio.fixture
async def session(migrated_url: str) -> AsyncSession:
    engine = create_async_engine(migrated_url)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s
    # isolate tests: truncate all data tables (order matters for FKs)
    async with engine.begin() as conn:
        await conn.execute(text("""
            TRUNCATE verifications, inspections, stamps, stamp_batches, serial_counters,
                     ledger_entries, journals, payment_receipts, payment_intents,
                     approvals, assessment_lines, assessments, declaration_lines,
                     declarations, idempotency_records, outbox_messages, audit_events,
                     status_list_snapshots, processed_events, verifier_credentials,
                     principals RESTART IDENTITY CASCADE
        """))
    await engine.dispose()


@pytest_asyncio.fixture
async def session_factory(migrated_url: str):
    engine = create_async_engine(migrated_url)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory
    async with engine.begin() as conn:
        await conn.execute(text("""
            TRUNCATE verifications, inspections, stamps, stamp_batches, serial_counters,
                     ledger_entries, journals, payment_receipts, payment_intents,
                     approvals, assessment_lines, assessments, declaration_lines,
                     declarations, idempotency_records, outbox_messages, audit_events,
                     status_list_snapshots, processed_events, verifier_credentials,
                     principals RESTART IDENTITY CASCADE
        """))
    await engine.dispose()


@pytest.fixture(scope="session")
def signing_key() -> SigningKey:
    return SigningKey(kid="blueeconomy-tax-stamps-0", private_key=Ed25519PrivateKey.generate())


@pytest.fixture()
def settings() -> Settings:
    return Settings(
        database_url="postgresql+asyncpg://invalid/invalid",
        signing_key_path="/dev/null",  # never loaded in service-level tests
        issuer_did="did:web:taxstamps.blueeconomy.gov.ng",
        policy_dir="policies",
        status_list_base_url="https://taxstamps.blueeconomy.gov.ng",
        issuance_chunk_size=100,
    )


async def make_declaration(session: AsyncSession, ref: str | None = None, lines=None) -> object:
    """Persist a real declaration with line items (helper, not a fixture mock)."""
    from taxstamps.models import Declaration, DeclarationLine, utcnow

    ref = ref or f"DECL-{uuid.uuid4().hex[:10]}"
    declaration = Declaration(
        id=uuid.uuid4(),
        declaration_ref=ref,
        consignee_tin="12345678-0001",
        consignee_name="Test Importer Ltd",
        source_event_id=f"evt-{uuid.uuid4()}",
        occurred_at=utcnow(),
        envelope={"intake": "test"},
    )
    session.add(declaration)
    for raw in lines or [
        {"hs_code": "2203.00", "quantity": 1000, "unit": "LITRE",
         "customs_value_kobo": 50_000_000, "stamps_required": 1000},
    ]:
        session.add(DeclarationLine(id=uuid.uuid4(), declaration_id=declaration.id, **raw))
    await session.flush()
    return declaration


async def make_paid_assessment(
    session: AsyncSession,
    settings: Settings,
    *,
    submitted_by: str = "maker-1",
    approvers: tuple[str, ...] = ("checker-1", "checker-2", "checker-3"),
    duty_lines=None,
) -> object:
    """Drive a real assessment through approval and payment to PAID."""
    import uuid as _uuid

    from taxstamps.models import Assessment
    from taxstamps.services import assessments
    from taxstamps.services.payments import create_intent, record_receipt

    declaration = await make_declaration(session, lines=duty_lines)
    assessment = await assessments.create_assessment(
        session, declaration=declaration, submitted_by=submitted_by,
        idempotency_key=f"idem-{_uuid.uuid4().hex[:8]}", on_date=date(2026, 8, 1),
    )
    for approver in approvers[: assessment.approvals_required]:
        assessment = await assessments.record_decision(
            session, assessment_id=assessment.id, principal_sub=approver, decision="APPROVE",
        )
    assert assessment.status == "APPROVED"
    rail_settings = settings.model_copy(update={
        "payment_rail": "cvff-tigerbeetle",
        "financial_controls_endpoint": "https://financial-controls.example",
    })
    intent = await create_intent(session, settings=rail_settings, assessment=assessment)
    receipt = await record_receipt(
        session, intent=intent, external_reference=f"rem-{_uuid.uuid4().hex[:10]}",
        amount_kobo=intent.expected_amount_kobo, currency="NGN",
    )
    assert receipt.status == "APPLIED"
    fresh = (await session.execute(
        __import__("sqlalchemy").select(Assessment).where(Assessment.id == assessment.id)
    )).scalar_one()
    assert fresh.status == "PAID"
    return fresh
