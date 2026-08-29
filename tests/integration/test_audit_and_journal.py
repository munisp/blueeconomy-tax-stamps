"""Audit chain tamper detection, append-only triggers, balanced-journal trigger."""

import pytest
import sqlalchemy.exc
from sqlalchemy import text

from taxstamps.services import audit
from taxstamps.services.journal import JournalError, post_journal


async def test_audit_chain_records_and_verifies(session):
    await audit.record(session, "test.one", {"n": 1})
    await audit.record(session, "test.two", {"n": 2})
    await session.commit()
    result = await audit.verify_chain(session)
    assert result.ok and result.events == 2


async def test_audit_update_rejected_by_trigger(session):
    await audit.record(session, "test.x", {"a": 1})
    await session.commit()
    with pytest.raises(sqlalchemy.exc.DBAPIError):
        await session.execute(text("UPDATE audit_events SET payload = '{}'::jsonb"))
    await session.rollback()


async def test_audit_delete_rejected_by_trigger(session):
    await audit.record(session, "test.x", {"a": 1})
    await session.commit()
    with pytest.raises(sqlalchemy.exc.DBAPIError):
        await session.execute(text("DELETE FROM audit_events"))
    await session.rollback()


async def test_audit_chain_detects_tamper(session):
    await audit.record(session, "test.1", {"v": 1})
    await audit.record(session, "test.2", {"v": 2})
    await session.commit()
    # A privileged attacker bypassing the application (triggers disabled at
    # the DB level) still cannot hide: full-chain recompute detects it.
    await session.execute(text("ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_append_only"))
    await session.execute(text("UPDATE audit_events SET payload = '{\"v\": 999}'::jsonb WHERE event_type = 'test.1'"))
    await session.execute(text("ALTER TABLE audit_events ENABLE TRIGGER trg_audit_events_append_only"))
    await session.commit()
    result = await audit.verify_chain(session)
    assert not result.ok
    assert "tampered" in result.detail


async def test_journal_balanced_posts(session):
    await post_journal(
        session, reference="j-1", narration="settlement",
        legs=[("assets:clearing", 1000, 0), ("revenue:excise", 0, 1000)],
    )
    await session.commit()
    count = (await session.execute(text("SELECT count(*) FROM ledger_entries"))).scalar_one()
    assert count == 2


async def test_journal_unbalanced_rejected_at_commit(session):
    import uuid

    from taxstamps.models import Journal, LedgerEntry

    j = Journal(id=uuid.uuid4(), reference="j-bad", narration="unbalanced")
    session.add(j)
    session.add(LedgerEntry(id=uuid.uuid4(), journal_id=j.id, account="a", debit_kobo=500, credit_kobo=0))
    session.add(LedgerEntry(id=uuid.uuid4(), journal_id=j.id, account="b", debit_kobo=0, credit_kobo=400))
    with pytest.raises(sqlalchemy.exc.DBAPIError, match="not balanced"):
        await session.commit()
    await session.rollback()


async def test_journal_service_prevalidation(session):
    with pytest.raises(JournalError):
        await post_journal(session, reference="j-x", narration="", legs=[("a", 5, 0), ("b", 0, 4)])
    await session.rollback()


async def test_immutable_tables_reject_mutation(session):
    await post_journal(
        session, reference="j-imm", narration="",
        legs=[("assets:clearing", 10, 0), ("revenue:excise", 0, 10)],
    )
    await session.commit()
    for stmt in (
        "UPDATE journals SET narration = 'x'",
        "DELETE FROM ledger_entries",
    ):
        with pytest.raises(sqlalchemy.exc.DBAPIError):
            await session.execute(text(stmt))
        await session.rollback()
