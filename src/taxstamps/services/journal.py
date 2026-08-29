"""Double-entry journal posting. Balance is enforced by a deferred database
trigger at COMMIT (migration 0001); the service pre-validates so honest
callers get a clean 4xx-style error instead of a trigger exception, but the
DB is the actual invariant."""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from taxstamps.models import Journal, LedgerEntry


class JournalError(ValueError):
    pass


async def post_journal(
    session: AsyncSession,
    *,
    reference: str,
    narration: str,
    legs: list[tuple[str, int, int]],  # (account, debit_kobo, credit_kobo)
) -> Journal:
    if not legs or len(legs) < 2:
        raise JournalError("a journal requires at least two legs")
    debits = sum(d for _, d, _ in legs)
    credits = sum(c for _, _, c in legs)
    if debits != credits:
        raise JournalError(f"unbalanced journal: debits {debits} <> credits {credits}")
    if debits == 0:
        raise JournalError("zero-amount journals are not postable")
    journal = Journal(id=uuid.uuid4(), reference=reference, narration=narration)
    session.add(journal)
    for account, debit, credit in legs:
        if debit < 0 or credit < 0 or (debit and credit):
            raise JournalError(f"illegal leg for {account}: debit {debit} credit {credit}")
        session.add(LedgerEntry(id=uuid.uuid4(), journal_id=journal.id, account=account,
                                debit_kobo=debit, credit_kobo=credit))
    await session.flush()
    return journal
