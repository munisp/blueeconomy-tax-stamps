"""Expiry sweeper: flips expired stamps for offline verifiers.

The signed Bitstring Status List is the verifier-facing truth, NOT the
database-row status. A stamp whose ``valid_until`` has passed must have its
``expired`` status-list bit set even if nobody ever scans it — so expiry is
swept, not computed lazily at scan time.

Each batch claims stamps with ``SELECT ... FOR UPDATE SKIP LOCKED`` (the same
pattern as the outbox publisher), flips ``status = 'EXPIRED'`` and publishes
the new signed status-list snapshot, all in one transaction per batch. Runs
as a separate process alongside the outbox publisher
(``taxstamps-expiry-sweeper``); also invocable once via
``sweep_expired_once`` (tests / ops tooling).
"""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from taxstamps.config import Settings, get_settings
from taxstamps.crypto.eddsa import SigningKey
from taxstamps.db import dispose_engine, init_engine
from taxstamps.db import session as db_session
from taxstamps.models import Stamp, utcnow
from taxstamps.services import statuslists

log = logging.getLogger("taxstamps.expiry-sweeper")

_POLL_SECONDS = 60.0
_BATCH = 500

# Stamps in a terminal state (CONSUMED/VOID/SUSPECT) keep their forensic
# status; only live states flip to EXPIRED.
_SWEEPABLE = ("ISSUED", "ACTIVE")


async def sweep_expired_batch(
    session: AsyncSession,
    *,
    settings: Settings,
    signing_key: SigningKey,
    batch_size: int = _BATCH,
) -> int:
    """Flip one batch of expired stamps. Returns the number swept.

    The row lock (FOR UPDATE SKIP LOCKED) makes concurrent sweepers safe:
    each stamp is claimed by exactly one transaction.
    """
    now = utcnow()
    rows = (
        await session.execute(
            select(Stamp)
            .where(Stamp.status.in_(_SWEEPABLE), Stamp.valid_until <= now)
            .order_by(Stamp.valid_until)
            .limit(batch_size)
            .with_for_update(skip_locked=True)
        )
    ).scalars().all()
    vm = f"{settings.issuer_did}#ed25519-{signing_key.kid}"
    for stamp in rows:
        stamp.status = "EXPIRED"
        await statuslists.set_flag(
            session,
            purpose="expired",
            index=stamp.status_list_index,
            settings=settings,
            signing_key=signing_key,
            verification_method=vm,
        )
    # A batch whose stamps are now all in terminal states is closed out.
    from taxstamps.services import issuance

    for batch_id in {stamp.batch_id for stamp in rows}:
        await issuance.refresh_batch_terminal_state(session, batch_id=batch_id)
    await session.flush()
    return len(rows)


async def sweep_expired_once(settings: Settings, signing_key: SigningKey) -> int:
    """Sweep all currently-expired stamps; returns the total flipped."""
    total = 0
    while True:
        async with db_session() as s:
            n = await sweep_expired_batch(s, settings=settings, signing_key=signing_key)
            await s.commit()
        total += n
        if n < _BATCH:
            return total


async def sweep_forever() -> None:
    settings = get_settings()
    if not settings.database_url:
        raise RuntimeError("TAXSTAMPS_DATABASE_URL is required for the expiry sweeper")
    from taxstamps.crypto.eddsa import load_signing_key

    if not settings.signing_key_path:
        raise RuntimeError("TAXSTAMPS_SIGNING_KEY_PATH is required for the expiry sweeper")
    signing_key = load_signing_key(settings.signing_key_path, settings.kid)
    init_engine(settings.database_url)
    log.info("expiry sweeper started")
    try:
        while True:
            swept = await sweep_expired_once(settings, signing_key)
            if swept:
                log.info("expiry sweeper flipped %d stamps", swept)
            await asyncio.sleep(_POLL_SECONDS)
    finally:
        await dispose_engine()


def run_sweeper() -> None:
    logging.basicConfig(level=logging.INFO)
    asyncio.run(sweep_forever())


if __name__ == "__main__":
    run_sweeper()
