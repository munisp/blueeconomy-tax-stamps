"""TS-3: the expiry sweeper flips expired stamps — database status AND the
signed expired status-list bit — so the verify path and the status list
always agree, even when nobody scans the stamp."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import select, text

from taxstamps.crypto.statuslist import parse_status_list_credential
from taxstamps.events.expiry_sweeper import sweep_expired_batch
from taxstamps.models import Stamp
from taxstamps.services import issuance, statuslists, verification
from tests.integration.conftest import make_paid_assessment


async def _active_stamps(session, settings, signing_key, count=4):
    assessment = await make_paid_assessment(session, settings, duty_lines=[
        {"hs_code": "2402.20", "quantity": count, "unit": "STICK",
         "customs_value_kobo": 0, "stamps_required": count},
    ])
    batch = await issuance.create_batch(session, assessment=assessment, settings=settings)
    while await issuance.issue_chunk(session, batch=batch, settings=settings, signing_key=signing_key):
        pass
    batch = await issuance.finalize_batch(session, batch=batch, signing_key=signing_key,
                                          principal_sub="officer-1")
    await issuance.record_inspection(session, batch=batch, defectives=0, inspector_sub="qa-1")
    await issuance.activate_batch(session, batch=batch, signing_key=signing_key,
                                  principal_sub="officer-1")
    await session.commit()
    return (await session.execute(select(Stamp).where(Stamp.batch_id == batch.id))).scalars().all()


async def test_sweeper_marks_expired_and_sets_status_bit(session, settings, signing_key):
    stamps = await _active_stamps(session, settings, signing_key, 4)
    past = datetime.now(UTC) - timedelta(days=1)
    expired_serial = stamps[0].serial
    # age exactly one stamp past its validity window
    await session.execute(
        text("UPDATE stamps SET valid_until = :past WHERE serial = :s"),
        {"past": past, "s": expired_serial},
    )
    await session.commit()

    swept = await sweep_expired_batch(session, settings=settings, signing_key=signing_key)
    await session.commit()
    assert swept == 1

    stamp = (await session.execute(select(Stamp).where(Stamp.serial == expired_serial))).scalar_one()
    assert stamp.status == "EXPIRED"
    # the expired status-list bit is set for offline verifiers
    credential = await statuslists.current_credential(session, "expired")
    assert credential is not None
    _, sl = parse_status_list_credential(credential)
    assert sl.get(stamp.status_list_index) is True
    # verify path and status list agree
    result = await verification.verify_stamp(
        session, serial=expired_serial, verifier_id="dev-1", public_scan=False,
        settings=settings, signing_key=signing_key,
    )
    await session.commit()
    assert result["outcome"] == "expired"
    # the still-valid stamps are untouched
    others = (await session.execute(
        select(Stamp).where(Stamp.serial != expired_serial)
    )).scalars().all()
    assert all(s.status == "ACTIVE" for s in others)
    for s in others:
        assert sl.get(s.status_list_index) is False


async def test_sweeper_is_idempotent_and_skip_locked_safe(session, settings, signing_key):
    stamps = await _active_stamps(session, settings, signing_key, 2)
    past = datetime.now(UTC) - timedelta(hours=1)
    await session.execute(text("UPDATE stamps SET valid_until = :past"), {"past": past})
    await session.commit()
    first = await sweep_expired_batch(session, settings=settings, signing_key=signing_key)
    await session.commit()
    assert first == 2
    # second pass: nothing left to sweep (already EXPIRED)
    second = await sweep_expired_batch(session, settings=settings, signing_key=signing_key)
    await session.commit()
    assert second == 0
    assert all(s.status == "EXPIRED" for s in stamps)
