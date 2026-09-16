"""First-scan-wins verification, clone-suspect analytics, attempt ledger."""

import asyncio

from sqlalchemy import func, select, text

from taxstamps.crypto.statuslist import parse_status_list_credential
from taxstamps.models import Stamp, Verification
from taxstamps.services import issuance, statuslists, verification
from taxstamps.services.verification import void_stamp
from tests.integration.conftest import make_paid_assessment


async def _active_stamps(session, settings, signing_key, stamps=10):
    assessment = await make_paid_assessment(session, settings, duty_lines=[
        {"hs_code": "2402.20", "quantity": stamps, "unit": "STICK",
         "customs_value_kobo": 0, "stamps_required": stamps},
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
    rows = (await session.execute(select(Stamp).where(Stamp.batch_id == batch.id))).scalars().all()
    return rows



async def _consume_kwargs(session, stamp):
    """Credential + status lists required for the H3 consumption gate."""
    status_lists = {}
    for purpose in ("void", "expired", "suspect"):
        cred = await statuslists.current_credential(session, purpose)
        if cred is not None:
            _, sl = parse_status_list_credential(cred)
            status_lists[purpose] = sl
    return {"credential": stamp.credential, "status_lists": status_lists}

async def test_first_scan_wins_then_already_verified(session, settings, signing_key):
    stamps = await _active_stamps(session, settings, signing_key, 1)
    serial = stamps[0].serial
    r1 = await verification.verify_stamp(
        session, serial=serial, verifier_id="dev-1", public_scan=False,
        settings=settings, signing_key=signing_key, lat_micros=6_500_000, long_micros=3_400_000,
        **(await _consume_kwargs(session, stamps[0])),
    )
    await session.commit()
    assert r1["outcome"] == "valid"
    assert r1["firstScan"]["verifierId"] == "dev-1"
    r2 = await verification.verify_stamp(
        session, serial=serial, verifier_id="dev-1", public_scan=False,
        settings=settings, signing_key=signing_key,
    )
    await session.commit()
    assert r2["outcome"] == "already_verified"
    assert r2["firstScan"]["latMicros"] == 6_500_000


async def test_repeat_scan_from_other_device_clone_suspect(session, settings, signing_key):
    stamps = await _active_stamps(session, settings, signing_key, 1)
    serial = stamps[0].serial
    await verification.verify_stamp(session, serial=serial, verifier_id="dev-1",
                                    public_scan=False, settings=settings, signing_key=signing_key,
                                    **(await _consume_kwargs(session, stamps[0])))
    await session.commit()
    r = await verification.verify_stamp(session, serial=serial, verifier_id="dev-2",
                                        public_scan=False, settings=settings, signing_key=signing_key)
    await session.commit()
    assert r["outcome"] == "clone_suspect"
    # suspect bit set in the published status list
    credential = await statuslists.current_credential(session, "suspect")
    assert credential is not None
    _, sl = parse_status_list_credential(credential)
    assert sl.get(stamps[0].status_list_index)
    stamp = (await session.execute(select(Stamp).where(Stamp.serial == serial))).scalar_one()
    assert stamp.status == "SUSPECT"


async def test_first_scan_race_exactly_one_winner(session_factory, settings, signing_key):
    factory = session_factory
    async with factory() as s:
        stamps = await _active_stamps(s, settings, signing_key, 1)
        serial = stamps[0].serial

    async def scan(device):
        async with factory() as s:
            result = await verification.verify_stamp(
                s, serial=serial, verifier_id=device, public_scan=False,
                settings=settings, signing_key=signing_key,
                **(await _consume_kwargs(s, stamps[0])),
            )
            await s.commit()
            return result["outcome"]

    outcomes = await asyncio.gather(*[scan(f"dev-{i}") for i in range(8)])
    assert outcomes.count("valid") == 1
    assert all(o in ("valid", "already_verified", "clone_suspect") for o in outcomes)
    async with factory() as s:
        attempts = (await s.execute(
            select(func.count()).select_from(Verification).where(Verification.serial_presented == serial)
        )).scalar_one()
        assert attempts == 8  # every attempt recorded, including losers


async def test_unknown_and_malformed_serials_recorded(session, settings, signing_key):
    r1 = await verification.verify_stamp(session, serial="NG-TBC-2026-0000000001-0",
                                         verifier_id="dev-1", public_scan=True,
                                         settings=settings, signing_key=signing_key)
    r2 = await verification.verify_stamp(session, serial="not-a-serial",
                                         verifier_id="dev-1", public_scan=True,
                                         settings=settings, signing_key=signing_key)
    await session.commit()
    assert r1["outcome"] in ("unknown_serial", "malformed_serial")
    assert r2["outcome"] == "malformed_serial"
    count = (await session.execute(select(func.count()).select_from(Verification))).scalar_one()
    assert count == 2


async def test_velocity_clone_suspect_flag(session, settings, signing_key):
    stamps = await _active_stamps(session, settings, signing_key, 1)
    serial = stamps[0].serial
    # three distinct devices inside 24h
    await verification.verify_stamp(session, serial=serial, verifier_id="dev-a",
                                    public_scan=False, settings=settings, signing_key=signing_key,
                                    **(await _consume_kwargs(session, stamps[0])))
    await verification.verify_stamp(session, serial=serial, verifier_id="dev-b",
                                    public_scan=False, settings=settings, signing_key=signing_key)
    await verification.verify_stamp(session, serial=serial, verifier_id="dev-c",
                                    public_scan=False, settings=settings, signing_key=signing_key)
    await session.commit()
    distinct = (await session.execute(text(
        "SELECT count(DISTINCT verifier_id) FROM verifications WHERE serial_presented = :s"
    ), {"s": serial})).scalar_one()
    assert distinct == 3  # substrate for the velocity rule (window >= 3 distinct devices)


async def test_void_flow_sets_status_bit_and_blocks_scan(session, settings, signing_key):
    stamps = await _active_stamps(session, settings, signing_key, 1)
    serial = stamps[0].serial
    stamp = await void_stamp(session, serial=serial, reason="counterfeit batch",
                             principal_sub="approver-1", settings=settings, signing_key=signing_key)
    await session.commit()
    assert stamp.status == "VOID"
    credential = await statuslists.current_credential(session, "void")
    _, sl = parse_status_list_credential(credential)
    assert sl.get(stamps[0].status_list_index)
    r = await verification.verify_stamp(session, serial=serial, verifier_id="dev-1",
                                        public_scan=False, settings=settings, signing_key=signing_key)
    await session.commit()
    assert r["outcome"] == "void"
    rows = (await session.execute(text(
        "SELECT count(*) FROM outbox_messages WHERE topic = 'stamps.voided'"
    ))).scalar_one()
    assert rows == 1


async def test_void_requires_reason(session, settings, signing_key):
    stamps = await _active_stamps(session, settings, signing_key, 1)
    import pytest

    with pytest.raises(Exception, match="reason-required"):
        await void_stamp(session, serial=stamps[0].serial, reason="  ",
                         principal_sub="approver-1", settings=settings, signing_key=signing_key)
    await session.rollback()


async def test_offline_credential_check(session, settings, signing_key):
    stamps = await _active_stamps(session, settings, signing_key, 1)
    stamp = stamps[0]
    await void_stamp(session, serial=stamp.serial, reason="test void",
                     principal_sub="approver-1", settings=settings, signing_key=signing_key)
    await session.commit()
    status_lists = {}
    for purpose in ("void", "expired", "suspect"):
        cred = await statuslists.current_credential(session, purpose)
        if cred is not None:
            _, sl = parse_status_list_credential(cred)
            status_lists[purpose] = sl
    failures = verification.verify_credential_offline(
        stamp.credential, signing_key.public_key, status_lists
    )
    assert "status-flagged:void" in failures


async def test_consumption_requires_valid_vc(session, settings, signing_key):
    """H3: the enumerable serial alone never consumes; a valid proof does."""
    stamps = await _active_stamps(session, settings, signing_key, 1)
    stamp = stamps[0]
    serial = stamp.serial

    # Serial-only presentation: recorded, not consumed.
    r = await verification.verify_stamp(
        session, serial=serial, verifier_id="dev-1", public_scan=False,
        settings=settings, signing_key=signing_key,
    )
    await session.commit()
    assert r["outcome"] == "invalid_credential"
    assert "credential-required" in r["detail"]
    await session.refresh(stamp)
    assert stamp.status == "ACTIVE"
    assert stamp.first_scan_at is None

    # A credential minted for a DIFFERENT serial is rejected.
    other = await _active_stamps(session, settings, signing_key, 1)
    r = await verification.verify_stamp(
        session, serial=serial, verifier_id="dev-1", public_scan=False,
        settings=settings, signing_key=signing_key,
        credential=other[0].credential, status_lists={},
    )
    await session.commit()
    assert r["outcome"] == "invalid_credential"
    assert "credential-serial-mismatch" in r["detail"]
    await session.refresh(stamp)
    assert stamp.status == "ACTIVE"

    # A tampered proof is rejected.
    import copy
    tampered = copy.deepcopy(stamp.credential)
    tampered["credentialSubject"]["dutyPaidKobo"] = 1
    r = await verification.verify_stamp(
        session, serial=serial, verifier_id="dev-1", public_scan=False,
        settings=settings, signing_key=signing_key, credential=tampered,
        **{"status_lists": (await _consume_kwargs(session, stamp))["status_lists"]},
    )
    await session.commit()
    assert r["outcome"] == "invalid_credential"
    await session.refresh(stamp)
    assert stamp.status == "ACTIVE"

    # The valid credential consumes exactly once.
    r = await verification.verify_stamp(
        session, serial=serial, verifier_id="dev-1", public_scan=False,
        settings=settings, signing_key=signing_key,
        **(await _consume_kwargs(session, stamp)),
    )
    await session.commit()
    assert r["outcome"] == "valid"
    await session.refresh(stamp)
    assert stamp.status == "CONSUMED"


async def test_public_precheck_never_consumes(session, settings, signing_key):
    """H3: the anonymous pre-check reports state but mutates nothing, so it
    can neither burn an ACTIVE serial nor launder a clone as first scanner."""
    stamps = await _active_stamps(session, settings, signing_key, 1)
    stamp = stamps[0]
    serial = stamp.serial
    r = await verification.verify_stamp(
        session, serial=serial, verifier_id="", public_scan=True,
        settings=settings, signing_key=signing_key, consume=False,
    )
    await session.commit()
    assert r["outcome"] == "active"
    await session.refresh(stamp)
    assert stamp.status == "ACTIVE"
    assert stamp.first_scan_at is None
    # The credential-bearing field scan still wins the first scan.
    r = await verification.verify_stamp(
        session, serial=serial, verifier_id="dev-1", public_scan=False,
        settings=settings, signing_key=signing_key,
        **(await _consume_kwargs(session, stamp)),
    )
    await session.commit()
    assert r["outcome"] == "valid"
    assert r["firstScan"]["verifierId"] == "dev-1"


async def test_suspect_never_suppressed_for_anonymous_first_scan(session, settings, signing_key):
    """A repeat by a real verifier after an anonymous first scan flags
    clone_suspect; anonymity of the first scan never launders the repeat."""
    stamps = await _active_stamps(session, settings, signing_key, 1)
    stamp = stamps[0]
    stamp.status = "CONSUMED"
    stamp.first_scan_verifier = ""
    from datetime import UTC, datetime
    stamp.first_scan_at = datetime.now(UTC)
    await session.commit()
    r = await verification.verify_stamp(
        session, serial=stamp.serial, verifier_id="dev-1", public_scan=False,
        settings=settings, signing_key=signing_key,
    )
    await session.commit()
    assert r["outcome"] == "clone_suspect"
