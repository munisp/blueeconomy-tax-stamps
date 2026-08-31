"""First-scan-wins verification, clone-suspect analytics, attempt ledger."""

import asyncio

from sqlalchemy import func, select, text

from taxstamps.crypto.statuslist import parse_status_list_credential
from taxstamps.models import Stamp, Verification
from taxstamps.services import issuance, statuslists, verification
from taxstamps.services.verification import approve_void, request_void
from tests.integration.conftest import make_paid_assessment


async def _two_party_void(session, *, serial, settings, signing_key,
                          requester="approver-1", approver="approver-2"):
    await request_void(session, serial=serial, reason="counterfeit batch",
                       principal_sub=requester)
    return await approve_void(session, serial=serial, principal_sub=approver,
                              settings=settings, signing_key=signing_key)


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


async def test_first_scan_wins_then_already_verified(session, settings, signing_key):
    stamps = await _active_stamps(session, settings, signing_key, 1)
    serial = stamps[0].serial
    r1 = await verification.verify_stamp(
        session, serial=serial, verifier_id="dev-1", public_scan=False,
        settings=settings, signing_key=signing_key, lat_micros=6_500_000, long_micros=3_400_000,
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
                                    public_scan=False, settings=settings, signing_key=signing_key)
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


# ------------------------------------------------- TS-6: non-consuming public path


async def test_public_scan_is_non_consuming(session, settings, signing_key):
    stamps = await _active_stamps(session, settings, signing_key, 1)
    serial = stamps[0].serial
    result = await verification.verify_stamp(
        session, serial=serial, verifier_id="", public_scan=True,
        settings=settings, signing_key=signing_key,
    )
    await session.commit()
    assert result["outcome"] == "valid"
    assert "non-consuming" in result["detail"]
    stamp = (await session.execute(select(Stamp).where(Stamp.serial == serial))).scalar_one()
    assert stamp.status == "ACTIVE"          # never burned by a public scan
    assert stamp.first_scan_at is None
    # a credentialed first scan still consumes afterwards
    r2 = await verification.verify_stamp(
        session, serial=serial, verifier_id="dev-1", public_scan=False,
        settings=settings, signing_key=signing_key,
    )
    await session.commit()
    assert r2["outcome"] == "valid"
    stamp = (await session.execute(select(Stamp).where(Stamp.serial == serial))).scalar_one()
    assert stamp.status == "CONSUMED"
    assert stamp.first_scan_verifier == "dev-1"


async def test_mass_public_scans_do_not_burn(session, settings, signing_key):
    stamps = await _active_stamps(session, settings, signing_key, 1)
    serial = stamps[0].serial
    for _ in range(25):
        r = await verification.verify_stamp(
            session, serial=serial, verifier_id="", public_scan=True,
            settings=settings, signing_key=signing_key,
        )
        assert r["outcome"] == "valid"
    await session.commit()
    stamp = (await session.execute(select(Stamp).where(Stamp.serial == serial))).scalar_one()
    assert stamp.status == "ACTIVE"
    assert stamp.first_scan_at is None
    attempts = (await session.execute(
        select(func.count()).select_from(Verification).where(Verification.serial_presented == serial)
    )).scalar_one()
    assert attempts == 25  # every public attempt still audited


async def test_public_scan_of_consumed_stamp_not_clone_suspect(session, settings, signing_key):
    stamps = await _active_stamps(session, settings, signing_key, 1)
    serial = stamps[0].serial
    await verification.verify_stamp(session, serial=serial, verifier_id="dev-1",
                                    public_scan=False, settings=settings, signing_key=signing_key)
    await session.commit()
    r = await verification.verify_stamp(session, serial=serial, verifier_id="",
                                        public_scan=True, settings=settings, signing_key=signing_key)
    await session.commit()
    assert r["outcome"] == "already_verified"
    stamp = (await session.execute(select(Stamp).where(Stamp.serial == serial))).scalar_one()
    assert stamp.status == "CONSUMED"  # public scan cannot flag SUSPECT


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
                                    public_scan=False, settings=settings, signing_key=signing_key)
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
    stamp = await _two_party_void(session, serial=serial, settings=settings, signing_key=signing_key)
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
        await request_void(session, serial=stamps[0].serial, reason="  ",
                           principal_sub="approver-1")
    await session.rollback()


async def test_single_actor_void_rejected(session, settings, signing_key):
    """TS-8: the void requester can never approve their own void request."""
    import pytest

    from taxstamps.services.verification import VerificationError

    stamps = await _active_stamps(session, settings, signing_key, 1)
    serial = stamps[0].serial
    await request_void(session, serial=serial, reason="single actor attempt",
                       principal_sub="approver-1")
    with pytest.raises(VerificationError, match="self-approval"):
        await approve_void(session, serial=serial, principal_sub="approver-1",
                           settings=settings, signing_key=signing_key)
    await session.rollback()
    stamp = (await session.execute(select(Stamp).where(Stamp.serial == serial))).scalar_one()
    assert stamp.status == "ACTIVE"  # untouched


async def test_two_party_void_succeeds(session, settings, signing_key):
    """TS-8: requester (excise-approver) + distinct approver -> void executes."""
    stamps = await _active_stamps(session, settings, signing_key, 1)
    serial = stamps[0].serial
    req = await request_void(session, serial=serial, reason="damaged in transit",
                             principal_sub="approver-1")
    assert req.status == "PENDING"
    stamp = await approve_void(session, serial=serial, principal_sub="approver-2",
                               settings=settings, signing_key=signing_key)
    await session.commit()
    assert stamp.status == "VOID"
    credential = await statuslists.current_credential(session, "void")
    _, sl = parse_status_list_credential(credential)
    assert sl.get(stamp.status_list_index)


async def test_void_api_maker_checker(session, oidc_client, settings, signing_key):
    """TS-8 regression (API): single-actor void -> 409; two-party -> succeeds."""
    stamps = await _active_stamps(session, settings, signing_key, 1)
    serial = stamps[0].serial
    client, mint = oidc_client
    h1 = {"Authorization": f"Bearer {mint('approver-1', ['excise-approver'])}"}
    h2 = {"Authorization": f"Bearer {mint('approver-2', ['excise-approver'])}"}
    resp = client.post(f"/v1/stamps/{serial}/void", json={"reason": "api void test"}, headers=h1)
    assert resp.status_code == 202
    assert resp.json()["voidStatus"] == "PENDING"
    # single-actor: the requester cannot approve their own request
    resp = client.post(f"/v1/stamps/{serial}/void/approve", headers=h1)
    assert resp.status_code == 409
    assert resp.json()["detail"]["reason"] == "self-approval"
    # two-party void succeeds
    resp = client.post(f"/v1/stamps/{serial}/void/approve", headers=h2)
    assert resp.status_code == 200
    assert resp.json()["status"] == "VOID"


async def test_offline_credential_check(session, settings, signing_key):
    stamps = await _active_stamps(session, settings, signing_key, 1)
    stamp = stamps[0]
    await _two_party_void(session, serial=stamp.serial, settings=settings, signing_key=signing_key)
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
