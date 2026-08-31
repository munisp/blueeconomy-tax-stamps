"""Verification: first-scan-wins with clone-suspect analytics.

- CONSUMPTION requires verifier credentials: the first CREDENTIALLED scan of
  an ACTIVE stamp CONSUMES it (ferry-boarding pattern). The transition
  happens under SELECT ... FOR UPDATE so concurrent first scans are
  serialized; exactly one wins.
- PUBLIC scans (no device credential) are NON-CONSUMING: they return
  validity/outcome and status-list state but NEVER transition
  ACTIVE -> CONSUMED. Serials are enumerable per category/year, so a
  consuming public path would let anyone mass-burn genuine active stamps.
  Clone-detection (first-scan-wins) applies only to credentialed
  consumption scans; the public path additionally carries a per-serial
  scan-rate cap (beyond per-IP) when Redis is present.
- Repeat credentialed scans return already_verified with first-scan
  evidence; a repeat from a DIFFERENT device than the first scan returns
  clone_suspect and sets the stamp's ``suspect`` bit in the status list.
- Velocity: >= N distinct devices in the trailing window flags clone_suspect.
- EVERY attempt (valid or not, public or authenticated) is persisted with
  device identity and integer micro-degree geo as audit substrate.
- Redis (nonce / rate limit) failure closes the endpoint: 503, never a
  fail-open scan.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from taxstamps.config import Settings
from taxstamps.crypto.eddsa import SigningKey
from taxstamps.crypto.vc import VCError, verify_proof
from taxstamps.domain.serials import SerialError, parse_serial
from taxstamps.models import Stamp, StampVoidRequest, Verification
from taxstamps.services import outbox, statuslists


class VerificationError(ValueError):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


def _result(
    outcome: str,
    serial: str,
    stamp: Stamp | None,
    detail: str = "",
) -> dict[str, Any]:
    body: dict[str, Any] = {"outcome": outcome, "serial": serial, "detail": detail}
    if stamp is not None and stamp.first_scan_at is not None:
        body["firstScan"] = {
            "at": stamp.first_scan_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "verifierId": stamp.first_scan_verifier,
            "latMicros": stamp.first_scan_lat_micros,
            "longMicros": stamp.first_scan_long_micros,
        }
    return body


async def _record_attempt(
    session: AsyncSession,
    *,
    serial_presented: str,
    stamp: Stamp | None,
    verifier_id: str,
    public_scan: bool,
    outcome: str,
    detail: str,
    lat_micros: int | None,
    long_micros: int | None,
) -> None:
    session.add(
        Verification(
            id=uuid.uuid4(),
            stamp_id=stamp.id if stamp else None,
            serial_presented=serial_presented,
            verifier_id=verifier_id,
            public_scan=public_scan,
            outcome=outcome,
            detail=detail,
            lat_micros=lat_micros,
            long_micros=long_micros,
        )
    )
    await session.flush()


async def _velocity_suspect(session: AsyncSession, stamp_id: uuid.UUID, settings: Settings) -> bool:
    window_start = datetime.now(UTC) - timedelta(hours=settings.velocity_window_hours)
    distinct = (
        await session.execute(
            select(func.count(func.distinct(Verification.verifier_id))).where(
                Verification.stamp_id == stamp_id,
                Verification.verified_at >= window_start,
                Verification.verifier_id != "",
            )
        )
    ).scalar_one()
    return distinct >= settings.velocity_distinct_devices


async def verify_stamp(
    session: AsyncSession,
    *,
    serial: str,
    verifier_id: str,
    public_scan: bool,
    settings: Settings,
    signing_key: SigningKey,
    lat_micros: int | None = None,
    long_micros: int | None = None,
) -> dict[str, Any]:
    """First-scan-wins verification. Always records the attempt."""
    presented = (serial or "").strip().upper()
    try:
        parts = parse_serial(presented)
    except SerialError as exc:
        await _record_attempt(
            session, serial_presented=presented[:64], stamp=None, verifier_id=verifier_id,
            public_scan=public_scan, outcome="malformed_serial", detail=str(exc),
            lat_micros=lat_micros, long_micros=long_micros,
        )
        return _result("malformed_serial", presented, None, str(exc))

    stamp = (
        await session.execute(
            select(Stamp).where(Stamp.serial == parts.serial).with_for_update()
        )
    ).scalars().first()
    if stamp is None:
        await _record_attempt(
            session, serial_presented=parts.serial, stamp=None, verifier_id=verifier_id,
            public_scan=public_scan, outcome="unknown_serial", detail="",
            lat_micros=lat_micros, long_micros=long_micros,
        )
        return _result("unknown_serial", parts.serial, None)

    # Terminal stamp states short-circuit (still recorded).
    now = datetime.now(UTC)
    if stamp.status == "VOID":
        await _record_attempt(
            session, serial_presented=parts.serial, stamp=stamp, verifier_id=verifier_id,
            public_scan=public_scan, outcome="void", detail="",
            lat_micros=lat_micros, long_micros=long_micros,
        )
        return _result("void", parts.serial, stamp)
    if stamp.status == "EXPIRED" or stamp.valid_until <= now:
        await _record_attempt(
            session, serial_presented=parts.serial, stamp=stamp, verifier_id=verifier_id,
            public_scan=public_scan, outcome="expired", detail="",
            lat_micros=lat_micros, long_micros=long_micros,
        )
        return _result("expired", parts.serial, stamp)
    if stamp.status == "CONSUMED" or stamp.first_scan_at is not None:
        suspect = stamp.first_scan_verifier != verifier_id and verifier_id != ""
        outcome = "clone_suspect" if suspect else "already_verified"
        await _record_attempt(
            session, serial_presented=parts.serial, stamp=stamp, verifier_id=verifier_id,
            public_scan=public_scan, outcome=outcome, detail="repeat scan",
            lat_micros=lat_micros, long_micros=long_micros,
        )
        if suspect:
            stamp.status = "SUSPECT"
            await statuslists.set_flag(
                session, purpose="suspect", index=stamp.status_list_index,
                settings=settings, signing_key=signing_key,
                verification_method=f"{settings.issuer_did}#ed25519-{signing_key.kid}",
            )
        await session.flush()
        return _result(outcome, parts.serial, stamp, "repeat scan")
    if stamp.status != "ACTIVE":
        await _record_attempt(
            session, serial_presented=parts.serial, stamp=stamp, verifier_id=verifier_id,
            public_scan=public_scan, outcome="not_active", detail=f"stamp is {stamp.status}",
            lat_micros=lat_micros, long_micros=long_micros,
        )
        return _result("not_active", parts.serial, stamp, f"stamp is {stamp.status}")

    # ACTIVE stamp: public scans are non-consuming; only a credentialed
    # first scan consumes the stamp.
    detail = "first scan"
    if public_scan:
        # Non-consuming public scan: report validity + status-list state but
        # leave the stamp ACTIVE so importers' goods can never be mass-burned
        # by an untrusted party enumerating serials.
        detail = "public scan (non-consuming)"
    else:
        # First credentialed scan wins: consume the stamp.
        stamp.status = "CONSUMED"
        stamp.first_scan_at = now
        stamp.first_scan_verifier = verifier_id
        stamp.first_scan_lat_micros = lat_micros
        stamp.first_scan_long_micros = long_micros
    await _record_attempt(
        session, serial_presented=parts.serial, stamp=stamp, verifier_id=verifier_id,
        public_scan=public_scan, outcome="valid", detail=detail,
        lat_micros=lat_micros, long_micros=long_micros,
    )
    if not public_scan:
        # A batch whose stamps are all in terminal states is closed out.
        from taxstamps.services import issuance

        await issuance.refresh_batch_terminal_state(session, batch_id=stamp.batch_id)
    velocity = await _velocity_suspect(session, stamp.id, settings)
    await outbox.enqueue(
        session,
        event_type="stamps.verified.v1",
        resource={
            "serial": stamp.serial,
            "batchId": str(stamp.batch_id),
            "verifierId": verifier_id,
            "publicScan": public_scan,
            "latMicros": lat_micros,
            "longMicros": long_micros,
            "velocitySuspect": velocity,
        },
        signing_key=signing_key,
        principal_id=verifier_id or "public",
        principal_role="verifier",
        correlation_id=stamp.declaration_ref,
    )
    await session.flush()
    return _result("valid", parts.serial, stamp, detail)


async def request_void(
    session: AsyncSession,
    *,
    serial: str,
    reason: str,
    principal_sub: str,
) -> StampVoidRequest:
    """Request a stamp void (maker step). The void executes only when a
    DIFFERENT excise-approver approves it — same maker-checker bar as
    assessments. Idempotent: one PENDING request per serial."""
    if not reason or not reason.strip():
        raise VerificationError("reason-required", "void requires a reason")
    normalized = serial.strip().upper()
    stamp = (
        await session.execute(select(Stamp).where(Stamp.serial == normalized))
    ).scalars().first()
    if stamp is None:
        raise VerificationError("not-found", "unknown serial")
    if stamp.status == "VOID":
        raise VerificationError("already-void", f"stamp {normalized} is already VOID")
    pending = (
        await session.execute(
            select(StampVoidRequest).where(
                StampVoidRequest.serial == normalized, StampVoidRequest.status == "PENDING"
            )
        )
    ).scalars().first()
    if pending is not None:
        return pending
    request = StampVoidRequest(
        id=uuid.uuid4(),
        serial=normalized,
        reason=reason,
        requested_by=principal_sub,
    )
    session.add(request)
    await session.flush()
    return request


async def approve_void(
    session: AsyncSession,
    *,
    serial: str,
    principal_sub: str,
    settings: Settings,
    signing_key: SigningKey,
) -> Stamp:
    """Approve a pending void request (checker step) and execute the void:
    stamp status VOID + the ``void`` status-list bit + outbox event.

    The requester can NEVER approve their own request (409 at the API layer),
    consistent with the assessment maker-checker pattern.
    """
    normalized = serial.strip().upper()
    request = (
        await session.execute(
            select(StampVoidRequest)
            .where(StampVoidRequest.serial == normalized, StampVoidRequest.status == "PENDING")
            .with_for_update()
        )
    ).scalars().first()
    if request is None:
        raise VerificationError("no-pending-request", f"no pending void request for {normalized}")
    if request.requested_by == principal_sub:
        raise VerificationError(
            "self-approval", "the void requester cannot approve their own void request"
        )
    stamp = (
        await session.execute(
            select(Stamp).where(Stamp.serial == normalized).with_for_update()
        )
    ).scalars().first()
    if stamp is None:
        raise VerificationError("not-found", "unknown serial")
    if stamp.status != "VOID":
        stamp.status = "VOID"
        await statuslists.set_flag(
            session, purpose="void", index=stamp.status_list_index,
            settings=settings, signing_key=signing_key,
            verification_method=f"{settings.issuer_did}#ed25519-{signing_key.kid}",
        )
        await outbox.enqueue(
            session,
            event_type="stamps.voided.v1",
            resource={
                "serial": stamp.serial,
                "reason": request.reason,
                "batchId": str(stamp.batch_id),
                "requestedBy": request.requested_by,
                "approvedBy": principal_sub,
            },
            signing_key=signing_key,
            principal_id=principal_sub,
            principal_role="excise-approver",
            correlation_id=stamp.declaration_ref,
        )
    request.status = "EXECUTED"
    request.approved_by = principal_sub
    request.decided_at = datetime.now(UTC)
    # A batch whose stamps are now all in terminal states is closed out.
    from taxstamps.services import issuance

    await issuance.refresh_batch_terminal_state(session, batch_id=stamp.batch_id)
    await session.flush()
    return stamp


def verify_credential_offline(
    credential: dict[str, Any],
    public_key: Any,
    status_lists: dict[str, Any],
) -> list[str]:
    """Public self-service checks: proof + status-list bits. Returns a list of
    failure reason codes (empty == verifiable)."""
    failures: list[str] = []
    try:
        verify_proof(credential, public_key)
    except VCError as exc:
        failures.append(exc.reason)
    statuses = credential.get("credentialStatus", [])
    if isinstance(statuses, dict):
        statuses = [statuses]
    for entry in statuses:
        purpose = entry.get("statusPurpose")
        index = int(entry.get("statusListIndex", "0"))
        status_list = status_lists.get(purpose)
        if status_list is None:
            failures.append(f"status-list-unavailable:{purpose}")
            continue
        if status_list.get(index):
            failures.append(f"status-flagged:{purpose}")
    return failures


def nonce_key(verifier_id: str, nonce: str) -> str:
    digest = hashlib.sha256(f"{verifier_id}:{nonce}".encode()).hexdigest()
    return f"taxstamps:nonce:{digest}"
