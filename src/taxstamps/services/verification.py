"""First-scan-wins verification with full audit persistence.

- The first valid scan of an ACTIVE stamp CONSUMES it (ferry-boarding
  pattern). The transition happens under SELECT ... FOR UPDATE so
  concurrent first scans are serialized; exactly one wins.
- H3: consumption requires the stamp's verifiable credential. Serials are
  sequential (``NG-<CAT3>-<YYYY>-<SEQ10>-<Luhn>`` with a public check-digit
  algorithm), so the serial alone is trivially enumerable and is NEVER a
  capability: the VC proof (the QR secret) is verified BEFORE any mutation,
  its subject serial must match the presented serial, and no status-list
  purpose may be flagged. A serial-only or bad-proof presentation is
  recorded as ``invalid_credential`` and leaves the stamp ACTIVE. The
  residual enumeration risk (oracle via distinct outcomes) is mitigated by
  per-verifier nonce + rate limiting; longer-term mitigation is
  unguessable serial entropy or HMAC'd check digits (tracked in the
  security roadmap).
- The public self-service endpoint is a NON-CONSUMING pre-check: it
  reports stamp state and performs offline credential checks but never
  mutates the stamp, so an anonymous party can neither burn ACTIVE serials
  nor launder clones by becoming ``first_scan_verifier``.
- Repeat scans return already_verified with first-scan evidence; a repeat
  from a DIFFERENT device than the first scan returns clone_suspect and sets
  the stamp's ``suspect`` bit in the status list. The suspect flag is never
  suppressed merely because an earlier scan was anonymous: any repeat by a
  non-empty verifier that differs from the first-scan verifier flags.
- Velocity: >= N distinct devices in the trailing window flags clone_suspect.
- EVERY attempt (valid or not, public or authenticated) is persisted with
  device identity and integer micro-degree geo as audit substrate.

Offline (air-gapped) verification: the QR carries the full verifiable
credential; ``verify_credential_offline`` checks the issuer's Ed25519 proof
plus the cached status-list bits without any network access.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from taxstamps.config import Settings
from taxstamps.crypto.eddsa import SigningKey, verify_proof
from taxstamps.crypto.statuslist import StatusList
from taxstamps.domain.serials import SerialParts, build_serial, parse_serial
from taxstamps.models import Stamp, Verification, utcnow


class VerificationError(ValueError):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


def _result(
    outcome: str, serial: str, stamp: Stamp | None, detail: str = ""
) -> dict[str, Any]:
    result: dict[str, Any] = {"outcome": outcome, "serial": serial, "detail": detail}
    if stamp is not None:
        result["stamp"] = {
            "status": stamp.status,
            "category": stamp.category,
            "dutyPaidKobo": stamp.duty_paid_kobo,
            "validFrom": stamp.valid_from.isoformat(),
            "validUntil": stamp.valid_until.isoformat(),
        }
        if stamp.first_scan_at is not None:
            result["firstScan"] = {
                "at": stamp.first_scan_at.isoformat(),
                "verifierId": stamp.first_scan_verifier,
            }
    return result


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
            serial_presented=serial_presented,
            stamp_id=stamp.id if stamp is not None else None,
            verifier_id=verifier_id,
            public_scan=public_scan,
            outcome=outcome,
            detail=detail[:500],
            lat_micros=lat_micros,
            long_micros=long_micros,
        )
    )


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
    credential: dict[str, Any] | None = None,
    consume: bool = True,
    status_lists: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """First-scan-wins verification. Always records the attempt.

    ``consume=True`` (authenticated field verification) requires the stamp's
    verifiable credential and verifies its proof BEFORE consuming.
    ``consume=False`` (public pre-check) never mutates the stamp."""
    presented = (serial or "").strip().upper()
    try:
        parts = parse_serial(presented)
    except Exception as exc:
        await _record_attempt(
            session, serial_presented=presented[:64], stamp=None, verifier_id=verifier_id,
            public_scan=public_scan, outcome="malformed_serial", detail=str(exc),
            lat_micros=lat_micros, long_micros=long_micros,
        )
        await session.flush()
        return _result("malformed_serial", presented[:64], None, str(exc))

    stamp = (
        await session.execute(
            select(Stamp).where(Stamp.serial == parts.serial).with_for_update()
        )
    ).scalar_one_or_none()
    now = utcnow()

    if stamp is None:
        await _record_attempt(
            session, serial_presented=parts.serial, stamp=None, verifier_id=verifier_id,
            public_scan=public_scan, outcome="unknown_serial", detail="serial not issued",
            lat_micros=lat_micros, long_micros=long_micros,
        )
        await session.flush()
        return _result("unknown_serial", parts.serial, None, "serial not issued")

    if stamp.status == "VOID":
        await _record_attempt(
            session, serial_presented=parts.serial, stamp=stamp, verifier_id=verifier_id,
            public_scan=public_scan, outcome="void", detail="stamp voided",
            lat_micros=lat_micros, long_micros=long_micros,
        )
        await session.flush()
        return _result("void", parts.serial, stamp, "stamp voided")

    if now < stamp.valid_from or now > stamp.valid_until:
        await _record_attempt(
            session, serial_presented=parts.serial, stamp=stamp, verifier_id=verifier_id,
            public_scan=public_scan, outcome="expired", detail="outside validity window",
            lat_micros=lat_micros, long_micros=long_micros,
        )
        await session.flush()
        return _result("expired", parts.serial, stamp, "outside validity window")

    if stamp.status == "CONSUMED":
        suspect = stamp.first_scan_verifier != verifier_id and verifier_id != ""
        outcome = "clone_suspect" if suspect else "already_verified"
        await _record_attempt(
            session, serial_presented=parts.serial, stamp=stamp, verifier_id=verifier_id,
            public_scan=public_scan, outcome=outcome, detail="repeat scan",
            lat_micros=lat_micros, long_micros=long_micros,
        )
        if suspect:
            from taxstamps.services import statuslists

            await statuslists.set_bit(session, stamp=stamp, purpose="suspect", key=signing_key)
        await session.flush()
        return _result(outcome, parts.serial, stamp, "repeat scan")

    if stamp.status != "ACTIVE":
        await _record_attempt(
            session, serial_presented=parts.serial, stamp=stamp, verifier_id=verifier_id,
            public_scan=public_scan, outcome="not_active", detail=f"stamp is {stamp.status}",
            lat_micros=lat_micros, long_micros=long_micros,
        )
        await session.flush()
        return _result("not_active", parts.serial, stamp, f"stamp is {stamp.status}")

    # First scan on an ACTIVE stamp.
    if not consume:
        # Public non-consuming pre-check: report state, mutate nothing. The
        # stamp stays ACTIVE for the credential-bearing field scan.
        await _record_attempt(
            session, serial_presented=parts.serial, stamp=stamp, verifier_id=verifier_id,
            public_scan=public_scan, outcome="active", detail="non-consuming pre-check",
            lat_micros=lat_micros, long_micros=long_micros,
        )
        await session.flush()
        return _result("active", parts.serial, stamp, "non-consuming pre-check")

    # H3: the VC proof is verified BEFORE the stamp is consumed. The serial
    # alone is enumerable and never a capability.
    failures = _credential_failures(credential, parts.serial, signing_key, status_lists or {})
    if failures:
        detail = "; ".join(failures)
        await _record_attempt(
            session, serial_presented=parts.serial, stamp=stamp, verifier_id=verifier_id,
            public_scan=public_scan, outcome="invalid_credential", detail=detail,
            lat_micros=lat_micros, long_micros=long_micros,
        )
        await session.flush()
        return _result("invalid_credential", parts.serial, stamp, detail)

    # First scan wins: consume the stamp.
    stamp.status = "CONSUMED"
    stamp.first_scan_at = now
    stamp.first_scan_verifier = verifier_id
    await _record_attempt(
        session, serial_presented=parts.serial, stamp=stamp, verifier_id=verifier_id,
        public_scan=public_scan, outcome="valid", detail="first scan consumes stamp",
        lat_micros=lat_micros, long_micros=long_micros,
    )
    await session.flush()
    return _result("valid", parts.serial, stamp, "first scan consumes stamp")


async def verification_velocity(
    session: AsyncSession, *, stamp_id: Any, window_hours: int
) -> int:
    """Distinct verifier count in the trailing window (velocity signal)."""
    since = datetime.now(UTC).timestamp() - window_hours * 3600
    row = (
        await session.execute(
            select(func.count(func.distinct(Verification.verifier_id))).where(
                Verification.stamp_id == stamp_id,
                Verification.scanned_at >= datetime.fromtimestamp(since, UTC),
            )
        )
    ).scalar_one()
    return int(row)


def reissue_serial(parts: SerialParts, sequence: int) -> str:
    """Serial for a replacement stamp (same category/year, new sequence)."""
    return build_serial(parts.category, parts.year, sequence)


def verify_credential_offline(
    credential: dict[str, Any],
    issuer_public_key: bytes,
    status_lists: dict[str, StatusList],
) -> list[str]:
    """Offline verification of the QR-carried credential: proof + status bits.

    Returns a list of failure reasons (empty == valid). Air-gap safe: needs
    only the issuer public key and the cached status lists."""
    failures: list[str] = []
    if not verify_proof(credential, issuer_public_key):
        failures.append("bad-proof")
    subject = credential.get("credentialSubject", {})
    until = subject.get("validUntil") or credential.get("validUntil", "")
    try:
        expiry = datetime.strptime(str(until), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        if datetime.now(UTC) > expiry:
            failures.append("credential-expired")
    except ValueError:
        failures.append("malformed-validity")
    for entry in credential.get("credentialStatus", []) or []:
        purpose = entry.get("statusPurpose", "")
        index = int(entry.get("statusListIndex", "0"))
        status_list = status_lists.get(purpose)
        if status_list is None:
            # An unpublished list has no flags by construction: flags are
            # only ever set by publishing the list credential. Treating the
            # absence as a failure would break every unflagged credential
            # (and does not weaken detection of actually-flagged stamps).
            continue
        if status_list.get(index):
            failures.append(f"status-flagged:{purpose}")
    return failures


def _credential_failures(
    credential: dict[str, Any] | None,
    serial: str,
    signing_key: SigningKey,
    status_lists: dict[str, Any],
) -> list[str]:
    """Fail-closed consumption gate: the presented credential must carry a
    valid issuer proof, match the presented serial, and be unflagged on every
    status-list purpose."""
    if credential is None:
        return ["credential-required"]
    failures = verify_credential_offline(credential, signing_key.public_key, status_lists)
    subject_serial = credential.get("credentialSubject", {}).get("serial")
    if subject_serial != serial:
        failures.append("credential-serial-mismatch")
    return failures


def nonce_key(verifier_id: str, nonce: str) -> str:
    digest = hashlib.sha256(f"{verifier_id}:{nonce}".encode()).hexdigest()
    return f"taxstamps:nonce:{digest}"
