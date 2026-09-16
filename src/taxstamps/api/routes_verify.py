"""Verification endpoints.

POST /v1/verify        — authenticated field verification: per-verifier
                         credential (no shared fleet secret), Redis single-use
                         nonce + rate limit (fail-closed on Redis outage).
                         CONSUMES the stamp, and only after the presented
                         verifiable credential's proof, serial match and
                         status-list state pass (H3): the serial alone is
                         enumerable and never a capability.
POST /v1/verify/public — importer/consumer self-service: no device credential.
                         NON-CONSUMING pre-check (H3): reports stamp state and
                         performs offline signature + status-list checks when
                         a full credential is presented, but never mutates the
                         stamp, so anonymous callers can neither burn ACTIVE
                         serials nor launder clones as first_scan_verifier.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import select

from taxstamps.api import schemas
from taxstamps.api.auth import hash_verifier_credential
from taxstamps.api.deps import SessionDep, SettingsDep
from taxstamps.crypto.statuslist import PURPOSES, StatusList
from taxstamps.models import VerifierCredential
from taxstamps.services import redis_guard, statuslists, verification
from taxstamps.services.redis_guard import RedisUnavailable

router = APIRouter(prefix="/v1")


async def _authenticate_verifier(session, verifier_id: str, credential: str) -> VerifierCredential:  # type: ignore[no-untyped-def]
    if not verifier_id or not credential:
        raise HTTPException(status_code=401, detail={"reason": "missing-verifier-credential"})
    row = (
        await session.execute(
            select(VerifierCredential).where(VerifierCredential.verifier_id == verifier_id)
        )
    ).scalar_one_or_none()
    if row is None or not row.active:
        raise HTTPException(status_code=401, detail={"reason": "unknown-verifier"})
    assert isinstance(row, VerifierCredential)
    import hmac

    presented = hash_verifier_credential(verifier_id, credential)
    if not hmac.compare_digest(presented, row.credential_hash):
        raise HTTPException(status_code=401, detail={"reason": "invalid-verifier-credential"})
    return row


async def _load_status_lists(session) -> dict[str, StatusList]:  # type: ignore[no-untyped-def]
    """Current status lists for every purpose, for offline credential checks."""
    status_lists: dict[str, StatusList] = {}
    for purpose in PURPOSES:
        credential_doc = await statuslists.current_credential(session, purpose)
        if credential_doc is not None:
            from taxstamps.crypto.statuslist import parse_status_list_credential

            _, sl = parse_status_list_credential(credential_doc)
            status_lists[purpose] = sl
    return status_lists


@router.post("/verify")
async def verify(
    body: schemas.VerifyIn,
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
) -> dict[str, Any]:
    verifier_id = request.headers.get("x-verifier-id", "")
    credential = request.headers.get("x-verifier-credential", "")
    verifier = await _authenticate_verifier(session, verifier_id, credential)
    try:
        await redis_guard.rate_limit(
            f"verify:{verifier.verifier_id}", settings.rate_limit_per_minute
        )
        await redis_guard.claim_nonce(verification.nonce_key(verifier.verifier_id, body.nonce))
    except RedisUnavailable as exc:
        raise HTTPException(
            status_code=503,
            detail={"reason": "redis-unavailable",
                    "detail": "verification is fail-closed when Redis is unavailable"},
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=429, detail={"reason": "nonce-or-rate-limit", "detail": str(exc)}) from exc
    result = await verification.verify_stamp(
        session,
        serial=body.serial,
        verifier_id=verifier.verifier_id,
        public_scan=False,
        settings=settings,
        signing_key=request.app.state.signing_key,
        lat_micros=body.lat_micros,
        long_micros=body.long_micros,
        credential=body.credential,
        consume=True,
        status_lists=await _load_status_lists(session),
    )
    await session.commit()
    return result


@router.post("/verify/public")
async def verify_public(
    body: schemas.PublicVerifyIn,
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
) -> dict[str, Any]:
    """Self-service verification: no device credential. Rate-limited by client
    address when Redis is configured; when Redis is configured-but-down the
    endpoint is fail-closed like the authenticated one."""
    if settings.redis_configured:
        try:
            client_ip = request.client.host if request.client else "unknown"
            await redis_guard.rate_limit(f"verify-public:{client_ip}", settings.rate_limit_per_minute)
        except RedisUnavailable as exc:
            raise HTTPException(
                status_code=503,
                detail={"reason": "redis-unavailable",
                        "detail": "verification is fail-closed when Redis is unavailable"},
            ) from exc
        except ValueError as exc:
            raise HTTPException(status_code=429, detail={"reason": "rate-limit", "detail": str(exc)}) from exc
    response: dict[str, Any] = {}
    serial = body.serial
    if body.credential is not None:
        subject = body.credential.get("credentialSubject", {})
        serial = serial or subject.get("serial")
        # Offline checks: proof signature + status-list bits.
        status_lists: dict[str, StatusList] = {}
        for purpose in PURPOSES:
            credential_doc = await statuslists.current_credential(session, purpose)
            if credential_doc is not None:
                from taxstamps.crypto.statuslist import parse_status_list_credential

                _, sl = parse_status_list_credential(credential_doc)
                status_lists[purpose] = sl
        failures = verification.verify_credential_offline(
            body.credential, request.app.state.signing_key.public_key, status_lists
        )
        response["credentialCheck"] = {"ok": not failures, "failures": failures}
    if serial:
        result = await verification.verify_stamp(
            session,
            serial=serial,
            verifier_id="",
            public_scan=True,
            settings=settings,
            signing_key=request.app.state.signing_key,
            lat_micros=body.lat_micros,
            long_micros=body.long_micros,
            consume=False,
        )
        response.update(result)
    await session.commit()
    return response
