"""FastAPI dependencies: settings, DB sessions, OIDC identity, PBAC, idempotency."""

from __future__ import annotations

import hashlib
import json
from collections.abc import AsyncIterator
from typing import Annotated, Any

from fastapi import Depends, Header, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from taxstamps.api.auth import AuthError, Identity, verify_bearer
from taxstamps.api.pbac import PolicyEngine
from taxstamps.config import Settings
from taxstamps.crypto.eddsa import SigningKey
from taxstamps.db import session as db_session
from taxstamps.models import IdempotencyRecord


def problem(status: int, title: str, detail: str = "", type_: str = "about:blank") -> JSONResponse:
    return JSONResponse(
        status_code=status,
        media_type="application/problem+json",
        content={"type": type_, "title": title, "status": status, "detail": detail},
    )


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


def get_signing_key(request: Request) -> SigningKey:
    return request.app.state.signing_key


def get_policy_engine(request: Request) -> PolicyEngine:
    return request.app.state.policy_engine


async def get_session() -> AsyncIterator[AsyncSession]:
    async with db_session() as s:
        yield s


SessionDep = Annotated[AsyncSession, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(get_settings_dep)]


async def get_identity(request: Request, settings: SettingsDep) -> Identity:
    """Verified OIDC identity or 401/503. Fail-closed: when OIDC is not
    configured there is no anonymous fallback — 503."""
    if not settings.oidc_configured or getattr(request.app.state, "keyring", None) is None:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=503,
            detail={"reason": "auth-oidc-unavailable",
                    "detail": "OIDC is not configured; see GET /v1/capabilities"},
        )
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        from fastapi import HTTPException

        raise HTTPException(status_code=401, detail={"reason": "missing-bearer"})
    try:
        return verify_bearer(auth.removeprefix("Bearer ").strip(), request.app.state.keyring, settings)
    except AuthError as exc:
        from fastapi import HTTPException

        raise HTTPException(status_code=401, detail={"reason": exc.reason, "detail": str(exc)}) from exc


IdentityDep = Annotated[Identity, Depends(get_identity)]


def require_policy(request: Request, identity: Identity, resource: str, action: str, classification: str) -> None:
    from fastapi import HTTPException

    engine: PolicyEngine = request.app.state.policy_engine
    if not engine.allow(identity, resource, action, classification):
        raise HTTPException(
            status_code=403,
            detail={"reason": "pbac-denied", "resource": resource, "action": action},
        )


async def idempotent_replay(
    session: AsyncSession,
    key: str | None,
    principal_sub: str,
    request_body: dict[str, Any],
) -> IdempotencyRecord | None:
    """Return the stored record when this (key, principal, body) was already
    processed; None otherwise. The caller must persist the record on success."""
    if not key:
        return None
    from sqlalchemy import select

    rec = (
        await session.execute(
            select(IdempotencyRecord).where(
                IdempotencyRecord.key == key, IdempotencyRecord.principal_sub == principal_sub
            )
        )
    ).scalar_one_or_none()
    if rec is None:
        return None
    body_hash = hashlib.sha256(json.dumps(request_body, sort_keys=True).encode()).hexdigest()
    if rec.request_hash != body_hash:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=409,
            detail={"reason": "idempotency-conflict",
                    "detail": "Idempotency-Key replayed with a different request body"},
        )
    return rec


async def store_idempotency(
    session: AsyncSession,
    key: str | None,
    principal_sub: str,
    request_body: dict[str, Any],
    status: int,
    response_body: dict[str, Any],
) -> None:
    if not key:
        return
    body_hash = hashlib.sha256(json.dumps(request_body, sort_keys=True).encode()).hexdigest()
    session.add(
        IdempotencyRecord(
            key=key,
            principal_sub=principal_sub,
            request_hash=body_hash,
            response_status=status,
            response_body=response_body,
        )
    )
    await session.flush()


IdempotencyKey = Annotated[str | None, Header(alias="Idempotency-Key")]
