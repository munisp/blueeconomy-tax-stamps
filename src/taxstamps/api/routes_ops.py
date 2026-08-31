"""Ops routes.

PUBLIC (probes and verifier-facing publications): liveness/readiness probes,
issuer key and status-list credentials — these are deliberately anonymous.
INTERNAL (`ops_router`): the capabilities honesty registry and the audit-chain
verifier leak DB/Kafka internals and audit integrity state, so they are
policy-gated behind require_policy("ops", "read") (auditor role) — anonymous
callers get 401 (or 503 when OIDC is unconfigured: fail-closed), authenticated
non-auditors get 403.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import text

from taxstamps.api.deps import IdentityDep, SessionDep, SettingsDep, require_policy
from taxstamps.crypto.statuslist import PURPOSES
from taxstamps.services import audit, capabilities, redis_guard, statuslists

router = APIRouter()
ops_router = APIRouter()


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": "blueeconomy-tax-stamps"}


@router.get("/readyz")
async def readyz(session: SessionDep) -> dict[str, str]:
    await session.execute(text("SELECT 1"))
    return {"status": "ready"}


@ops_router.get("/v1/capabilities")
async def v1_capabilities(
    request: Request, settings: SettingsDep, session: SessionDep, identity: IdentityDep
) -> dict[str, Any]:
    require_policy(request, identity, "ops", "read", "INTERNAL")
    runtime: dict[str, bool | str] = {}
    try:
        await session.execute(text("SELECT 1"))
        runtime["database"] = True
    except Exception as exc:
        runtime["database"] = False
        runtime["database_reason"] = str(exc)
    runtime["signing"] = getattr(request.app.state, "signing_key", None) is not None
    if settings.redis_configured:
        runtime["redis"] = await redis_guard.ping()
    runtime["oidc"] = getattr(request.app.state, "keyring", None) is not None
    runtime["kafka"] = bool(getattr(request.app.state, "kafka_available", False))
    if not settings.kafka_configured:
        runtime.pop("kafka", None)
        runtime["kafka"] = False
        runtime["kafka_reason"] = "TAXSTAMPS_KAFKA_BOOTSTRAP_SERVERS not configured"
    return capabilities.capability_report(settings, runtime)


@ops_router.get("/v1/ops/audit-chain")
async def audit_chain_verify(
    request: Request, session: SessionDep, identity: IdentityDep
) -> dict[str, Any]:
    require_policy(request, identity, "ops", "read", "INTERNAL")
    result = await audit.verify_chain(session)
    return {
        "ok": result.ok,
        "events": result.events,
        "firstBadId": result.first_bad_id,
        "detail": result.detail,
    }


@router.get("/v1/issuers/{issuer}/key")
async def issuer_key(issuer: str, request: Request, settings: SettingsDep) -> dict[str, Any]:
    """Public issuer Ed25519 key for offline eddsa-jcs-2022 verification."""
    if issuer != settings.issuer_did:
        raise HTTPException(status_code=404, detail="unknown issuer")
    key = request.app.state.signing_key
    return {"issuer": settings.issuer_did, "kid": key.kid, "public_key_b64u": key.public_key_b64u()}


@router.get("/v1/status-list/{purpose}")
async def status_list(purpose: str, session: SessionDep) -> dict[str, Any]:
    if purpose not in PURPOSES:
        raise HTTPException(status_code=404, detail="unknown status list")
    credential = await statuslists.current_credential(session, purpose)
    if credential is None:
        raise HTTPException(status_code=404, detail="status list not yet published")
    return credential
