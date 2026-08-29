"""Bitstring Status List management: index allocation and snapshot publishing.

Stamp state visible to verifiers lives in signed Bitstring Status List
credentials (purposes void / expired / suspect), NOT in database-row status.
The database mirrors working state for the service; snapshots published to
``status_list_snapshots`` are the verifier-facing truth, served by
GET /v1/status-list/{purpose}.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from taxstamps.config import Settings
from taxstamps.crypto.eddsa import SigningKey
from taxstamps.crypto.statuslist import (
    DEFAULT_LIST_SIZE_BITS,
    PURPOSES,
    StatusList,
    build_status_list_credential,
    parse_status_list_credential,
)
from taxstamps.models import Stamp, StatusListSnapshot


class StatusListError_(ValueError):
    pass


async def allocate_index(session: AsyncSession) -> int:
    """Allocate the next free status-list index (shared across purposes)."""
    row = await session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": 0x535441545553})  # noqa: F841
    current = (
        await session.execute(select(func.max(Stamp.status_list_index)))
    ).scalar_one()
    nxt = (current + 1) if current is not None else 0
    if nxt >= DEFAULT_LIST_SIZE_BITS:
        raise StatusListError_("status list exhausted: rotate to a new list credential")
    return nxt


def list_credential_id(settings: Settings, purpose: str) -> str:
    base = settings.status_list_base_url.rstrip("/") or "urn:blueeconomy:taxstamps"
    return f"{base}/status-list/{purpose}"


async def _current_list(session: AsyncSession, purpose: str) -> StatusList:
    row = (
        await session.execute(
            select(StatusListSnapshot)
            .where(StatusListSnapshot.purpose == purpose)
            .order_by(StatusListSnapshot.version.desc())
            .limit(1)
        )
    ).scalars().first()
    if row is None:
        return StatusList()
    _, status_list = parse_status_list_credential(row.credential)
    return status_list


async def set_flag(
    session: AsyncSession,
    *,
    purpose: str,
    index: int,
    settings: Settings,
    signing_key: SigningKey,
    verification_method: str,
) -> None:
    """Set a stamp's bit in one status list and publish the new snapshot."""
    if purpose not in PURPOSES:
        raise StatusListError_(f"unknown purpose {purpose}")
    status_list = await _current_list(session, purpose)
    status_list.set(index, True)
    version_row = (
        await session.execute(
            select(func.max(StatusListSnapshot.version)).where(StatusListSnapshot.purpose == purpose)
        )
    ).scalar_one()
    version = (version_row or 0) + 1
    credential = build_status_list_credential(
        list_credential_id=list_credential_id(settings, purpose),
        issuer_did=settings.issuer_did,
        status_purpose=purpose,
        status_list=status_list,
        key=signing_key,
        verification_method=verification_method,
    )
    session.add(StatusListSnapshot(purpose=purpose, version=version, credential=credential))
    await session.flush()


async def current_credential(session: AsyncSession, purpose: str) -> dict[str, Any] | None:
    row = (
        await session.execute(
            select(StatusListSnapshot)
            .where(StatusListSnapshot.purpose == purpose)
            .order_by(StatusListSnapshot.version.desc())
            .limit(1)
        )
    ).scalars().first()
    return row.credential if row else None
