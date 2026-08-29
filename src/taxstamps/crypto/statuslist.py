"""W3C Bitstring Status List v1.0 for stamp revocation/flag state.

Each stamp's credential carries three ``BitstringStatusListEntry`` statuses —
purposes ``void``, ``expired`` and ``suspect`` — each pointing into its own
status-list credential at the stamp's assigned index. Stamp state is thus
expressed in the published status lists, NOT as a database-row status (the
database row is the service's working state; the signed status lists are the
verifier-facing truth).

Bitstring layout (per the W3C spec): bit ``i`` lives in byte ``i // 8`` at
bit position ``7 - (i % 8)`` (MSB-first). ``encodedList`` is the multibase
base64url (``u`` prefix, no padding) of the gzip-compressed bitstring.
"""

from __future__ import annotations

import base64
import gzip
from typing import Any

from taxstamps.crypto.eddsa import SigningKey
from taxstamps.crypto.vc import VC_CONTEXT, issue_proof, utc_now_iso

__all__ = [
    "DEFAULT_LIST_SIZE_BITS",
    "PURPOSES",
    "StatusListError",
    "StatusList",
    "build_status_list_credential",
    "parse_status_list_credential",
]

DEFAULT_LIST_SIZE_BITS = 131072  # 16 KiB minimum per W3C Bitstring Status List
PURPOSES = ("void", "expired", "suspect")


class StatusListError(ValueError):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


class StatusList:
    """A mutable bitstring with W3C bit ordering."""

    def __init__(self, size_bits: int = DEFAULT_LIST_SIZE_BITS, data: bytes | None = None) -> None:
        if size_bits <= 0 or size_bits % 8 != 0:
            raise StatusListError("invalid-size", "size must be a positive multiple of 8")
        self.size_bits = size_bits
        if data is None:
            self._bits = bytearray(size_bits // 8)
        else:
            if len(data) != size_bits // 8:
                raise StatusListError("invalid-size", "data length does not match size")
            self._bits = bytearray(data)

    def _check_index(self, index: int) -> None:
        if not (0 <= index < self.size_bits):
            raise StatusListError("index-out-of-range", str(index))

    def get(self, index: int) -> bool:
        self._check_index(index)
        return bool(self._bits[index // 8] & (1 << (7 - (index % 8))))

    def set(self, index: int, value: bool = True) -> None:
        self._check_index(index)
        if value:
            self._bits[index // 8] |= 1 << (7 - (index % 8))
        else:
            self._bits[index // 8] &= ~(1 << (7 - (index % 8)))

    def raw_bytes(self) -> bytes:
        return bytes(self._bits)

    def encode(self) -> str:
        """Multibase base64url of the gzip-compressed bitstring."""
        compressed = gzip.compress(self.raw_bytes(), mtime=0)
        return "u" + base64.urlsafe_b64encode(compressed).rstrip(b"=").decode("ascii")

    @classmethod
    def decode(cls, encoded: str, size_bits: int = DEFAULT_LIST_SIZE_BITS) -> StatusList:
        if not isinstance(encoded, str) or not encoded.startswith("u"):
            raise StatusListError("malformed-encoded-list", "expected multibase base64url 'u' prefix")
        body = encoded[1:]
        if "=" in body:
            raise StatusListError("malformed-encoded-list", "padding prohibited")
        try:
            compressed = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
            raw = gzip.decompress(compressed)
        except StatusListError:
            raise
        except Exception as exc:
            raise StatusListError("malformed-encoded-list", str(exc)) from exc
        return cls(size_bits=size_bits, data=raw)


def build_status_list_credential(
    *,
    list_credential_id: str,
    issuer_did: str,
    status_purpose: str,
    status_list: StatusList,
    key: SigningKey | None = None,
    verification_method: str | None = None,
) -> dict[str, Any]:
    """Render (and optionally sign) the status list as a VC."""
    if status_purpose not in PURPOSES:
        raise StatusListError("unknown-purpose", status_purpose)
    doc: dict[str, Any] = {
        "@context": list(VC_CONTEXT),
        "id": list_credential_id,
        "type": ["VerifiableCredential", "BitstringStatusListCredential"],
        "issuer": issuer_did,
        "validFrom": utc_now_iso(),
        "credentialSubject": {
            "id": f"{list_credential_id}#list",
            "type": "BitstringStatusList",
            "statusPurpose": status_purpose,
            "encodedList": status_list.encode(),
        },
    }
    if key is not None:
        if not verification_method:
            raise StatusListError("verification-method-required")
        doc = issue_proof(doc, key, verification_method)
    return doc


def parse_status_list_credential(credential: dict[str, Any]) -> tuple[str, StatusList]:
    """Extract (statusPurpose, StatusList) from a status-list credential."""
    subject = credential.get("credentialSubject")
    if not isinstance(subject, dict):
        raise StatusListError("malformed-status-list", "missing credentialSubject")
    if subject.get("type") != "BitstringStatusList":
        raise StatusListError("malformed-status-list", "credentialSubject.type mismatch")
    purpose = subject.get("statusPurpose")
    if purpose not in PURPOSES:
        raise StatusListError("unknown-purpose", repr(purpose))
    encoded = subject.get("encodedList")
    if not isinstance(encoded, str):
        raise StatusListError("malformed-status-list", "encodedList missing")
    return purpose, StatusList.decode(encoded)


def status_entry(list_credential_id: str, index: int, purpose: str) -> dict[str, Any]:
    """A BitstringStatusListEntry for embedding in a stamp credential."""
    if purpose not in PURPOSES:
        raise StatusListError("unknown-purpose", purpose)
    return {
        "id": f"{list_credential_id}#{index}",
        "type": "BitstringStatusListEntry",
        "statusPurpose": purpose,
        "statusListIndex": str(index),
        "statusListCredential": list_credential_id,
    }
