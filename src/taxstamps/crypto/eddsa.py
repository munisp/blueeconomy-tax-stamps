"""Ed25519 keys and JWS compact serialization (RFC 7515 / RFC 8037 EdDSA),
implementing the fleet envelope-signature scheme
(blueeconomy-contracts docs/envelope-signature.md).

- Protected header is exactly {"alg":"EdDSA","kid":"<producer>-<epoch>"}.
- Base64url without padding everywhere.
- Signature input is the ASCII bytes b64u(header) + "." + b64u(payload).
- Consumer verification is fail-closed with reason codes:
  malformed-jws | unsupported-alg | unknown-kid | payload-mismatch |
  invalid-signature.

Keys: Ed25519 PKCS#8 PEM private key loaded from an env-supplied file path
(never from an inline env value, never committed). Public keys distributed as
a mounted JSON directory {kid: base64url(raw 32-byte pubkey)}.
"""

from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

__all__ = [
    "b64u_encode",
    "b64u_decode",
    "KeyDirectory",
    "SigningKey",
    "JwsError",
    "jws_sign",
    "jws_verify",
    "load_signing_key",
    "generate_pkcs8_pem",
]

_KID_RE = re.compile(r"^[A-Za-z0-9._-]{1,256}$")


class JwsError(ValueError):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(data: str) -> bytes:
    if "=" in data:
        raise JwsError("malformed-jws", "base64url padding is prohibited")
    try:
        return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    except Exception as exc:
        raise JwsError("malformed-jws", f"invalid base64url: {exc}") from exc


@dataclass(frozen=True)
class SigningKey:
    kid: str
    private_key: Ed25519PrivateKey

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    def public_key_b64u(self) -> str:
        raw = self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return b64u_encode(raw)


def generate_pkcs8_pem() -> bytes:
    """Generate a fresh Ed25519 PKCS#8 PEM (operator/test tooling only)."""
    key = Ed25519PrivateKey.generate()
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


# Substrings that mark a key file as a placeholder. Boot refuses these.
_PLACEHOLDER_MARKERS = ("CHANGE_ME", "CHANGEME", "PLACEHOLDER", "DUMMY", "EXAMPLE-KEY", "REPLACE_ME")


def _is_production() -> bool:
    return os.environ.get("ENV", "").strip().lower() in {"production", "prod"}


def load_signing_key(path: str, kid: str) -> SigningKey:
    """Load the PKCS#8 PEM signing key; refuse placeholder/dummy material."""
    if _is_production() and os.environ.get("TAXSTAMPS_ALLOW_PERMISSIVE_KEY_FILE"):
        # Fail-closed: the permissive-mode escape hatch is a development
        # convenience and must never be armed in production.
        raise JwsError(
            "permissive-key-file-refused",
            "TAXSTAMPS_ALLOW_PERMISSIVE_KEY_FILE is forbidden when ENV=production",
        )
    p = Path(path)
    if not p.is_file() or p.is_symlink():
        raise JwsError("key-unavailable", f"signing key {path} is not a regular non-symlink file")
    if os.stat(p).st_mode & 0o077 and os.environ.get("TAXSTAMPS_ALLOW_PERMISSIVE_KEY_FILE") != "1":
        raise JwsError("key-unavailable", f"signing key {path} must not be group/world-readable")
    raw = p.read_bytes()
    upper = raw.decode("utf-8", "ignore").upper()
    for marker in _PLACEHOLDER_MARKERS:
        if marker in upper:
            raise JwsError("placeholder-key", f"signing key {path} contains placeholder marker {marker}")
    try:
        key = load_pem_private_key(raw, password=None)
    except Exception as exc:
        raise JwsError("key-unavailable", f"cannot parse signing key: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise JwsError("key-unavailable", "signing key is not an Ed25519 private key")
    return SigningKey(kid=kid, private_key=key)


class KeyDirectory:
    """Mounted public-key directory {kid: base64url-ed25519-pubkey}."""

    def __init__(self, keys: dict[str, Ed25519PublicKey]) -> None:
        if not keys:
            raise JwsError("key-directory-empty", "public key directory contains no keys")
        self._keys = keys

    @classmethod
    def load(cls, path: str) -> KeyDirectory:
        p = Path(path)
        if not p.is_file() or p.is_symlink():
            raise JwsError("key-directory-unavailable", f"{path} is not a regular non-symlink file")
        try:
            data = json.loads(p.read_text("utf-8"))
        except Exception as exc:
            raise JwsError("key-directory-unavailable", f"cannot parse {path}: {exc}") from exc
        if not isinstance(data, dict) or not data:
            raise JwsError("key-directory-unavailable", "directory must be a non-empty JSON object")
        keys: dict[str, Ed25519PublicKey] = {}
        for kid, b64 in data.items():
            if not _KID_RE.match(kid):
                raise JwsError("key-directory-unavailable", f"malformed kid {kid!r}")
            if not isinstance(b64, str):
                raise JwsError("key-directory-unavailable", f"key for {kid} is not a string")
            raw = b64u_decode(b64)
            if len(raw) != 32:
                raise JwsError("key-directory-unavailable", f"key for {kid} is not 32 bytes")
            keys[kid] = Ed25519PublicKey.from_public_bytes(raw)
        return cls(keys)

    def resolve(self, kid: str) -> Ed25519PublicKey:
        key = self._keys.get(kid)
        if key is None:
            raise JwsError("unknown-kid", kid)
        return key


def jws_sign(key: SigningKey, payload: bytes) -> str:
    header = json.dumps({"alg": "EdDSA", "kid": key.kid}, separators=(",", ":")).encode("utf-8")
    seg1 = b64u_encode(header)
    seg2 = b64u_encode(payload)
    signature = key.private_key.sign(f"{seg1}.{seg2}".encode("ascii"))
    return f"{seg1}.{seg2}.{b64u_encode(signature)}"


def jws_verify(jws: str, directory: KeyDirectory, expected_payload: bytes | None = None) -> bytes:
    """Fail-closed verification. Returns the payload on success.

    When ``expected_payload`` is supplied the decoded payload must byte-equal
    it (the self-verifying envelope rule) before the signature is checked.
    """
    if not isinstance(jws, str):
        raise JwsError("malformed-jws", "not a string")
    parts = jws.split(".")
    if len(parts) != 3 or any(not p for p in parts):
        raise JwsError("malformed-jws", "expected three non-empty segments")
    seg1, seg2, seg3 = parts
    try:
        header = json.loads(b64u_decode(seg1))
    except JwsError:
        raise
    except Exception as exc:
        raise JwsError("malformed-jws", f"protected header is not JSON: {exc}") from exc
    if not isinstance(header, dict) or set(header) != {"alg", "kid"}:
        raise JwsError("malformed-jws", "protected header must be exactly {alg, kid}")
    if header["alg"] != "EdDSA":
        raise JwsError("unsupported-alg", repr(header["alg"]))
    if not isinstance(header["kid"], str) or not _KID_RE.match(header["kid"]):
        raise JwsError("malformed-jws", "malformed kid")
    public_key = directory.resolve(header["kid"])
    payload = b64u_decode(seg2)
    if expected_payload is not None and payload != expected_payload:
        raise JwsError("payload-mismatch")
    signature = b64u_decode(seg3)
    try:
        public_key.verify(signature, f"{seg1}.{seg2}".encode("ascii"))
    except Exception as exc:
        raise JwsError("invalid-signature") from exc
    return payload
