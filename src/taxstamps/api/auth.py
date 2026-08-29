"""OIDC bearer authentication (Keycloak JWKS, RS256 or EdDSA) — fail-closed.

- JWKS is loaded once at startup from a mounted file (TAXSTAMPS_OIDC_JWKS_PATH)
  or fetched from TAXSTAMPS_OIDC_JWKS_URL; unreadable/malformed JWKS aborts
  boot when OIDC is configured.
- When OIDC is NOT configured, authenticated routes return 503
  (capabilities registry reports ``auth.oidc`` unavailable); there is no
  fail-open anonymous path.
- Roles come from realm_access.roles plus resource_access[client].roles.
- ``auditor`` is denied every mutation by policy (see policies/).
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPublicNumbers

from taxstamps.config import Settings


class AuthError(ValueError):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


@dataclass(frozen=True)
class Identity:
    subject: str
    roles: frozenset[str]
    tenant: str = ""
    clearance: str = ""


def _b64u(data: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    except Exception as exc:
        raise AuthError("malformed-token", str(exc)) from exc


def _rsa_from_jwk(jwk: dict[str, Any]) -> RSAPublicKey:
    n = int.from_bytes(_b64u(jwk["n"]), "big")
    e = int.from_bytes(_b64u(jwk["e"]), "big")
    return RSAPublicNumbers(e, n).public_key()


class JwksKeyring:
    """Startup-loaded JWKS. Fail-closed: any load defect aborts boot."""

    def __init__(self, keys: dict[str, Any]) -> None:
        if not keys:
            raise AuthError("jwks-empty", "JWKS contains no usable keys")
        self._keys = keys

    @classmethod
    def load(cls, settings: Settings) -> JwksKeyring:
        if settings.oidc_jwks_path:
            p = Path(settings.oidc_jwks_path)
            if not p.is_file() or p.is_symlink():
                raise AuthError("jwks-unavailable", f"{p} is not a regular non-symlink file")
            data = json.loads(p.read_text("utf-8"))
        elif settings.oidc_jwks_url:
            if not settings.oidc_jwks_url.startswith("https://"):
                raise AuthError("jwks-unavailable", "JWKS URL must be https://")
            resp = httpx.get(settings.oidc_jwks_url, timeout=10.0)
            resp.raise_for_status()
            data = resp.json()
        else:
            raise AuthError("jwks-unavailable", "no JWKS source configured")
        keys: dict[str, Any] = {}
        for jwk in data.get("keys", []):
            kid = jwk.get("kid")
            kty = jwk.get("kty")
            if not kid:
                continue
            try:
                if kty == "RSA":
                    keys[kid] = ("RS256", _rsa_from_jwk(jwk))
                elif kty == "OKP" and jwk.get("crv") == "Ed25519":
                    keys[kid] = ("EdDSA", Ed25519PublicKey.from_public_bytes(_b64u(jwk["x"])))
            except Exception as exc:
                raise AuthError("jwks-unavailable", f"malformed key {kid}: {exc}") from exc
        return cls(keys)

    def resolve(self, kid: str) -> tuple[str, Any]:
        entry = self._keys.get(kid)
        if entry is None:
            raise AuthError("unknown-kid", kid)
        alg, key = entry
        return str(alg), key


def verify_bearer(token: str, keyring: JwksKeyring, settings: Settings) -> Identity:
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthError("malformed-token")
    header = json.loads(_b64u(parts[0]))
    payload = json.loads(_b64u(parts[1]))
    alg, key = keyring.resolve(header.get("kid", ""))
    if header.get("alg") != alg:
        raise AuthError("unsupported-alg", repr(header.get("alg")))
    signature = _b64u(parts[2])
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    try:
        if alg == "RS256":
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding

            key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
        else:
            key.verify(signature, signing_input)
    except Exception as exc:
        raise AuthError("invalid-signature") from exc
    now = int(time.time())
    if not isinstance(payload.get("exp"), int) or payload["exp"] <= now:
        raise AuthError("token-expired")
    if settings.oidc_issuer and payload.get("iss") != settings.oidc_issuer:
        raise AuthError("issuer-mismatch")
    if settings.oidc_audience:
        aud = payload.get("aud")
        audiences = aud if isinstance(aud, list) else [aud]
        if settings.oidc_audience not in audiences:
            raise AuthError("audience-mismatch")
    roles = set(payload.get("realm_access", {}).get("roles", []) or [])
    for client_roles in (payload.get("resource_access", {}) or {}).values():
        roles.update(client_roles.get("roles", []) or [])
    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject:
        raise AuthError("malformed-token", "sub missing")
    return Identity(
        subject=subject,
        roles=frozenset(roles),
        tenant=str(payload.get("tenant", "") or ""),
        clearance=str(payload.get("clearance", "") or ""),
    )


# ------------------------------------------------------- verifier credentials


def hash_verifier_credential(verifier_id: str, credential: str) -> str:
    """Keyed hash of a per-verifier bearer credential; the raw credential is
    never stored. There is no shared fleet secret."""
    return hashlib.sha256(f"verifier:{verifier_id}:{credential}".encode()).hexdigest()
