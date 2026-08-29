"""W3C Verifiable Credentials Data Model 2.0 issuance/verification with the
Data Integrity **eddsa-jcs-2022** cryptosuite (Ed25519 + RFC 8785 JCS).

Clean-room implementation of the public W3C algorithm:

  proof options  = {type: "DataIntegrityProof", cryptosuite: "eddsa-jcs-2022",
                    created, verificationMethod, proofPurpose}
  transform      = JCS(document without proof) and JCS(proof options)
  hashData       = sha256(JCS(proofOptions)) || sha256(JCS(document))
  signature      = Ed25519.Sign(hashData)
  proofValue     = multibase base58btc: "z" || base58btc(signature)

No external network calls at issue or verify time. ``@context`` is exactly
["https://www.w3.org/ns/credentials/v2"] and is never fetched.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from taxstamps.crypto.eddsa import SigningKey
from taxstamps.crypto.jcs import canonicalize_bytes

__all__ = [
    "VC_CONTEXT",
    "VCError",
    "base58btc_encode",
    "base58btc_decode",
    "issue_proof",
    "verify_proof",
    "build_stamp_credential",
    "utc_now_iso",
]

VC_CONTEXT = ["https://www.w3.org/ns/credentials/v2"]

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {ch: i for i, ch in enumerate(_B58_ALPHABET)}


class VCError(ValueError):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


def base58btc_encode(data: bytes) -> str:
    num = int.from_bytes(data, "big")
    out = ""
    while num > 0:
        num, rem = divmod(num, 58)
        out = _B58_ALPHABET[rem] + out
    # Leading zero bytes become leading '1's.
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return "1" * pad + (out or "")


def base58btc_decode(text: str) -> bytes:
    num = 0
    for ch in text:
        if ch not in _B58_INDEX:
            raise VCError("malformed-proof", "invalid base58btc character")
        num = num * 58 + _B58_INDEX[ch]
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(text) - len(text.lstrip("1"))
    return b"\x00" * pad + body


def utc_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash_data(document_without_proof: dict[str, Any], proof_options: dict[str, Any]) -> bytes:
    return hashlib.sha256(canonicalize_bytes(proof_options)).digest() + hashlib.sha256(
        canonicalize_bytes(document_without_proof)
    ).digest()


def issue_proof(
    document: dict[str, Any],
    key: SigningKey,
    verification_method: str,
    proof_purpose: str = "assertionMethod",
    created: str | None = None,
) -> dict[str, Any]:
    """Attach an eddsa-jcs-2022 Data Integrity proof; returns a new document."""
    if "proof" in document:
        raise VCError("already-signed", "document already carries a proof")
    proof_options = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "created": created or utc_now_iso(),
        "verificationMethod": verification_method,
        "proofPurpose": proof_purpose,
    }
    signature = key.private_key.sign(_hash_data(document, proof_options))
    proof = dict(proof_options)
    proof["proofValue"] = "z" + base58btc_encode(signature)
    out = dict(document)
    out["proof"] = proof
    return out


def verify_proof(document: dict[str, Any], public_key: Ed25519PublicKey) -> None:
    """Fail-closed proof verification. Raises VCError with a reason code."""
    proof = document.get("proof")
    if not isinstance(proof, dict):
        raise VCError("missing-proof")
    required = {"type", "cryptosuite", "created", "verificationMethod", "proofPurpose", "proofValue"}
    if not required.issubset(proof):
        raise VCError("malformed-proof", "missing required proof members")
    if proof["type"] != "DataIntegrityProof":
        raise VCError("unsupported-proof-type", repr(proof["type"]))
    if proof["cryptosuite"] != "eddsa-jcs-2022":
        raise VCError("unsupported-cryptosuite", repr(proof["cryptosuite"]))
    proof_value = proof["proofValue"]
    if not isinstance(proof_value, str) or not proof_value.startswith("z"):
        raise VCError("malformed-proof", "proofValue must be multibase base58btc")
    signature = base58btc_decode(proof_value[1:])
    proof_options = {k: v for k, v in proof.items() if k != "proofValue"}
    doc_without_proof = {k: v for k, v in document.items() if k != "proof"}
    try:
        public_key.verify(signature, _hash_data(doc_without_proof, proof_options))
    except Exception as exc:
        raise VCError("invalid-proof") from exc


def build_stamp_credential(
    *,
    credential_id: str,
    issuer_did: str,
    serial: str,
    hs_code: str,
    declaration_ref: str,
    consignee_tin: str,
    duty_paid_kobo: int,
    valid_from: str,
    valid_until: str,
    status_entries: list[dict[str, Any]],
) -> dict[str, Any]:
    """The stamp credential (unsigned; proof attached by issue_proof).

    credentialSubject carries exactly the fields named in the platform
    integration design: serial, HS code, declaration reference, consignee
    TIN, duty paid, validity window.
    """
    return {
        "@context": list(VC_CONTEXT),
        "id": credential_id,
        "type": ["VerifiableCredential", "ExciseTaxStamp"],
        "issuer": issuer_did,
        "validFrom": valid_from,
        "validUntil": valid_until,
        "credentialSubject": {
            "id": f"{credential_id}#stamp",
            "serial": serial,
            "hsCode": hs_code,
            "declarationRef": declaration_ref,
            "consigneeTin": consignee_tin,
            "dutyPaidKobo": duty_paid_kobo,
        },
        "credentialStatus": status_entries,
    }
