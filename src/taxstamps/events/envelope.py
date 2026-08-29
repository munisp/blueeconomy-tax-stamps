"""Canonical event envelope v1.0 (blueeconomy-contracts): a FHIR R4 message
Bundle wrap, signed with JWS-EdDSA over the RFC 8785 JCS canonicalization of
the envelope minus ``provenance.signature``.

Producer side: build_envelope + sign_envelope.
Consumer side: verify_envelope implements the fail-closed algorithm of
docs/envelope-signature.md §4 (reason codes malformed-jws, unsupported-alg,
unknown-kid, payload-mismatch, invalid-signature) plus structural checks
(envelopeVersion, eventType/resource agreement, FHIR message Bundle shape).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from taxstamps.crypto.eddsa import (
    JwsError,
    KeyDirectory,
    SigningKey,
    jws_sign,
    jws_verify,
)
from taxstamps.crypto.jcs import canonicalize_bytes

ENVELOPE_VERSION = "1.0"

# eventType -> platform StructureDefinition extension URL and Any type name.
_EVENT_RESOURCES: dict[str, str] = {
    "stamps.assessed.v1": "TaxStampAssessed",
    "stamps.approved.v1": "TaxStampAssessmentApproved",
    "stamps.issued.v1": "TaxStampBatchIssued",
    "stamps.activated.v1": "TaxStampBatchActivated",
    "stamps.verified.v1": "TaxStampVerified",
    "stamps.voided.v1": "TaxStampVoided",
}

_SD_BASE = "https://blueeconomy.gov.ng/fhir/StructureDefinition/"


class EnvelopeError(ValueError):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


def build_envelope(
    *,
    event_type: str,
    resource: dict[str, Any],
    producer: str,
    classification: str,
    principal_id: str,
    principal_role: str,
    correlation_id: str | None = None,
    event_id: str | None = None,
) -> dict[str, Any]:
    """Build an unsigned envelope v1.0 around a primary event resource."""
    if event_type not in _EVENT_RESOURCES:
        raise EnvelopeError("unknown-event-type", event_type)
    event_id = event_id or f"evt-{uuid.uuid4()}"
    resource = dict(resource)
    resource.setdefault(
        "@type", f"type.googleapis.com/blueeconomy.contracts.v1.{_EVENT_RESOURCES[event_type]}"
    )
    return {
        "envelopeVersion": ENVELOPE_VERSION,
        "eventId": event_id,
        "eventType": event_type,
        "occurredAt": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "producer": producer,
        "correlationId": correlation_id or event_id,
        "classification": classification,
        "fhir": {
            "resourceType": "Bundle",
            "type": "message",
            "bundleId": f"bdl-{uuid.uuid4()}",
            "entry": [
                {
                    "fullUrl": f"urn:uuid:{uuid.uuid4()}",
                    "resource": resource,
                }
            ],
        },
        "provenance": {
            "principalId": principal_id,
            "principalRole": principal_role,
            "ledgerCommitHash": "",
            "signature": "",
        },
    }


def sign_envelope(envelope: dict[str, Any], key: SigningKey) -> dict[str, Any]:
    """Attach the JWS-EdDSA provenance signature. Returns a new envelope."""
    unsigned = _without_signature(envelope)
    payload = canonicalize_bytes(unsigned)
    out = {**envelope, "provenance": {**envelope["provenance"], "signature": jws_sign(key, payload)}}
    return out


def _without_signature(envelope: dict[str, Any]) -> dict[str, Any]:
    prov = {k: v for k, v in envelope.get("provenance", {}).items() if k != "signature"}
    return {**envelope, "provenance": prov}


def verify_envelope(
    envelope: dict[str, Any],
    directory: KeyDirectory,
    *,
    expected_event_type: str | None = None,
    require_signature: bool = True,
) -> dict[str, Any]:
    """Fail-closed consumer verification. Returns the primary resource.

    Rejection is terminal: a rejected envelope must never be persisted.
    """
    if not isinstance(envelope, dict):
        raise EnvelopeError("malformed-envelope", "not an object")
    if envelope.get("envelopeVersion") != ENVELOPE_VERSION:
        raise EnvelopeError("malformed-envelope", "envelopeVersion must be 1.0")
    event_type = envelope.get("eventType")
    if not isinstance(event_type, str) or not event_type:
        raise EnvelopeError("malformed-envelope", "eventType missing")
    if expected_event_type is not None and event_type != expected_event_type:
        raise EnvelopeError("event-type-mismatch", f"{event_type} != {expected_event_type}")
    fhir = envelope.get("fhir")
    if not isinstance(fhir, dict) or fhir.get("resourceType") != "Bundle" or fhir.get("type") != "message":
        raise EnvelopeError("malformed-envelope", "fhir must be a FHIR message Bundle")
    entry = fhir.get("entry")
    if not isinstance(entry, list) or len(entry) != 1 or not isinstance(entry[0], dict):
        raise EnvelopeError("malformed-envelope", "message Bundle must carry exactly one entry")
    resource = entry[0].get("resource")
    if not isinstance(resource, dict):
        raise EnvelopeError("malformed-envelope", "entry resource missing")
    type_url = resource.get("@type", "")
    known = _EVENT_RESOURCES.get(event_type)
    if known is not None and not str(type_url).endswith(f".{known}"):
        raise EnvelopeError(
            "resource-type-mismatch", f"type_url {type_url!r} does not name {known}"
        )
    signature = envelope.get("provenance", {}).get("signature", "")
    if require_signature:
        if not signature:
            raise EnvelopeError("malformed-jws", "provenance.signature missing")
        expected_payload = canonicalize_bytes(_without_signature(envelope))
        try:
            jws_verify(signature, directory, expected_payload=expected_payload)
        except JwsError as exc:
            raise EnvelopeError(exc.reason, str(exc)) from exc
    return resource
