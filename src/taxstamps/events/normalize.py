"""Producer-contract normalization for inbound declaration envelopes.

The port-interoperability producer (``s1-port-interoperability``) publishes
customs declaration lifecycle events on ``trade.declarations.v1`` in envelope
v1.0 whose FHIR message Bundle entry is a FHIR ``Basic`` resource carrying
the Declaration JSON as a ``domain-payload`` *string* extension
(``https://blueeconomy.gov.ng/fhir/StructureDefinition/domain-payload``).
The tax-stamps consumer domain model, however, works with the structural
declaration resource (``declarationRef`` / ``consigneeTin`` / ``lineItems``).

This module is the fail-closed bridge:

- a config-driven eventType -> mode map (``TAXSTAMPS_DECLARATION_EVENT_MAP``,
  ``eventType=mode`` comma-separated) declares which producer eventTypes are
  normalized and how; an eventType that is present in the map but whose
  payload is malformed is rejected, never guessed;
- the FHIR-Basic string extension is unwrapped exactly once and the wire
  fields (``declaration_ref`` / ``consignee_id`` / ``hs_code`` /
  ``number_of_packages`` / ``invoice_amount_minor``) are mapped to the
  structural resource;
- a trusted-kid-prefix allow-list (``TAXSTAMPS_TRUSTED_KID_PREFIXES``)
  rejects envelopes signed by kids outside the producer prefix with reason
  ``untrusted-kid`` before any payload is trusted.

Events whose eventType is NOT in the map are passed through unchanged and
remain subject to the structural contract of the consumer.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from taxstamps.events.envelope import EnvelopeError

_DOMAIN_PAYLOAD_URL = (
    "https://blueeconomy.gov.ng/fhir/StructureDefinition/domain-payload"
)

# Wire (snake_case, producer Declaration JSON) -> required presence for the
# declaration normalization mode. Mapping is explicit; nothing is inferred.
_REQUIRED_WIRE_FIELDS = (
    "declaration_ref",
    "consignee_id",
    "hs_code",
    "number_of_packages",
    "invoice_amount_minor",
)

DEFAULT_DECLARATION_EVENT_MAP = "trade.declaration.submitted.v1=declaration"


class NormalizationError(EnvelopeError):
    """Fail-closed rejection during producer-contract normalization."""

    def __init__(self, detail: str) -> None:
        super().__init__("normalization-error", detail)


def parse_event_map(raw: str) -> dict[str, str]:
    """Parse ``eventType=mode`` comma pairs. Empty string -> empty map.

    Malformed entries fail closed (a misconfigured map must never silently
    drop or reinterpret events).
    """
    out: dict[str, str] = {}
    for entry in (raw or "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        event_type, sep, mode = entry.partition("=")
        if not sep or not event_type.strip() or mode.strip() != "declaration":
            raise ValueError(
                f"invalid declaration event map entry {entry!r} "
                "(expected '<eventType>=declaration')"
            )
        out[event_type.strip()] = mode.strip()
    return out


def parse_kid_prefixes(raw: str) -> tuple[str, ...]:
    """Parse the comma-separated trusted kid prefix allow-list."""
    return tuple(p.strip() for p in (raw or "").split(",") if p.strip())


def extract_jws_kid(envelope: dict[str, Any]) -> str | None:
    """Best-effort kid extraction from the provenance JWS header.

    Returns None when the signature is absent or unparseable — the fail-closed
    JWS verifier rejects those envelopes downstream anyway.
    """
    signature = envelope.get("provenance", {}).get("signature", "")
    if not isinstance(signature, str) or signature.count(".") != 2:
        return None
    header_b64 = signature.split(".", 1)[0]
    try:
        header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4)))
    except (ValueError, binascii.Error):
        return None
    kid = header.get("kid")
    return kid if isinstance(kid, str) else None


def check_trusted_kid(
    envelope: dict[str, Any], trusted_prefixes: tuple[str, ...]
) -> None:
    """Fail-closed kid-prefix gate. Empty allow-list disables the gate."""
    if not trusted_prefixes:
        return
    kid = extract_jws_kid(envelope)
    if kid is None:
        raise EnvelopeError("untrusted-kid", "provenance JWS carries no parseable kid")
    if not any(kid.startswith(prefix) for prefix in trusted_prefixes):
        raise EnvelopeError(
            "untrusted-kid", f"kid {kid!r} matches no trusted prefix {trusted_prefixes!r}"
        )


def normalize_resource(
    envelope: dict[str, Any],
    resource: dict[str, Any],
    event_map: dict[str, str],
) -> dict[str, Any]:
    """Map a producer wire resource to the structural declaration resource.

    Passthrough when the envelope eventType is not in the event map. Raises
    NormalizationError (fail-closed) on any malformed mapped payload.
    """
    mode = event_map.get(envelope.get("eventType", ""))
    if mode is None:
        return resource
    if mode != "declaration":  # defensive: parse_event_map restricts modes
        raise NormalizationError(f"unsupported normalization mode {mode!r}")
    return _normalize_declaration(resource)


def _normalize_declaration(resource: dict[str, Any]) -> dict[str, Any]:
    if resource.get("resourceType") != "Basic":
        raise NormalizationError(
            f"expected a FHIR Basic resource, got {resource.get('resourceType')!r}"
        )
    extensions = resource.get("extension")
    if not isinstance(extensions, list):
        raise NormalizationError("FHIR Basic resource carries no extensions")
    payload_json: str | None = None
    for ext in extensions:
        if isinstance(ext, dict) and ext.get("url") == _DOMAIN_PAYLOAD_URL:
            value = ext.get("valueString")
            if not isinstance(value, str):
                raise NormalizationError("domain-payload extension is not a string")
            payload_json = value
            break
    if payload_json is None:
        raise NormalizationError("domain-payload extension missing")
    try:
        payload = json.loads(payload_json)
    except ValueError as exc:
        raise NormalizationError(f"domain-payload is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise NormalizationError("domain-payload is not a JSON object")
    missing = [f for f in _REQUIRED_WIRE_FIELDS if f not in payload]
    if missing:
        raise NormalizationError(f"declaration payload missing fields {missing}")
    try:
        quantity = int(payload["number_of_packages"])
        customs_value = int(payload["invoice_amount_minor"])
    except (TypeError, ValueError) as exc:
        raise NormalizationError(
            f"number_of_packages/invoice_amount_minor must be integers: {exc}"
        ) from exc
    if quantity <= 0 or customs_value <= 0:
        raise NormalizationError(
            "number_of_packages and invoice_amount_minor must be positive"
        )
    declaration_ref = str(payload["declaration_ref"]).strip()
    consignee_id = str(payload["consignee_id"]).strip()
    hs_code = str(payload["hs_code"]).strip()
    if not declaration_ref or not consignee_id or not hs_code:
        raise NormalizationError(
            "declaration_ref, consignee_id and hs_code must be non-empty"
        )
    # Package-count declarations normalize to a single structural line item in
    # UNITs; stamps_required defaults to the package count (consumer default).
    return {
        "@type": "type.googleapis.com/blueeconomy.contracts.v1.CustomsDeclarationFiled",
        "declarationRef": declaration_ref,
        "consigneeTin": consignee_id,
        "consigneeName": "",
        "lineItems": [
            {
                "hsCode": hs_code,
                "description": str(payload.get("goods_description", "")),
                "quantity": quantity,
                "unit": "UNIT",
                "customsValueKobo": customs_value,
                "stampsRequired": quantity,
            }
        ],
    }
