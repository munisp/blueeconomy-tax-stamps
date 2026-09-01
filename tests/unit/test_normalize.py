"""Producer-contract normalization: FHIR-Basic unwrapper + kid-prefix gate."""

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from taxstamps.crypto.eddsa import KeyDirectory, SigningKey
from taxstamps.events.envelope import EnvelopeError
from taxstamps.events.normalize import (
    NormalizationError,
    check_trusted_kid,
    extract_jws_kid,
    normalize_resource,
    parse_event_map,
    parse_kid_prefixes,
)
from taxstamps.crypto.jcs import canonicalize_bytes
from taxstamps.crypto.eddsa import jws_sign


def _producer_envelope(kid: str = "port-interoperability-0"):
    key = SigningKey(kid=kid, private_key=Ed25519PrivateKey.generate())
    envelope = {
        "envelopeVersion": "1.0",
        "eventId": "evt-1",
        "eventType": "trade.declaration.submitted.v1",
        "provenance": {"principalId": "p", "principalRole": "r"},
    }
    payload = canonicalize_bytes(envelope)
    envelope["provenance"]["signature"] = jws_sign(key, payload)
    return envelope, key


def _basic_resource(payload: dict) -> dict:
    return {
        "resourceType": "Basic",
        "id": "decl-1",
        "code": {"text": "trade.declaration.submitted.v1"},
        "extension": [
            {
                "url": "https://blueeconomy.gov.ng/fhir/StructureDefinition/domain-payload",
                "valueString": json.dumps(payload),
            }
        ],
    }


_WIRE = {
    "declaration_ref": "DECL-2026-001",
    "consignee_id": "TIN-12345678",
    "hs_code": "240220",
    "goods_description": "Cigarettes containing tobacco",
    "number_of_packages": 40,
    "invoice_amount_minor": 1250000,
}


def test_parse_event_map():
    assert parse_event_map("") == {}
    assert parse_event_map("trade.declaration.submitted.v1=declaration") == {
        "trade.declaration.submitted.v1": "declaration"
    }
    with pytest.raises(ValueError):
        parse_event_map("trade.declaration.submitted.v1")
    with pytest.raises(ValueError):
        parse_event_map("trade.declaration.submitted.v1=bogus")


def test_parse_kid_prefixes():
    assert parse_kid_prefixes("") == ()
    assert parse_kid_prefixes("port-interoperability-, blueeconomy-tax-stamps-") == (
        "port-interoperability-",
        "blueeconomy-tax-stamps-",
    )


def test_extract_jws_kid():
    envelope, _ = _producer_envelope()
    assert extract_jws_kid(envelope) == "port-interoperability-0"
    assert extract_jws_kid({"provenance": {}}) is None
    assert extract_jws_kid({"provenance": {"signature": "not-a-jws"}}) is None


def test_check_trusted_kid_gate():
    envelope, _ = _producer_envelope()
    check_trusted_kid(envelope, ("port-interoperability-",))
    check_trusted_kid(envelope, ())  # empty allow-list disables the gate
    with pytest.raises(EnvelopeError) as exc:
        check_trusted_kid(envelope, ("other-producer-",))
    assert exc.value.reason == "untrusted-kid"
    with pytest.raises(EnvelopeError) as exc2:
        check_trusted_kid({"provenance": {}}, ("port-interoperability-",))
    assert exc2.value.reason == "untrusted-kid"


def test_normalize_declaration_happy_path():
    resource = normalize_resource(
        {"eventType": "trade.declaration.submitted.v1"},
        _basic_resource(_WIRE),
        {"trade.declaration.submitted.v1": "declaration"},
    )
    assert resource["declarationRef"] == "DECL-2026-001"
    assert resource["consigneeTin"] == "TIN-12345678"
    line = resource["lineItems"][0]
    assert line["hsCode"] == "240220"
    assert line["quantity"] == 40
    assert line["unit"] == "UNIT"
    assert line["customsValueKobo"] == 1250000
    assert line["stampsRequired"] == 40


def test_normalize_passthrough_unknown_event_type():
    resource = {"declarationRef": "x"}
    assert (
        normalize_resource({"eventType": "declarations.imported.v1"}, resource, {})
        is resource
    )


def test_normalize_fail_closed():
    event_map = {"trade.declaration.submitted.v1": "declaration"}
    envelope = {"eventType": "trade.declaration.submitted.v1"}
    # Not a Basic resource
    with pytest.raises(NormalizationError):
        normalize_resource(envelope, {"resourceType": "Patient"}, event_map)
    # Missing domain-payload extension
    with pytest.raises(NormalizationError):
        normalize_resource(envelope, {"resourceType": "Basic", "extension": []}, event_map)
    # Bad JSON
    with pytest.raises(NormalizationError):
        normalize_resource(
            envelope,
            {
                "resourceType": "Basic",
                "extension": [
                    {
                        "url": "https://blueeconomy.gov.ng/fhir/StructureDefinition/domain-payload",
                        "valueString": "{nope",
                    }
                ],
            },
            event_map,
        )
    # Missing wire fields
    with pytest.raises(NormalizationError):
        normalize_resource(envelope, _basic_resource({"declaration_ref": "x"}), event_map)
    # Non-positive numbers
    bad = dict(_WIRE, number_of_packages=0)
    with pytest.raises(NormalizationError):
        normalize_resource(envelope, _basic_resource(bad), event_map)
    bad2 = dict(_WIRE, invoice_amount_minor=-5)
    with pytest.raises(NormalizationError):
        normalize_resource(envelope, _basic_resource(bad2), event_map)
