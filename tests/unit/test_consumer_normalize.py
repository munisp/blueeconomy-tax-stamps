"""Normalize the real port-interoperability declaration payload.

The fixture below is built from blueeconomy-port-interoperability's actual
code, not invented:
- internal/events/envelope.go Message: the FHIR Bundle entry resource is a
  FHIR Basic {resourceType, id=<subjectID=declaration ref>,
  code.text=<eventType>, extension[0]={url: .../domain-payload,
  valueString: <payload JSON>}, ...context extensions};
- internal/declarations/model.go Declaration: the payload JSON field names
  (declaration_ref, consignee_id, hs_code, goods_description,
  number_of_packages, invoice_amount_minor, invoice_currency, ...).
"""

import json

import pytest

from taxstamps.events.consumer import normalize_declaration_resource

# Mirror of internal/declarations/model.go Declaration JSON tags.
_PRODUCER_PAYLOAD = {
    "declaration_id": "d-9f1c2a",
    "tenant_id": "t-nigeria",
    "request_id": "req-12345",
    "declaration_ref": "DECL-2025-000123",
    "revision": 1,
    "trader_id": "trader-77",
    "declaration_type": "IMPORT",
    "status": "CLEARED",
    "hs_code": "22030000",
    "goods_description": "Malt beer, 24x33cl cases",
    "country_of_origin": "NL",
    "port_of_entry": "NGAPP",
    "gross_weight_kg": 8400,
    "net_weight_kg": 7920,
    "number_of_packages": 1200,
    "consignee_id": "TIN-01010101",
    "operator_id": "op-1",
    "is_aeo": False,
    "invoice_amount_minor": 48_000_000_00,
    "invoice_currency": "NGN",
    "tariff_bps": 2000,
    "vat_bps": 750,
    "created_at": "2025-01-02T03:04:05Z",
    "updated_at": "2025-01-02T03:04:05Z",
    "version": 3,
}


def _producer_resource(payload: dict | None = None) -> dict:
    """FHIR Basic entry resource exactly as events.Message builds it."""
    payload = _PRODUCER_PAYLOAD if payload is None else payload
    return {
        "resourceType": "Basic",
        "id": payload.get("declaration_ref", "DECL-2025-000123"),
        "code": {"text": "trade.declaration.cleared.v1"},
        "extension": [
            {
                "url": "https://blueeconomy.gov.ng/fhir/StructureDefinition/domain-payload",
                "valueString": json.dumps(payload),
            },
            {
                "url": "https://blueeconomy.gov.ng/fhir/StructureDefinition/port-of-entry",
                "valueString": "NGAPP",
            },
        ],
    }


def test_real_producer_payload_maps_to_canonical():
    normalized = normalize_declaration_resource(_producer_resource())
    assert normalized["declarationRef"] == "DECL-2025-000123"
    assert normalized["consigneeTin"] == "TIN-01010101"
    assert normalized["consigneeName"] == ""  # producer carries no name
    (line,) = normalized["lineItems"]
    assert line["hsCode"] == "22030000"
    assert line["description"] == "Malt beer, 24x33cl cases"
    assert line["quantity"] == 1200
    assert line["unit"] == "UNIT"
    assert line["customsValueKobo"] == 48_000_000_00


def test_canonical_resource_passes_through():
    canonical = {
        "declarationRef": "DECL-X",
        "consigneeTin": "TIN-X",
        "lineItems": [{"hsCode": "2402", "quantity": 10, "unit": "STICK"}],
    }
    assert normalize_declaration_resource(canonical) is canonical


def test_foreign_currency_is_not_fabricated_into_kobo():
    payload = {**_PRODUCER_PAYLOAD, "invoice_currency": "USD", "invoice_amount_minor": 500_00}
    (line,) = normalize_declaration_resource(_producer_resource(payload))["lineItems"]
    assert line["customsValueKobo"] == 0


def test_missing_domain_payload_extension_rejected():
    resource = _producer_resource()
    resource["extension"] = []
    with pytest.raises(ValueError, match="domain-payload"):
        normalize_declaration_resource(resource)


def test_missing_required_payload_fields_rejected():
    for field in ("declaration_ref", "consignee_id", "hs_code"):
        payload = {**_PRODUCER_PAYLOAD, field: ""}
        with pytest.raises(ValueError, match="missing"):
            normalize_declaration_resource(_producer_resource(payload))


def test_malformed_payload_json_rejected():
    resource = _producer_resource()
    resource["extension"][0]["valueString"] = "{not json"
    with pytest.raises(ValueError, match="not valid JSON"):
        normalize_declaration_resource(resource)


def test_unknown_resource_shape_rejected():
    with pytest.raises(ValueError, match="neither canonical"):
        normalize_declaration_resource({"@type": "SomethingElse", "foo": "bar"})
