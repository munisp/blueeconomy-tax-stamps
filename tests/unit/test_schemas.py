"""API schemas: extra fields (incl. client-supplied totals) are rejected."""

import pytest
from pydantic import ValidationError

from taxstamps.api.schemas import DeclarationIn, PublicVerifyIn, VerifyIn


def test_declaration_rejects_client_totals():
    with pytest.raises(ValidationError):
        DeclarationIn.model_validate({
            "declaration_ref": "D-1",
            "consignee_tin": "12345678-0001",
            "total_duty_kobo": 100,
            "lines": [{"hs_code": "2203.00", "quantity": 1, "unit": "LITRE",
                       "customs_value_kobo": 0, "stamps_required": 1}],
        })


def test_declaration_line_rejects_client_totals():
    with pytest.raises(ValidationError):
        DeclarationIn.model_validate({
            "declaration_ref": "D-1",
            "consignee_tin": "12345678-0001",
            "lines": [{"hs_code": "2203.00", "quantity": 1, "unit": "LITRE",
                       "customs_value_kobo": 0, "stamps_required": 1,
                       "duty_kobo": 5}],
        })


def test_declaration_valid_minimal():
    d = DeclarationIn.model_validate({
        "declaration_ref": "D-1",
        "consignee_tin": "12345678-0001",
        "lines": [{"hs_code": "2203.00", "quantity": 1, "unit": "LITRE",
                   "customs_value_kobo": 0, "stamps_required": 1}],
    })
    assert d.lines[0].hs_code == "2203.00"


def test_verify_requires_nonce_and_geo_bounds():
    with pytest.raises(ValidationError):
        VerifyIn.model_validate({"serial": "X"})  # nonce missing
    with pytest.raises(ValidationError):
        VerifyIn.model_validate({"serial": "X", "nonce": "12345678", "lat_micros": 91_000_000})


def test_public_verify_requires_serial_or_credential():
    with pytest.raises(ValidationError):
        PublicVerifyIn.model_validate({})
    ok = PublicVerifyIn.model_validate({"serial": "NG-TBC-2026-0000000042-V"})
    assert ok.serial
