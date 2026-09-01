"""Payment rail client: signed settlement forwarding, retry/fail-closed."""

import json
import uuid
from datetime import UTC, datetime

import httpx
import pytest

from taxstamps.config import Settings
from taxstamps.crypto.eddsa import KeyDirectory, jws_verify
from taxstamps.crypto.jcs import canonicalize_bytes
from taxstamps.models import PaymentReceipt
from taxstamps.services.payment_rail import (
    PaymentRailClient,
    RailRejectedError,
    RailUnavailableError,
    receipt_settlement_payload,
)


def _settings() -> Settings:
    return Settings(
        database_url="postgresql+asyncpg://x/x",
        signing_key_path="/dev/null",
        issuer_did="did:web:x",
        policy_dir="policies",
        payment_rail="cvff-tigerbeetle",
        financial_controls_endpoint="https://fc.example",
        financial_controls_token="token-123",
    )


def _receipt() -> PaymentReceipt:
    return PaymentReceipt(
        id=uuid.uuid4(),
        payment_intent_id=uuid.uuid4(),
        external_reference="rem-rail-1",
        amount_kobo=12500,
        currency="NGN",
        status="APPLIED",
        received_at=datetime(2026, 8, 1, 12, 0, tzinfo=UTC),
    )


def test_payload_mapping():
    receipt = _receipt()
    payload = receipt_settlement_payload(receipt)
    assert payload == {
        "bankReference": "rem-rail-1",
        "amountMinor": 12500,
        "currency": "NGN",
        "payerRef": f"taxstamps:{receipt.payment_intent_id}",
        "valueDate": "2026-08-01",
    }


def test_unconfigured_rail_fails_closed():
    unconfigured = _settings().model_copy(update={"financial_controls_token": ""})
    with pytest.raises(RailUnavailableError):
        PaymentRailClient(unconfigured, None)


async def test_signed_forward_success(signing_key):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        seen["auth"] = request.headers["Authorization"]
        seen["jws"] = request.headers["X-Receipt-Envelope-JWS"]
        seen["idem"] = request.headers["Idempotency-Key"]
        return httpx.Response(201, json={"settlementId": "st-1"})

    client = PaymentRailClient(
        _settings(), signing_key,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    await client.forward_receipt(_receipt())
    assert seen["auth"] == "Bearer token-123"
    assert seen["idem"] == "rem-rail-1"
    # JWS verifies over the JCS-canonical posted body
    directory = KeyDirectory({signing_key.kid: signing_key.public_key})
    assert jws_verify(seen["jws"], directory, expected_payload=canonicalize_bytes(seen["body"]))


async def test_5xx_retries_then_unavailable(signing_key, monkeypatch):
    monkeypatch.setattr("taxstamps.services.payment_rail._BACKOFF_BASE_SECONDS", 0)
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(502, text="bad gateway")

    client = PaymentRailClient(
        _settings(), signing_key,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(RailUnavailableError):
        await client.forward_receipt(_receipt())
    assert calls["n"] == 3


async def test_4xx_terminal_no_retry(signing_key):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(422, text="bankReference is required")

    client = PaymentRailClient(
        _settings(), signing_key,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(RailRejectedError) as exc:
        await client.forward_receipt(_receipt())
    assert exc.value.status_code == 422
    assert calls["n"] == 1


async def test_timeout_retried_then_unavailable(signing_key, monkeypatch):
    monkeypatch.setattr("taxstamps.services.payment_rail._BACKOFF_BASE_SECONDS", 0)

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("boom", request=request)

    client = PaymentRailClient(
        _settings(), signing_key,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(RailUnavailableError):
        await client.forward_receipt(_receipt())
