"""Outbound payment rail: forward APPLIED receipts to financial-controls.

Every APPLIED receipt is mirrored to the financial-controls revenue contract
(``POST {TAXSTAMPS_FINANCIAL_CONTROLS_ENDPOINT}/v1/revenue/settlements``) as
the collection record. The receipt payload is JCS-canonicalized (RFC 8785)
and signed with the service Ed25519 key (JWS compact, EdDSA) carried in the
``X-Receipt-Envelope-JWS`` header so the downstream side can verify
provenance independently of the bearer token.

Fail-closed semantics:
- 5xx responses and transport timeouts are transient: retried with backoff,
  then surfaced as ``RailUnavailableError`` (the API layer answers 503 and
  rolls the receipt back — a receipt is never committed unless the rail
  mirror succeeded);
- 4xx responses are terminal contract rejections: ``RailRejectedError``,
  never retried.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from taxstamps.config import Settings
from taxstamps.crypto.eddsa import SigningKey, jws_sign
from taxstamps.crypto.jcs import canonicalize_bytes
from taxstamps.models import PaymentReceipt

_TIMEOUT_SECONDS = 5.0
_MAX_ATTEMPTS = 3
_BACKOFF_BASE_SECONDS = 0.25


class RailUnavailableError(ValueError):
    """Transient rail failure after retries (maps to HTTP 503)."""


class RailRejectedError(ValueError):
    """Terminal 4xx contract rejection by financial-controls."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(f"rail rejected the receipt with HTTP {status_code}: {detail}")
        self.status_code = status_code


def receipt_settlement_payload(receipt: PaymentReceipt) -> dict[str, Any]:
    """Map an APPLIED receipt onto the FC SettlementInput contract."""
    return {
        "bankReference": receipt.external_reference,
        "amountMinor": int(receipt.amount_kobo),
        "currency": receipt.currency,
        "payerRef": f"taxstamps:{receipt.payment_intent_id}",
        "valueDate": receipt.received_at.strftime("%Y-%m-%d"),
    }


class PaymentRailClient:
    """Signed httpx client for the financial-controls settlement endpoint."""

    def __init__(
        self,
        settings: Settings,
        signing_key: SigningKey,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if not settings.payment_rail_configured:
            raise RailUnavailableError(
                "payment rail is not configured "
                "(TAXSTAMPS_PAYMENT_RAIL / TAXSTAMPS_FINANCIAL_CONTROLS_ENDPOINT / "
                "TAXSTAMPS_FINANCIAL_CONTROLS_TOKEN)"
            )
        self._endpoint = settings.financial_controls_endpoint.rstrip("/")
        self._token = settings.financial_controls_token
        self._signing_key = signing_key
        self._client = http_client or httpx.AsyncClient(timeout=_TIMEOUT_SECONDS)
        self._owns_client = http_client is None

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def forward_receipt(self, receipt: PaymentReceipt) -> None:
        payload = receipt_settlement_payload(receipt)
        jws = jws_sign(self._signing_key, canonicalize_bytes(payload))
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
            "Idempotency-Key": receipt.external_reference,
            "X-Receipt-Envelope-JWS": jws,
        }
        url = f"{self._endpoint}/v1/revenue/settlements"
        last_error: Exception | None = None
        for attempt in range(_MAX_ATTEMPTS):
            try:
                response = await self._client.post(url, json=payload, headers=headers)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_error = exc
            else:
                if response.status_code < 400:
                    return
                if 400 <= response.status_code < 500:
                    raise RailRejectedError(response.status_code, response.text[:200])
                last_error = RailUnavailableError(f"HTTP {response.status_code}")
            if attempt + 1 < _MAX_ATTEMPTS:
                await asyncio.sleep(_BACKOFF_BASE_SECONDS * (2**attempt))
        raise RailUnavailableError(
            f"financial-controls rail unavailable after {_MAX_ATTEMPTS} attempts: {last_error}"
        )
