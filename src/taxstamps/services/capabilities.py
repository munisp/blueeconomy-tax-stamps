"""Honesty registry: GET /v1/capabilities publishes exactly what is and is
not available. An unconfigured integration is reported unavailable-with-reason
and its dependent routes return 503 — success is never fabricated."""

from __future__ import annotations

from typing import Any

from taxstamps.config import Settings

_KAFKA_REASON = "TAXSTAMPS_KAFKA_BOOTSTRAP_SERVERS not configured"
_RAIL_REASON = "TAXSTAMPS_PAYMENT_RAIL and TAXSTAMPS_FINANCIAL_CONTROLS_ENDPOINT not configured"


def capability_report(settings: Settings, runtime: dict[str, bool | str]) -> dict[str, Any]:
    """``runtime`` carries live probe results keyed by integration name."""
    caps: list[dict[str, Any]] = []

    def add(name: str, available: bool, reason: str = "") -> None:
        entry: dict[str, Any] = {"capability": name, "available": available}
        if not available:
            entry["reason"] = reason
        caps.append(entry)

    def reason(key: str, default: str) -> str:
        return str(runtime.get(key) or default)

    add("database", bool(runtime.get("database")), reason("database_reason", "database probe failed"))
    add("signing.eddsa-jcs-2022", bool(runtime.get("signing")), reason("signing_reason", "signing key unavailable"))
    add("status-list.bitstring", bool(runtime.get("signing")), "requires signing key")

    if settings.redis_configured:
        add("redis.nonce-rate-limit", bool(runtime.get("redis")), reason("redis_reason", "redis probe failed"))
    else:
        add("redis.nonce-rate-limit", False, "TAXSTAMPS_REDIS_URL not configured")

    if settings.oidc_configured:
        add("auth.oidc", bool(runtime.get("oidc")), str(runtime.get("oidc_reason") or "JWKS unavailable"))
    else:
        add("auth.oidc", False, "TAXSTAMPS_OIDC_JWKS_URL/PATH and TAXSTAMPS_OIDC_ISSUER not configured")

    if settings.kafka_configured:
        add("kafka.outbox-publisher", bool(runtime.get("kafka")), reason("kafka_reason", "Kafka unreachable"))
        add("kafka.declarations-consumer", bool(runtime.get("kafka")), reason("kafka_reason", "Kafka unreachable"))
    else:
        add("kafka.outbox-publisher", False, _KAFKA_REASON)
        add("kafka.declarations-consumer", False, _KAFKA_REASON)

    if settings.payment_rail_configured:
        add("payments.rail", True, "")
    else:
        add("payments.rail", False, _RAIL_REASON)

    # Declared-but-not-implemented scope, stated truthfully.
    add("verification.public-self-service", True, "")
    add("verification.first-scan-wins", True, "")
    add("printer.hardware-integration", False, "not implemented: no printer control path exists in this service")
    add("image.ml-authenticity", False, "not implemented: no image/ML authenticity detector")
    add("offline.field-sync", False, "not implemented: verification requires connectivity to this API")

    return {"service": "blueeconomy-tax-stamps", "capabilities": caps}


def capability_available(report: dict[str, Any], name: str) -> bool:
    for cap in report["capabilities"]:
        if cap["capability"] == name:
            return bool(cap["available"])
    return False
