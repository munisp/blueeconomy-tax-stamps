"""HTTP-level integration via the real app (TestClient runs the real lifespan):
capabilities honesty registry, client-total rejection (422), fail-closed auth
(503 when OIDC is unconfigured), public issuer key."""

import stat

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)


@pytest.fixture()
def client(migrated_url, tmp_path, monkeypatch):
    key_path = tmp_path / "ed25519.pem"
    key_path.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    monkeypatch.setenv("TAXSTAMPS_DATABASE_URL", migrated_url)
    monkeypatch.setenv("TAXSTAMPS_SIGNING_KEY_PATH", str(key_path))
    monkeypatch.setenv("TAXSTAMPS_ISSUER_DID", "did:web:taxstamps.blueeconomy.gov.ng")
    monkeypatch.setenv("TAXSTAMPS_POLICY_DIR", "policies")
    monkeypatch.delenv("TAXSTAMPS_REDIS_URL", raising=False)
    monkeypatch.delenv("TAXSTAMPS_OIDC_JWKS_URL", raising=False)
    monkeypatch.delenv("TAXSTAMPS_OIDC_JWKS_PATH", raising=False)
    monkeypatch.delenv("TAXSTAMPS_OIDC_ISSUER", raising=False)
    monkeypatch.delenv("TAXSTAMPS_KAFKA_BOOTSTRAP_SERVERS", raising=False)
    monkeypatch.delenv("TAXSTAMPS_PAYMENT_RAIL", raising=False)
    from taxstamps.config import get_settings

    get_settings.cache_clear()
    from fastapi.testclient import TestClient

    from taxstamps.main import app

    with TestClient(app) as c:
        yield c
    get_settings.cache_clear()


def test_healthz_readyz(client):
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code == 200


def test_capabilities_honesty(client):
    report = client.get("/v1/capabilities").json()
    caps = {c["capability"]: c for c in report["capabilities"]}
    assert caps["database"]["available"] is True
    assert caps["signing.eddsa-jcs-2022"]["available"] is True
    # unconfigured integrations: unavailable WITH reason, never fabricated
    assert caps["auth.oidc"]["available"] is False and caps["auth.oidc"]["reason"]
    assert caps["payments.rail"]["available"] is False and caps["payments.rail"]["reason"]
    assert caps["kafka.outbox-publisher"]["available"] is False
    assert caps["printer.hardware-integration"]["available"] is False


def test_auth_fail_closed_when_oidc_unconfigured(client):
    resp = client.post("/v1/assessments", json={"declaration_ref": "X-1"})
    assert resp.status_code == 503


def test_client_supplied_totals_rejected_422(client):
    # Auth runs before body parsing (fail-closed), so schema strictness is
    # demonstrated on the unauthenticated public verification endpoint.
    resp = client.post("/v1/verify/public", json={"total_duty_kobo": 1})
    assert resp.status_code == 422
    assert resp.headers["content-type"].startswith("application/problem+json")
    # and the declaration schema itself rejects smuggled totals (unit-level
    # proof lives in tests/unit/test_schemas.py)
    from pydantic import ValidationError

    from taxstamps.api.schemas import DeclarationIn

    with pytest.raises(ValidationError):
        DeclarationIn.model_validate({
            "declaration_ref": "DECL-X",
            "consignee_tin": "12345678-0001",
            "total_duty_kobo": 1,
            "lines": [
                {"hs_code": "2203.00", "quantity": 10, "unit": "LITRE",
                 "customs_value_kobo": 100, "stamps_required": 10,
                 "total_duty_kobo": 1},
            ],
        })


def test_public_issuer_key(client):
    did = "did:web:taxstamps.blueeconomy.gov.ng"
    resp = client.get(f"/v1/issuers/{did}/key")
    assert resp.status_code == 200
    body = resp.json()
    assert body["kid"] == "blueeconomy-tax-stamps-0"
    assert body["public_key_b64u"]
    assert client.get("/v1/issuers/did:web:other/key").status_code == 404


def test_status_list_404_until_published(client):
    assert client.get("/v1/status-list/void").status_code == 404
    assert client.get("/v1/status-list/bogus").status_code == 404


def test_audit_chain_endpoint(client):
    resp = client.get("/v1/ops/audit-chain")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
