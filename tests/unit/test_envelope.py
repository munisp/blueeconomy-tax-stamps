"""Envelope v1.0 sign/verify per the fleet envelope-signature scheme."""

import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from taxstamps.crypto.eddsa import (
    JwsError,
    KeyDirectory,
    b64u_decode,
    b64u_encode,
    jws_sign,
    jws_verify,
)
from taxstamps.events.envelope import (
    EnvelopeError,
    build_envelope,
    sign_envelope,
    verify_envelope,
)


@pytest.fixture(scope="module")
def directory(signing_key) -> KeyDirectory:
    return KeyDirectory({signing_key.kid: signing_key.public_key})


def _envelope():
    return build_envelope(
        event_type="stamps.assessed.v1",
        resource={"assessmentId": "a-1", "totalDutyKobo": 100},
        producer="blueeconomy-tax-stamps",
        classification="CONFIDENTIAL",
        principal_id="sub-1",
        principal_role="excise-officer",
    )


def test_jws_round_trip(signing_key, directory):
    jws = jws_sign(signing_key, b"payload")
    assert jws.count(".") == 2
    assert "=" not in jws
    assert jws_verify(jws, directory, expected_payload=b"payload") == b"payload"


def test_jws_reason_codes(signing_key, directory):
    jws = jws_sign(signing_key, b"payload")
    with pytest.raises(JwsError) as e1:
        jws_verify(jws, directory, expected_payload=b"other")
    assert e1.value.reason == "payload-mismatch"

    with pytest.raises(JwsError) as e2:
        jws_verify("a.b", directory)
    assert e2.value.reason == "malformed-jws"

    parts = jws.split(".")
    with pytest.raises(JwsError) as e3:
        jws_verify(".".join([parts[0], parts[1], parts[2][:-2] + "AA"]), directory)
    assert e3.value.reason == "invalid-signature"


def test_jws_unknown_kid_and_bad_alg(signing_key, directory):
    jws = jws_sign(signing_key, b"p")
    h, p, s = jws.split(".")
    import json as _json

    bad_kid_header = b64u_encode(_json.dumps({"alg": "EdDSA", "kid": "nobody-0"}).encode())
    with pytest.raises(JwsError) as e1:
        jws_verify(f"{bad_kid_header}.{p}.{s}", directory)
    assert e1.value.reason == "unknown-kid"

    bad_alg_header = b64u_encode(_json.dumps({"alg": "HS256", "kid": signing_key.kid}).encode())
    with pytest.raises(JwsError) as e2:
        jws_verify(f"{bad_alg_header}.{p}.{s}", directory)
    assert e2.value.reason == "unsupported-alg"


def test_b64u_padding_rejected():
    with pytest.raises(JwsError):
        b64u_decode("AA==")
    assert b64u_encode(b"\x00") == "AA"


def test_envelope_sign_verify(signing_key, directory):
    signed = sign_envelope(_envelope(), signing_key)
    resource = verify_envelope(signed, directory, expected_event_type="stamps.assessed.v1")
    assert resource["assessmentId"] == "a-1"


def test_envelope_tamper_rejected(signing_key, directory):
    signed = sign_envelope(_envelope(), signing_key)
    tampered = copy.deepcopy(signed)
    tampered["fhir"]["entry"][0]["resource"]["totalDutyKobo"] = 1
    with pytest.raises(EnvelopeError) as exc:
        verify_envelope(tampered, directory)
    assert exc.value.reason == "payload-mismatch"


def test_envelope_structural_fail_closed(signing_key, directory):
    signed = sign_envelope(_envelope(), signing_key)
    bad_version = copy.deepcopy(signed)
    bad_version["envelopeVersion"] = "0.9"
    with pytest.raises(EnvelopeError, match="malformed-envelope"):
        verify_envelope(bad_version, directory)

    bad_type = copy.deepcopy(signed)
    with pytest.raises(EnvelopeError) as exc:
        verify_envelope(bad_type, directory, expected_event_type="stamps.voided.v1")
    assert exc.value.reason == "event-type-mismatch"

    bad_bundle = copy.deepcopy(signed)
    bad_bundle["fhir"]["type"] = "collection"
    with pytest.raises(EnvelopeError, match="malformed-envelope"):
        verify_envelope(bad_bundle, directory)


def test_envelope_resource_type_mismatch(signing_key, directory):
    env = _envelope()
    env["fhir"]["entry"][0]["resource"]["@type"] = "type.googleapis.com/other.Wrong"
    signed = sign_envelope(env, signing_key)
    with pytest.raises(EnvelopeError) as exc:
        verify_envelope(signed, directory)
    assert exc.value.reason == "resource-type-mismatch"


def test_envelope_unsigned_rejected(directory):
    with pytest.raises(EnvelopeError) as exc:
        verify_envelope(_envelope(), directory)
    assert exc.value.reason == "malformed-jws"


def test_key_directory_load_failures(tmp_path):
    with pytest.raises(JwsError):
        KeyDirectory.load(str(tmp_path / "missing.json"))
    p = tmp_path / "dir.json"
    p.write_text("{}")
    with pytest.raises(JwsError):
        KeyDirectory.load(str(p))
    p.write_text('{"bad kid!": "AA"}')
    with pytest.raises(JwsError):
        KeyDirectory.load(str(p))
    p.write_text('{"good-kid-0": "AA"}')  # 1 byte, not 32
    with pytest.raises(JwsError):
        KeyDirectory.load(str(p))


def test_placeholder_key_refused(tmp_path, monkeypatch):
    from taxstamps.crypto.eddsa import generate_pkcs8_pem, load_signing_key

    monkeypatch.setenv("TAXSTAMPS_ALLOW_PERMISSIVE_KEY_FILE", "1")
    p = tmp_path / "key.pem"
    p.write_bytes(generate_pkcs8_pem() + b"\n# CHANGE_ME placeholder\n")
    with pytest.raises(JwsError) as exc:
        load_signing_key(str(p), "kid-0")
    assert exc.value.reason == "placeholder-key"


def test_key_permissions_enforced(tmp_path, monkeypatch):
    import os

    from taxstamps.crypto.eddsa import generate_pkcs8_pem, load_signing_key

    monkeypatch.delenv("TAXSTAMPS_ALLOW_PERMISSIVE_KEY_FILE", raising=False)
    p = tmp_path / "key.pem"
    p.write_bytes(generate_pkcs8_pem())
    os.chmod(p, 0o644)
    with pytest.raises(JwsError) as exc:
        load_signing_key(str(p), "kid-0")
    assert exc.value.reason == "key-unavailable"
    os.chmod(p, 0o600)
    key = load_signing_key(str(p), "kid-0")
    assert isinstance(key.public_key, Ed25519PublicKey)
