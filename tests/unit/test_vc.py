"""VC 2.0 eddsa-jcs-2022 round-trip, tamper detection, base58btc, merkle."""

import copy

import pytest

from taxstamps.crypto.vc import (
    VCError,
    base58btc_decode,
    base58btc_encode,
    build_stamp_credential,
    issue_proof,
    verify_proof,
)
from taxstamps.domain.merkle import leaf_hash, merkle_root


def _doc():
    return build_stamp_credential(
        credential_id="did:web:example/credentials/NG-TBC-2026-0000000001-A",
        issuer_did="did:web:taxstamps.blueeconomy.gov.ng",
        serial="NG-TBC-2026-0000000001-A",
        hs_code="2402.20",
        declaration_ref="DECL-2026-000123",
        consignee_tin="12345678-0001",
        duty_paid_kobo=800_000,
        valid_from="2026-07-01T00:00:00Z",
        valid_until="2027-07-01T00:00:00Z",
        status_entries=[],
    )


def test_sign_verify_round_trip(signing_key):
    signed = issue_proof(_doc(), signing_key, "did:web:taxstamps.blueeconomy.gov.ng#ed25519-blueeconomy-tax-stamps-0")
    assert signed["proof"]["cryptosuite"] == "eddsa-jcs-2022"
    assert signed["proof"]["proofValue"].startswith("z")
    verify_proof(signed, signing_key.public_key)  # no raise


def test_vc_context_and_type(signing_key):
    signed = issue_proof(_doc(), signing_key, "vm")
    assert signed["@context"] == ["https://www.w3.org/ns/credentials/v2"]
    assert signed["type"] == ["VerifiableCredential", "ExciseTaxStamp"]
    subject = signed["credentialSubject"]
    assert subject["serial"] == "NG-TBC-2026-0000000001-A"
    assert subject["dutyPaidKobo"] == 800_000
    assert subject["consigneeTin"] == "12345678-0001"


def test_tampered_subject_rejected(signing_key):
    signed = issue_proof(_doc(), signing_key, "vm")
    tampered = copy.deepcopy(signed)
    tampered["credentialSubject"]["dutyPaidKobo"] = 1
    with pytest.raises(VCError, match="invalid-proof"):
        verify_proof(tampered, signing_key.public_key)


def test_tampered_proof_created_rejected(signing_key):
    signed = issue_proof(_doc(), signing_key, "vm")
    tampered = copy.deepcopy(signed)
    tampered["proof"]["created"] = "2020-01-01T00:00:00Z"
    with pytest.raises(VCError, match="invalid-proof"):
        verify_proof(tampered, signing_key.public_key)


def test_wrong_key_rejected(signing_key):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    signed = issue_proof(_doc(), signing_key, "vm")
    with pytest.raises(VCError, match="invalid-proof"):
        verify_proof(signed, Ed25519PrivateKey.generate().public_key())


def test_missing_and_malformed_proof(signing_key):
    with pytest.raises(VCError, match="missing-proof"):
        verify_proof(_doc(), signing_key.public_key)
    signed = issue_proof(_doc(), signing_key, "vm")
    bad = copy.deepcopy(signed)
    bad["proof"]["cryptosuite"] = "eddsa-rdfc-2022"
    with pytest.raises(VCError, match="unsupported-cryptosuite"):
        verify_proof(bad, signing_key.public_key)
    bad2 = copy.deepcopy(signed)
    bad2["proof"]["proofValue"] = "x" + signed["proof"]["proofValue"][1:]
    with pytest.raises(VCError, match="malformed-proof"):
        verify_proof(bad2, signing_key.public_key)


def test_double_sign_rejected(signing_key):
    signed = issue_proof(_doc(), signing_key, "vm")
    with pytest.raises(VCError, match="already-signed"):
        issue_proof(signed, signing_key, "vm")


def test_base58btc_round_trip():
    for raw in [b"", b"\x00", b"\x00\x00\x01", bytes(range(64)), b"hello world"]:
        assert base58btc_decode(base58btc_encode(raw)) == raw


def test_base58btc_known_vector():
    assert base58btc_encode(b"hello world") == "StV1DL6CwTryKyV"
    assert base58btc_decode("StV1DL6CwTryKyV") == b"hello world"


def test_merkle_root_deterministic_and_ordered():
    leaves = [b"a", b"b", b"c"]
    r1 = merkle_root(leaves)
    assert r1 == merkle_root(leaves)
    assert r1 != merkle_root([b"c", b"b", b"a"])
    assert r1 != merkle_root([b"a", b"b"])


def test_merkle_leaf_domain_separation():
    # leaf hash of X must differ from any inner-node encoding of X
    assert leaf_hash(b"x") != leaf_hash(b"y")
    root_single = merkle_root([b"x"])
    assert root_single == leaf_hash(b"x").hex()


def test_merkle_empty():
    import hashlib

    assert merkle_root([]) == hashlib.sha256(b"").hexdigest()


def test_merkle_odd_leaf_count():
    assert len(merkle_root([b"a", b"b", b"c", b"d", b"e"])) == 64
