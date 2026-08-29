"""Bitstring Status List: bit ops, encode/decode, credential build/parse."""

import pytest

from taxstamps.crypto.statuslist import (
    DEFAULT_LIST_SIZE_BITS,
    StatusList,
    StatusListError,
    build_status_list_credential,
    parse_status_list_credential,
    status_entry,
)


def test_bit_ops_w3c_ordering():
    sl = StatusList(size_bits=64)
    assert not sl.get(0)
    sl.set(0)
    sl.set(7)
    sl.set(8)
    assert sl.get(0) and sl.get(7) and sl.get(8)
    assert not sl.get(1)
    raw = sl.raw_bytes()
    assert raw[0] == 0b1000_0001  # MSB-first: bits 0 and 7
    assert raw[1] == 0b1000_0000  # bit 8 -> byte 1 MSB


def test_set_unset():
    sl = StatusList(size_bits=64)
    sl.set(3, True)
    assert sl.get(3)
    sl.set(3, False)
    assert not sl.get(3)


def test_index_bounds():
    sl = StatusList(size_bits=64)
    with pytest.raises(StatusListError):
        sl.get(64)
    with pytest.raises(StatusListError):
        sl.set(-1)


def test_encode_decode_round_trip():
    sl = StatusList()
    for i in (0, 5, 1000, DEFAULT_LIST_SIZE_BITS - 1):
        sl.set(i)
    encoded = sl.encode()
    assert encoded.startswith("u")
    assert "=" not in encoded
    decoded = StatusList.decode(encoded)
    for i in (0, 5, 1000, DEFAULT_LIST_SIZE_BITS - 1):
        assert decoded.get(i)
    assert not decoded.get(6)


def test_decode_rejects_malformed():
    with pytest.raises(StatusListError):
        StatusList.decode("xAAA")
    with pytest.raises(StatusListError):
        StatusList.decode("u!!!!")
    with pytest.raises(StatusListError):
        StatusList.decode("uAA==")


def test_credential_build_and_parse(signing_key):
    sl = StatusList()
    sl.set(42)
    cred = build_status_list_credential(
        list_credential_id="https://taxstamps.example/status-list/void",
        issuer_did="did:web:taxstamps.example",
        status_purpose="void",
        status_list=sl,
        key=signing_key,
        verification_method="did:web:taxstamps.example#ed25519-blueeconomy-tax-stamps-0",
    )
    assert cred["type"] == ["VerifiableCredential", "BitstringStatusListCredential"]
    assert "proof" in cred
    purpose, parsed = parse_status_list_credential(cred)
    assert purpose == "void"
    assert parsed.get(42)
    assert not parsed.get(41)


def test_credential_unsigned_when_no_key():
    cred = build_status_list_credential(
        list_credential_id="x", issuer_did="y", status_purpose="suspect",
        status_list=StatusList(),
    )
    assert "proof" not in cred


def test_unknown_purpose_rejected():
    with pytest.raises(StatusListError):
        build_status_list_credential(
            list_credential_id="x", issuer_did="y", status_purpose="revocation",
            status_list=StatusList(),
        )
    with pytest.raises(StatusListError):
        status_entry("x", 0, "revocation")


def test_status_entry_shape():
    entry = status_entry("https://example/list/void", 17, "void")
    assert entry["type"] == "BitstringStatusListEntry"
    assert entry["statusPurpose"] == "void"
    assert entry["statusListIndex"] == "17"
    assert entry["statusListCredential"] == "https://example/list/void"
    assert entry["id"] == "https://example/list/void#17"
