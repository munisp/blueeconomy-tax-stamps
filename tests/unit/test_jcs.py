"""RFC 8785 JCS conformance, including the public RFC test vectors."""

import json

import pytest

from taxstamps.crypto.jcs import (
    CanonicalizationError,
    canonicalize,
    canonicalize_bytes,
    parse_and_canonicalize,
)


def test_object_key_ordering():
    assert canonicalize({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_no_whitespace_nested():
    assert canonicalize({"a": [1, {"x": True}, None]}) == '{"a":[1,{"x":true},null]}'


def test_string_escapes():
    assert canonicalize("a\nb") == '"a\\nb"'
    assert canonicalize('q"q') == '"q\\"q"'
    assert canonicalize("back\\slash") == '"back\\\\slash"'
    assert canonicalize("\t") == '"\\t"'
    assert canonicalize("\x01") == '"\\u0001"'


def test_non_ascii_raw_utf8():
    assert canonicalize("₦") == '"₦"'
    assert canonicalize({"€": 1}) == '{"€":1}'


def test_utf16_sort_order():
    # astral-plane character U+1F600 sorts AFTER BMP per UTF-16 code units
    assert canonicalize({"\U0001F600": 1, "z": 2}) == '{"z":2,"\U0001F600":1}'


def test_integer_rendering():
    assert canonicalize(0) == "0"
    assert canonicalize(-42) == "-42"
    assert canonicalize(1_000_000) == "1000000"
    assert canonicalize(9007199254740991) == "9007199254740991"


def test_float_integral_rendering():
    assert canonicalize(5.0) == "5"


def test_float_fixed_notation():
    assert canonicalize(0.5) == "0.5"
    assert canonicalize(-0.000001) == "-0.000001"
    assert canonicalize(3.25) == "3.25"


def test_float_exponential_thresholds():
    assert canonicalize(1e21) == "1e+21"
    assert canonicalize(1e20) == "100000000000000000000"
    assert canonicalize(1e-7) == "1e-7"
    assert canonicalize(1e-6) == "0.000001"


def test_rfc8785_appendix_vector():
    # RFC 8785 §3.2.2.2 style: shortest round-trip digits must match repr
    assert canonicalize(333333333.33333329) == "333333333.3333333"
    assert canonicalize(6.02e23) == "6.02e+23"


def test_duplicate_semantics_via_json_roundtrip():
    raw = b'{"b":1,  "a" : [ true , null ]}'
    assert parse_and_canonicalize(raw) == b'{"a":[true,null],"b":1}'


def test_nan_infinity_rejected():
    with pytest.raises(CanonicalizationError):
        canonicalize(float("nan"))
    with pytest.raises(CanonicalizationError):
        canonicalize(float("inf"))


def test_unsafe_integer_rejected():
    with pytest.raises(CanonicalizationError):
        canonicalize(2**53)
    with pytest.raises(CanonicalizationError):
        canonicalize(-(2**53))


def test_unsupported_type_rejected():
    with pytest.raises(CanonicalizationError):
        canonicalize(object())


def test_bytes_helper():
    assert canonicalize_bytes({"a": "é"}) == '{"a":"é"}'.encode()


def test_json_module_agreement_on_basic_types():
    value = {"x": [1, 2.5, "s", None, True], "y": {"k": "v"}}
    # canonical output must parse back to an equal value
    assert json.loads(canonicalize(value)) == value
