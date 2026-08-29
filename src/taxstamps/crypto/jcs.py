"""RFC 8785 JSON Canonicalization Scheme (JCS).

Clean-room implementation. Every platform producer/consumer must agree on
this byte-for-byte (see blueeconomy-contracts docs/envelope-signature.md):

- object members sorted by key (UTF-16 code-unit order; for BMP strings this
  is identical to Python's code-point ordering; astral-plane keys are
  converted to UTF-16 code units for sorting);
- no whitespace;
- minimal string escaping: only the mandatory control-character escapes,
  backslash and quote; non-ASCII emitted raw (UTF-8), never ``\\u`` escaped;
- numbers follow ECMAScript ``Number::toString`` semantics: shortest
  round-trip, integers without fraction/exponent, exponential form only for
  |x| < 1e-6 or |x| >= 1e21;
- no duplicate object keys (rejected on input construction by callers).

Platform envelope and VC payloads deliberately avoid non-integral numbers
(money is integer kobo, coordinates integer micro-degrees), but the number
path is implemented and unit-tested for conformance anyway.
"""

from __future__ import annotations

import json
from typing import Any

__all__ = ["canonicalize", "canonicalize_bytes", "CanonicalizationError"]


class CanonicalizationError(ValueError):
    """Raised for values JCS cannot represent (NaN, Infinity, non-JSON types)."""


_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _escape_string(value: str) -> str:
    out: list[str] = ['"']
    for ch in value:
        esc = _ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_sort_key(value: str) -> bytes:
    """Sort key per RFC 8785: UTF-16 code units (big-endian for byte order)."""
    return value.encode("utf-16-be", "surrogatepass")


def _number_to_string(value: float) -> str:
    """ECMAScript Number::toString for IEEE-754 doubles.

    Python's ``repr`` already yields the shortest round-trip decimal, so the
    work here is choosing the same fixed/exponential notation thresholds as
    ECMAScript and formatting the exponent identically.
    """
    if value != value or value in (float("inf"), float("-inf")):
        raise CanonicalizationError("JCS cannot represent NaN or Infinity")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    # Shortest round-trip digits + decimal exponent via repr parsing.
    mantissa_digits, exp10 = _shortest_digits(value)
    n = len(mantissa_digits) + exp10  # value == 0.<digits> * 10**n
    k = len(mantissa_digits)
    if k <= n <= 21:
        # Integer: digits followed by (n - k) zeros.
        return sign + mantissa_digits + "0" * (n - k)
    if 0 < n <= 21:
        # Fixed notation with a fraction part.
        return sign + mantissa_digits[:n] + "." + mantissa_digits[n:]
    if -6 < n <= 0:
        # 0.000ddd fixed notation.
        return sign + "0." + "0" * (-n) + mantissa_digits
    # Exponential notation.
    if k == 1:
        mant = mantissa_digits
    else:
        mant = mantissa_digits[0] + "." + mantissa_digits[1:]
    exp = n - 1
    exp_sign = "+" if exp >= 0 else ""
    return f"{sign}{mant}e{exp_sign}{exp}"


def _shortest_digits(value: float) -> tuple[str, int]:
    """Return (digits, exp10) such that abs(value) == int(digits) * 10**exp10,
    with ``digits`` the shortest decimal that round-trips (same digits as
    ECMAScript Number::toString, via Python's shortest-repr)."""
    rep = repr(abs(value))
    if "e" in rep or "E" in rep:
        mant, _, exp_s = rep.partition("e")
        e = int(exp_s)
    else:
        mant, e = rep, 0
    if "." in mant:
        int_part, _, frac_part = mant.partition(".")
    else:
        int_part, frac_part = mant, ""
    digits = (int_part + frac_part).lstrip("0")
    exp10 = e - len(frac_part)
    trailing = len(digits) - len(digits.rstrip("0"))
    digits = digits.rstrip("0") or "0"
    exp10 += trailing
    return digits, exp10


def _encode(value: Any, out: list[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        out.append(_escape_string(value))
    elif isinstance(value, int):
        # JSON numbers are doubles; integers beyond 2**53 are rejected so no
        # implementation can disagree on their decimal rendering.
        if abs(value) > 9007199254740991:
            raise CanonicalizationError(f"integer {value} exceeds IEEE-754 safe range")
        out.append(str(value))
    elif isinstance(value, float):
        if value.is_integer() and abs(value) <= 9007199254740991:
            out.append(str(int(value)))
        else:
            out.append(_number_to_string(value))
    elif isinstance(value, list) or isinstance(value, tuple):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _encode(item, out)
        out.append("]")
    elif isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: _utf16_sort_key(kv[0]))
        out.append("{")
        for i, (k, v) in enumerate(items):
            if i:
                out.append(",")
            if not isinstance(k, str):
                raise CanonicalizationError("object keys must be strings")
            _escape_into(k, out)
            out.append(":")
            _encode(v, out)
        out.append("}")
    else:
        raise CanonicalizationError(f"unsupported type for JCS: {type(value).__name__}")


def _escape_into(value: str, out: list[str]) -> None:
    out.append(_escape_string(value))


def canonicalize(value: Any) -> str:
    """Return the RFC 8785 canonical JSON string for ``value``."""
    out: list[str] = []
    _encode(value, out)
    return "".join(out)


def canonicalize_bytes(value: Any) -> bytes:
    return canonicalize(value).encode("utf-8")


def parse_and_canonicalize(raw: bytes | str) -> bytes:
    """Parse JSON and re-canonicalize (used by verifiers)."""
    data = json.loads(raw)
    return canonicalize_bytes(data)
