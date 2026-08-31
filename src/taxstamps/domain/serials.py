"""Tax stamp serial numbers with a Luhn mod-N check digit.

Format: ``NG-<CAT3>-<YYYY>-<SEQ10>-<CHECK>``  e.g. ``NG-TBC-2026-0000000042-7``.

- ``CAT3``  three-letter excise category code (TBC/ALC/PHA/BEV) — letters I
  and O never appear in category codes so every body character is inside the
  check-digit alphabet.
- ``YYYY``  issuance year.
- ``SEQ10`` zero-padded 10-digit sequence claimed atomically from the
  per-(category, year) serial counter.
- ``CHECK`` Luhn mod-34 check character computed over
  ``NG<CAT3><YYYY><SEQ10>`` (the serial body without separators) using a
  34-symbol alphabet: digits 0-9 plus uppercase letters A-Z excluding I and O
  (visual ambiguity with 1/0). Total 10 + 24 = 34 symbols.

The check character gives typo rejection before any database lookup. The
Luhn mod-N algorithm is the standard generalization of Luhn (mod 10) to an
arbitrary alphabet: process right to left, doubling every second code point
value, summing the base-N digits of each doubled value.
"""

from __future__ import annotations

import re

__all__ = [
    "ALPHABET",
    "CATEGORIES",
    "SerialError",
    "luhn_mod_n_check",
    "luhn_mod_n_validate",
    "build_serial",
    "parse_serial",
    "validate_serial",
    "SerialParts",
]

# 34 symbols: unambiguous digits and letters.
ALPHABET = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ"
assert len(ALPHABET) == 34

CATEGORIES: dict[str, str] = {
    "tobacco": "TBC",
    "alcohol": "ALC",
    "pharmaceuticals": "PHA",
    "beverages": "BEV",
}

_SERIAL_RE = re.compile(r"^NG-([A-Z]{3})-(\d{4})-(\d{10})-([0-9A-Z])$")

_INDEX = {ch: i for i, ch in enumerate(ALPHABET)}


class SerialError(ValueError):
    pass


def luhn_mod_n_check(body: str) -> str:
    """Return the check character for ``body`` under Luhn mod-34."""
    n = len(ALPHABET)
    factor = 2  # the rightmost body character is doubled first
    total = 0
    try:
        code_points = [_INDEX[ch] for ch in body]
    except KeyError as exc:
        raise SerialError(f"character {exc.args[0]!r} not in serial alphabet") from exc
    for cp in reversed(code_points):
        addend = factor * cp
        factor = 1 if factor == 2 else 2
        # Sum the base-N digits of the addend.
        addend = (addend // n) + (addend % n)
        total += addend
    remainder = total % n
    check_index = (n - remainder) % n
    return ALPHABET[check_index]


def luhn_mod_n_validate(body: str, check: str) -> bool:
    """Validate ``check`` against ``body`` (constant work for fixed input)."""
    if len(check) != 1 or check not in _INDEX:
        return False
    try:
        expected = luhn_mod_n_check(body)
    except SerialError:
        return False
    # Constant-time-ish: both are single characters from a 34-symbol alphabet.
    return expected == check


def build_serial(category_code: str, year: int, sequence: int) -> str:
    """Build a full serial with check character.

    ``sequence`` must be in [0, 9999999999]; counters guarantee uniqueness
    per (category_code, year).
    """
    cat = category_code.upper()
    if not re.fullmatch(r"[A-Z]{3}", cat):
        raise SerialError(f"invalid category code {category_code!r}")
    if not (1900 <= year <= 9999):
        raise SerialError(f"invalid year {year}")
    if not (0 <= sequence <= 9_999_999_999):
        raise SerialError(f"sequence {sequence} out of range")
    body = f"NG{cat}{year:04d}{sequence:010d}"
    return f"NG-{cat}-{year:04d}-{sequence:010d}-{luhn_mod_n_check(body)}"


class SerialParts:
    __slots__ = ("category_code", "year", "sequence", "check", "serial")

    def __init__(self, category_code: str, year: int, sequence: int, check: str, serial: str) -> None:
        self.category_code = category_code
        self.year = year
        self.sequence = sequence
        self.check = check
        self.serial = serial

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"SerialParts({self.serial!r})"


def parse_serial(serial: str) -> SerialParts:
    """Parse and check-digit-validate a serial. Raises SerialError on any defect.

    Callers must run this before any database lookup so malformed or
    mis-transcribed serials never touch the store.
    """
    if not isinstance(serial, str):
        raise SerialError("serial must be a string")
    serial = serial.strip().upper()
    m = _SERIAL_RE.match(serial)
    if not m:
        raise SerialError("serial does not match NG-<CAT3>-<YYYY>-<SEQ10>-<CHECK>")
    cat, year_s, seq_s, check = m.groups()
    body = f"NG{cat}{year_s}{seq_s}"
    if not luhn_mod_n_validate(body, check):
        raise SerialError("serial check digit mismatch")
    return SerialParts(cat, int(year_s), int(seq_s), check, serial)


def validate_serial(serial: str) -> bool:
    try:
        parse_serial(serial)
        return True
    except SerialError:
        return False
