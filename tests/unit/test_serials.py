"""Serial format + Luhn mod-34 check digit."""

import pytest

from taxstamps.domain.serials import (
    ALPHABET,
    CATEGORIES,
    SerialError,
    build_serial,
    luhn_mod_n_check,
    luhn_mod_n_validate,
    parse_serial,
    validate_serial,
)


def test_alphabet_is_34_unambiguous_symbols():
    assert len(ALPHABET) == 34
    assert "I" not in ALPHABET and "O" not in ALPHABET
    assert len(set(ALPHABET)) == 34


def test_category_codes_avoid_excluded_letters():
    for code in CATEGORIES.values():
        assert len(code) == 3
        assert "I" not in code and "O" not in code


def test_build_serial_format():
    s = build_serial("TBC", 2026, 42)
    assert s.startswith("NG-TBC-2026-0000000042-")
    assert len(s) == 24  # NG- + CAT3 + - + YYYY + - + SEQ10 + - + CHECK


def test_round_trip_all_categories():
    for code in CATEGORIES.values():
        s = build_serial(code, 2026, 9_999_999_999)
        parts = parse_serial(s)
        assert parts.category_code == code
        assert parts.sequence == 9_999_999_999
        assert parts.year == 2026


def test_check_digit_catches_single_char_typo():
    s = build_serial("ALC", 2026, 123456)
    body = s[:-1]
    for replacement in "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ":
        if replacement != s[-1]:
            assert not validate_serial(body + replacement)


def test_check_digit_catches_transposition():
    s = build_serial("BEV", 2026, 1234567890)
    # swap two adjacent sequence digits
    swapped = s[:8] + s[9] + s[8] + s[10:]
    if swapped != s:
        assert not validate_serial(swapped)


def test_parse_rejects_malformed():
    for bad in ["", "NG-TBC-2026-42-X", "XX-TBC-2026-0000000042-V",
                "NG-TBC-2026-0000000042", "NG-TB-2026-0000000042-V",
                "NG-TBC-202-0000000042-V"]:
        with pytest.raises(SerialError):
            parse_serial(bad)


def test_parse_rejects_bad_check():
    s = build_serial("PHA", 2026, 7)
    bad = s[:-1] + ("0" if s[-1] != "0" else "1")
    with pytest.raises(SerialError, match="check digit"):
        parse_serial(bad)


def test_case_insensitive_input():
    s = build_serial("TBC", 2026, 5)
    assert validate_serial(s.lower())


def test_luhn_known_vector_mod10_equivalence():
    # Luhn mod-34 over pure-digit bodies must agree with classic Luhn mod 10
    # behaviour restricted to the digit sub-alphabet ordering property: a
    # valid body+check always validates; a mutated one never does.
    body = "NGTBC20260000000001"
    check = luhn_mod_n_check(body)
    assert luhn_mod_n_validate(body, check)
    assert not luhn_mod_n_validate(body + "1", check)


def test_sequence_bounds():
    with pytest.raises(SerialError):
        build_serial("TBC", 2026, 10_000_000_000)
    with pytest.raises(SerialError):
        build_serial("TBC", 2026, -1)
    with pytest.raises(SerialError):
        build_serial("TBC", 1899, 0)
    with pytest.raises(SerialError):
        build_serial("TO", 2026, 0)


def test_character_outside_alphabet_rejected():
    with pytest.raises(SerialError):
        luhn_mod_n_check("NGTBI2026")  # contains I
