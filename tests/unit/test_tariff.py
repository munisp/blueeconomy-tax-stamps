"""Excise tariff: effective dating, rates, statutory references."""

from datetime import date

import pytest

from taxstamps.domain.money import MoneyError, ad_valorem_kobo
from taxstamps.domain.tariff import (
    ExciseError,
    category_for_hs,
    compute_line_duty,
    rate_for,
)


def test_cigarettes_2026_rate():
    d = compute_line_duty("2402.20.00", 1000, 0, date(2026, 7, 1))
    assert d is not None
    assert d.specific_duty_kobo == 1000 * 800  # NGN 8.00/stick
    assert d.ad_valorem_duty_kobo == 0
    assert "2026" in d.tariff.statutory_ref


def test_cigarettes_prior_rate():
    d = compute_line_duty("2402.20.00", 1000, 0, date(2026, 6, 30))
    assert d is not None
    assert d.specific_duty_kobo == 1000 * 600  # NGN 6.00/stick


def test_beer_2026_rate():
    d = compute_line_duty("2203.00", 500, 0, date(2026, 8, 1))
    assert d.specific_duty_kobo == 500 * 8000  # NGN 80.00/l


def test_beer_prior_rate():
    d = compute_line_duty("2203.00", 500, 0, date(2026, 1, 1))
    assert d.specific_duty_kobo == 500 * 7200  # NGN 72.00/l


def test_spirits_ad_valorem_plus_specific():
    # 30% of customs value + NGN 75.00/l
    d = compute_line_duty("2208.90", 100, 5_000_000_00, date(2026, 8, 1))
    assert d.specific_duty_kobo == 100 * 7500
    assert d.ad_valorem_duty_kobo == 150_000_000
    assert d.total_kobo == 750_000 + 150_000_000


def test_spirits_prior_rate():
    d = compute_line_duty("2208.90", 100, 5_000_000_00, date(2026, 1, 1))
    assert d.specific_duty_kobo == 100 * 6000
    assert d.ad_valorem_duty_kobo == 1_000_000_00  # 20%


def test_sweetened_beverages_flat():
    d = compute_line_duty("2202.10", 10000, 99_000_000, date(2024, 1, 1))
    assert d.specific_duty_kobo == 10000 * 1000  # NGN 10.00/l
    assert d.ad_valorem_duty_kobo == 0


def test_pharmaceuticals_zero_rated_but_stamp_bearing():
    d = compute_line_duty("3004.90", 2000, 5_000_000, date(2026, 1, 1))
    assert d is not None
    assert d.total_kobo == 0
    assert d.tariff.category == "pharmaceuticals"


def test_unmapped_hs_returns_none():
    assert compute_line_duty("8471.30", 1, 100, date(2026, 1, 1)) is None
    assert rate_for("9999", date(2026, 1, 1)) is None


def test_category_mapping():
    assert category_for_hs("2402.20") == "tobacco"
    assert category_for_hs("2203.00") == "alcohol"
    assert category_for_hs("2202.10") == "beverages"
    assert category_for_hs("3004.90") == "pharmaceuticals"
    assert category_for_hs("0101") is None


def test_effective_date_boundary():
    old = rate_for("2203", date(2026, 6, 30))
    new = rate_for("2203", date(2026, 7, 1))
    assert old.specific_kobo == 7200
    assert new.specific_kobo == 8000


def test_ad_valorem_rounding_half_up():
    assert ad_valorem_kobo(101, 3000) == 30  # 30.3 -> 30
    assert ad_valorem_kobo(105, 5000) == 53  # 52.5 -> 53 half-up
    assert ad_valorem_kobo(0, 3000) == 0


def test_negative_inputs_rejected():
    with pytest.raises(ExciseError):
        compute_line_duty("2203", -1, 0, date(2026, 1, 1))
    with pytest.raises(ExciseError):
        compute_line_duty("2203", 1, -5, date(2026, 1, 1))
    with pytest.raises(MoneyError):
        ad_valorem_kobo(-1, 3000)
