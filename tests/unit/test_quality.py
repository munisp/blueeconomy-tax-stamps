"""ANSI/ASQ Z1.4 GIL-II AQL 0.65% sampling table conformance."""

import pytest

from taxstamps.domain.quality import SamplingError, evaluate_sample, plan_for_lot


@pytest.mark.parametrize(
    "lot,letter,n,ac,re",
    [
        (2, "A", 2, 0, 1),        # arrow -> E plan; n >= lot -> 100% inspection
        (8, "A", 8, 0, 1),
        (15, "B", 13, 0, 1),
        (25, "C", 13, 0, 1),
        (50, "D", 13, 0, 1),
        (90, "E", 13, 0, 1),
        (150, "F", 20, 0, 1),
        (280, "G", 32, 0, 1),
        (500, "H", 50, 1, 2),
        (1200, "J", 80, 1, 2),
        (3200, "K", 125, 2, 3),
        (10000, "L", 200, 3, 4),
        (35000, "M", 315, 5, 6),
        (150000, "N", 500, 7, 8),
        (500000, "P", 800, 10, 11),
        (500001, "Q", 1250, 14, 15),
    ],
)
def test_table_values(lot, letter, n, ac, re):
    plan = plan_for_lot(lot)
    assert plan.code_letter == letter
    assert plan.sample_size == n
    assert plan.accept == ac
    assert plan.reject == re


def test_hundred_percent_flag():
    assert plan_for_lot(5).hundred_percent is True
    assert plan_for_lot(2).hundred_percent is True
    assert plan_for_lot(5000).hundred_percent is False


def test_accept_reject_boundary():
    plan = plan_for_lot(5000)  # Ac 3 Re 4
    assert evaluate_sample(plan, 3) is True
    assert evaluate_sample(plan, 4) is False
    plan = plan_for_lot(150)  # Ac 0 Re 1
    assert evaluate_sample(plan, 0) is True
    assert evaluate_sample(plan, 1) is False


def test_single_unit_lot_is_full_inspection():
    plan = plan_for_lot(1)
    assert plan.sample_size == 1 and plan.accept == 0 and plan.hundred_percent


def test_invalid_inputs():
    with pytest.raises(SamplingError):
        plan_for_lot(0)
    with pytest.raises(SamplingError):
        evaluate_sample(plan_for_lot(100), -1)
    with pytest.raises(SamplingError):
        evaluate_sample(plan_for_lot(100), 10**9)
