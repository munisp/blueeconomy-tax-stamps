"""ANSI/ASQ Z1.4-style acceptance sampling for tax stamp print-run QA.

Clean-room tabulation of the well-known single-sampling, normal-inspection,
General Inspection Level II plan at AQL 0.65% (the platform-mandated AQL for
stamp lots). The table below reproduces the widely published MIL-STD-105E /
ANSI/ASQ Z1.4 Table I (code letters) and Table II-A (accept/reject numbers
at AQL 0.65) values; those standards are factual tabulations, re-entered here
from the public specification.

Down-arrow semantics (standard rule): where the table shows an arrow for a
code letter at the chosen AQL, use the first sampling plan below the arrow
(here: letter E, n=13, Ac=0, Re=1). If that sample size equals or exceeds the
lot size, perform 100% inspection with that plan's Ac/Re.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["SamplingPlan", "SamplingError", "plan_for_lot", "evaluate_sample"]

AQL_PERCENT = 0.65


class SamplingError(ValueError):
    pass


@dataclass(frozen=True)
class SamplingPlan:
    lot_size: int
    code_letter: str
    sample_size: int
    accept: int  # Ac: maximum defectives for lot acceptance
    reject: int  # Re: minimum defectives for lot rejection
    hundred_percent: bool  # True when plan sample size >= lot size


# Table I (General inspection level II): (lot_low, lot_high) -> code letter.
_CODE_LETTERS: list[tuple[int, int, str]] = [
    (2, 8, "A"),
    (9, 15, "B"),
    (16, 25, "C"),
    (26, 50, "D"),
    (51, 90, "E"),
    (91, 150, "F"),
    (151, 280, "G"),
    (281, 500, "H"),
    (501, 1200, "J"),
    (1201, 3200, "K"),
    (3201, 10000, "L"),
    (10001, 35000, "M"),
    (35001, 150000, "N"),
    (150001, 500000, "P"),
    (500001, 10**15, "Q"),
]

_SAMPLE_SIZES: dict[str, int] = {
    "A": 2, "B": 3, "C": 5, "D": 8, "E": 13, "F": 20, "G": 32, "H": 50,
    "J": 80, "K": 125, "L": 200, "M": 315, "N": 500, "P": 800, "Q": 1250,
    "R": 2000,
}

# Table II-A, AQL 0.65 column: code letter -> (Ac, Re). Letters A-D carry the
# down arrow at this AQL; the arrow resolves to the first plan below it,
# which is letter E (n=13, Ac 0, Re 1).
_PLANS_AQL_0_65: dict[str, tuple[int, int]] = {
    "E": (0, 1),
    "F": (0, 1),
    "G": (0, 1),
    "H": (1, 2),
    "J": (1, 2),
    "K": (2, 3),
    "L": (3, 4),
    "M": (5, 6),
    "N": (7, 8),
    "P": (10, 11),
    "Q": (14, 15),
    "R": (21, 22),
}

_ARROW_TARGET = "E"  # first sampling plan below the arrow at AQL 0.65


def _code_letter_for(lot_size: int) -> str:
    for low, high, letter in _CODE_LETTERS:
        if low <= lot_size <= high:
            return letter
    raise SamplingError(f"lot size {lot_size} out of tabulated range")  # pragma: no cover


def plan_for_lot(lot_size: int) -> SamplingPlan:
    """Return the single-sampling normal GIL-II plan at AQL 0.65% for a lot."""
    if not isinstance(lot_size, int) or lot_size < 1:
        raise SamplingError("lot size must be a positive integer")
    if lot_size == 1:
        # Single-unit lot: 100% inspection, zero defectives tolerated.
        return SamplingPlan(lot_size=1, code_letter="A", sample_size=1,
                            accept=0, reject=1, hundred_percent=True)
    letter = _code_letter_for(lot_size)
    plan_letter = letter if letter in _PLANS_AQL_0_65 else _ARROW_TARGET
    accept, reject = _PLANS_AQL_0_65[plan_letter]
    sample_size = _SAMPLE_SIZES[plan_letter]
    hundred = sample_size >= lot_size
    if hundred:
        sample_size = lot_size
    return SamplingPlan(
        lot_size=lot_size,
        code_letter=letter,
        sample_size=sample_size,
        accept=accept,
        reject=reject,
        hundred_percent=hundred,
    )


def evaluate_sample(plan: SamplingPlan, defectives: int) -> bool:
    """Return True when the lot is ACCEPTED given ``defectives`` in the sample."""
    if not isinstance(defectives, int) or defectives < 0:
        raise SamplingError("defectives must be a non-negative integer")
    if defectives > plan.sample_size:
        raise SamplingError("defectives cannot exceed sample size")
    return defectives <= plan.accept
