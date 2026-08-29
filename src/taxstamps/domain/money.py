"""Exact-money semantics. All amounts are integer kobo (1 NGN = 100 kobo).

Floating-point money is prohibited anywhere in the service. Ad-valorem
computations use basis points (1 bp = 0.01%) with half-up rounding to kobo,
performed in integers only.
"""

from __future__ import annotations

__all__ = ["Currency", "MoneyError", "ad_valorem_kobo", "require_ngn", "NGN"]

NGN = "NGN"


class MoneyError(ValueError):
    pass


class Currency(str):
    pass


def require_ngn(currency: str) -> str:
    if currency != NGN:
        raise MoneyError(f"unsupported currency {currency!r}: excise is assessed in NGN")
    return NGN


def ad_valorem_kobo(customs_value_kobo: int, rate_basis_points: int) -> int:
    """Ad-valorem duty in kobo with half-up rounding, integer arithmetic only."""
    if customs_value_kobo < 0:
        raise MoneyError("customs value cannot be negative")
    if rate_basis_points < 0:
        raise MoneyError("rate cannot be negative")
    numerator = customs_value_kobo * rate_basis_points
    # half-up: (numerator + denominator//2) // denominator
    return (numerator + 5000) // 10000
