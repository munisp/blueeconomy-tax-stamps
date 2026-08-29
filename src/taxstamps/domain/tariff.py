"""Effective-dated Nigerian excise tariff table with statutory references.

Reference data for the 2026 fiscal-policy excise schedule on imported
excisable goods (PwC Worldwide Tax Summaries; Nigeria Customs Excise Tariff;
Finance Acts). Server-side pricing only: assessment duty is ALWAYS computed
from this table; client-supplied totals are rejected at the API boundary.

Rates:
- cigarettes (HS 2402):        specific NGN/stick  (6.00 -> 8.00 on 2026-07-01)
- beer (HS 2203):              specific NGN/litre  (72.00 -> 80.00 on 2026-07-01)
- spirits (HS 2208):           ad valorem + specific (20%+60.00 -> 30%+75.00 on 2026-07-01)
- sweetened non-alcoholic beverages (HS 2202): NGN 10/litre (Finance Act 2021)

Pharmaceuticals (HS ch. 30) are a stamp *category* for traceability but carry
no federal excise; they are zero-rated here rather than absent so the
assessment records the legal basis explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from taxstamps.domain.money import ad_valorem_kobo

__all__ = [
    "TariffRate",
    "LineDuty",
    "TARIFF_TABLE",
    "rate_for",
    "compute_line_duty",
    "category_for_hs",
    "ExciseError",
]


class ExciseError(ValueError):
    pass


@dataclass(frozen=True)
class TariffRate:
    hs_prefix: str            # HS heading prefix, e.g. "2402"
    category: str             # tobacco | alcohol | pharmaceuticals | beverages
    unit: str                 # STICK | LITRE | UNIT
    specific_kobo: int        # kobo per unit (0 when purely ad valorem)
    ad_valorem_bp: int        # basis points of customs value (0 when purely specific)
    effective_from: date
    effective_to: date | None  # None = open-ended
    statutory_ref: str


@dataclass(frozen=True)
class LineDuty:
    tariff: TariffRate
    specific_duty_kobo: int
    ad_valorem_duty_kobo: int

    @property
    def total_kobo(self) -> int:
        return self.specific_duty_kobo + self.ad_valorem_duty_kobo


TARIFF_TABLE: tuple[TariffRate, ...] = (
    TariffRate(
        hs_prefix="2402", category="tobacco", unit="STICK",
        specific_kobo=600, ad_valorem_bp=0,
        effective_from=date(2023, 6, 1), effective_to=date(2026, 6, 30),
        statutory_ref="Finance Act 2020 s.13; Nigeria Customs Excise Tariff (2023 review)",
    ),
    TariffRate(
        hs_prefix="2402", category="tobacco", unit="STICK",
        specific_kobo=800, ad_valorem_bp=0,
        effective_from=date(2026, 7, 1), effective_to=None,
        statutory_ref="2026 Fiscal Policy Measures: excise on tobacco, NGN 8.00/stick (2026-2028)",
    ),
    TariffRate(
        hs_prefix="2203", category="alcohol", unit="LITRE",
        specific_kobo=7200, ad_valorem_bp=0,
        effective_from=date(2023, 6, 1), effective_to=date(2026, 6, 30),
        statutory_ref="Finance Act 2020 s.13; Nigeria Customs Excise Tariff (2023 review)",
    ),
    TariffRate(
        hs_prefix="2203", category="alcohol", unit="LITRE",
        specific_kobo=8000, ad_valorem_bp=0,
        effective_from=date(2026, 7, 1), effective_to=None,
        statutory_ref="2026 Fiscal Policy Measures: excise on beer, NGN 80.00/litre",
    ),
    TariffRate(
        hs_prefix="2208", category="alcohol", unit="LITRE",
        specific_kobo=6000, ad_valorem_bp=2000,
        effective_from=date(2023, 6, 1), effective_to=date(2026, 6, 30),
        statutory_ref="Finance Act 2020 s.13; Nigeria Customs Excise Tariff (2023 review)",
    ),
    TariffRate(
        hs_prefix="2208", category="alcohol", unit="LITRE",
        specific_kobo=7500, ad_valorem_bp=3000,
        effective_from=date(2026, 7, 1), effective_to=None,
        statutory_ref="2026 Fiscal Policy Measures: excise on spirits, 30% ad valorem + NGN 75.00/litre",
    ),
    TariffRate(
        hs_prefix="2202", category="beverages", unit="LITRE",
        specific_kobo=1000, ad_valorem_bp=0,
        effective_from=date(2022, 6, 1), effective_to=None,
        statutory_ref="Finance Act 2021 s.17: NGN 10/litre on non-alcoholic, carbonated and sweetened beverages",
    ),
    TariffRate(
        hs_prefix="30", category="pharmaceuticals", unit="UNIT",
        specific_kobo=0, ad_valorem_bp=0,
        effective_from=date(2020, 1, 1), effective_to=None,
        statutory_ref="Zero-rated: pharmaceutical products carry no federal excise (stamp traceability only)",
    ),
)

_HS_CATEGORY = {
    "24": "tobacco",
    "22": "alcohol",  # refined by heading below
    "30": "pharmaceuticals",
}
_HEADING_CATEGORY = {
    "2202": "beverages",
    "2203": "alcohol",
    "2208": "alcohol",
    "2402": "tobacco",
}


def category_for_hs(hs_code: str) -> str | None:
    """Map an HS code to a stamp category, or None when not stamp-bearing."""
    hs = "".join(ch for ch in hs_code if ch.isdigit())
    heading = hs[:4]
    if heading in _HEADING_CATEGORY:
        return _HEADING_CATEGORY[heading]
    return _HS_CATEGORY.get(hs[:2])


def rate_for(hs_code: str, on: date) -> TariffRate | None:
    """Effective-dated lookup. Returns None when the HS code is not covered."""
    hs = "".join(ch for ch in hs_code if ch.isdigit())
    candidates = [
        r for r in TARIFF_TABLE
        if hs.startswith(r.hs_prefix)
        and r.effective_from <= on
        and (r.effective_to is None or on <= r.effective_to)
    ]
    if not candidates:
        return None
    # Longest prefix wins (e.g. "2202" before "22").
    candidates.sort(key=lambda r: len(r.hs_prefix), reverse=True)
    return candidates[0]


def compute_line_duty(
    hs_code: str,
    quantity: int,
    customs_value_kobo: int,
    on: date,
) -> LineDuty | None:
    """Duty for one declaration line item. Integer kobo only.

    ``quantity`` is expressed in the tariff unit (sticks / litres / units).
    Returns None when the line is not stamp-bearing.
    """
    if quantity < 0:
        raise ExciseError("quantity cannot be negative")
    if customs_value_kobo < 0:
        raise ExciseError("customs value cannot be negative")
    rate = rate_for(hs_code, on)
    if rate is None:
        return None
    specific = rate.specific_kobo * quantity
    ad_valorem = ad_valorem_kobo(customs_value_kobo, rate.ad_valorem_bp)
    return LineDuty(tariff=rate, specific_duty_kobo=specific, ad_valorem_duty_kobo=ad_valorem)
