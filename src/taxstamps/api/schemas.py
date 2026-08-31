"""Request/response schemas. Client-supplied totals are REJECTED: pricing is
computed server-side from the tariff table only."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class DeclarationLineIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hs_code: str = Field(min_length=2, max_length=16)
    description: str = ""
    quantity: int = Field(ge=0)
    unit: Literal["STICK", "LITRE", "UNIT"]
    customs_value_kobo: int = Field(ge=0)
    stamps_required: int = Field(ge=0)


class DeclarationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    declaration_ref: str = Field(min_length=3, max_length=64)
    consignee_tin: str = Field(min_length=6, max_length=32)
    consignee_name: str = ""
    lines: list[DeclarationLineIn] = Field(min_length=1)

    @model_validator(mode="after")
    def _no_client_totals(self) -> DeclarationIn:
        # extra="forbid" already rejects unexpected fields; this guard makes
        # the intent explicit for any field name smuggling totals.
        return self


class AssessmentCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    declaration_ref: str = Field(min_length=3, max_length=64)


class DecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["APPROVE", "REJECT"]
    reason: str = ""


class CancelIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=3, max_length=512)


class ReceiptIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    payment_intent_id: str
    external_reference: str = Field(min_length=4, max_length=128)
    amount_kobo: int = Field(ge=0)
    currency: str = Field(min_length=3, max_length=3)


class QuarantineResolutionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resolution: Literal["SETTLE", "FAIL"]
    external_reference: str = Field(min_length=4, max_length=128)  # new superseding receipt ref
    supersedes_reference: str = Field(min_length=4, max_length=128)  # the QUARANTINED receipt
    amount_kobo: int = Field(ge=0)
    currency: str = Field(min_length=3, max_length=3)
    reason: str = Field(min_length=3, max_length=512)


class InspectionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    defectives: int = Field(ge=0)


class IssueIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    chunk_size: int | None = Field(default=None, ge=1, le=10000)
    run_to_completion: bool = False


class VoidIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=3)


class VerifyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    serial: str = Field(min_length=1, max_length=64)
    nonce: str = Field(min_length=8, max_length=128)
    lat_micros: int | None = Field(default=None, ge=-90_000_000, le=90_000_000)
    long_micros: int | None = Field(default=None, ge=-180_000_000, le=180_000_000)


class PublicVerifyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    serial: str | None = Field(default=None, max_length=64)
    credential: dict[str, Any] | None = None
    lat_micros: int | None = Field(default=None, ge=-90_000_000, le=90_000_000)
    long_micros: int | None = Field(default=None, ge=-180_000_000, le=180_000_000)

    @model_validator(mode="after")
    def _serial_or_credential(self) -> PublicVerifyIn:
        if not self.serial and not self.credential:
            raise ValueError("serial or credential is required")
        return self


class Problem(BaseModel):
    type: str
    title: str
    status: int
    detail: str = ""
