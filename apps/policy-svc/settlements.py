"""Frozen local M3/M4 settlement protocol; no change to frozen MS0 contracts."""

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Completion(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    reservation_id: str
    status_code: int = Field(ge=200, le=599)

    @field_validator("reservation_id")
    @classmethod
    def canonical_receipt(cls, value: str) -> str:
        return str(UUID(value))


class SettlementBatch(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    engagement_id: str = Field(pattern=r"^[A-Za-z0-9_-]+$", min_length=1, max_length=255)
    completions: list[Completion] = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def distinct_receipts(self) -> "SettlementBatch":
        if len({item.reservation_id for item in self.completions}) != len(self.completions):
            raise ValueError("duplicate reservation")
        return self


class SettlementAcknowledgement(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    reservation_id: str
    status: Literal["committed", "missing"]


class SettlementResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    engagement_id: str
    completions: list[SettlementAcknowledgement]


class ConflictingCompletion(ValueError):
    """An already committed receipt cannot be assigned another origin status."""
