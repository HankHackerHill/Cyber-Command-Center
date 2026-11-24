"""Validation plan and human approval records."""

from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .events import Ed25519Signature


class BlastRadius(StrEnum):
    READ_ONLY = "READ_ONLY"
    REVERSIBLE = "REVERSIBLE"
    DESTRUCTIVE = "DESTRUCTIVE"


class ValidationPlan(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(min_length=1)
    engagement_id: str = Field(min_length=1)
    blast_radius: BlastRadius
    approver_sig: Ed25519Signature | None = None
    second_approver_sig: Ed25519Signature | None = None

    @model_validator(mode="after")
    def require_dual_approval(self) -> Self:
        if self.blast_radius == BlastRadius.DESTRUCTIVE:
            first, second = self.approver_sig, self.second_approver_sig
            if first is None or second is None:
                raise ValueError("destructive plans require two approvals")
            if first.signer_id == second.signer_id or first.signature == second.signature:
                raise ValueError("destructive plans require distinct approvers and signatures")
        return self
