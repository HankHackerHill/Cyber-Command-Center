"""Signed engagement transition records."""

import json
from enum import StrEnum

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


class EngagementState(StrEnum):
    INIT_SCOPING = "INIT_SCOPING"
    ROE_LOCKED = "ROE_LOCKED"
    DISCOVERY_PASSIVE = "DISCOVERY_PASSIVE"
    ANALYTICAL_TRIAGE = "ANALYTICAL_TRIAGE"
    AWAITING_HITL_GATE = "AWAITING_HITL_GATE"
    CONTROLLED_VALIDATION = "CONTROLLED_VALIDATION"
    EVIDENCE_VERIFICATION = "EVIDENCE_VERIFICATION"
    REMEDIATION_SYNTHESIS = "REMEDIATION_SYNTHESIS"
    RETEST_VERIFICATION = "RETEST_VERIFICATION"
    COMPLETED_ARCHIVED = "COMPLETED_ARCHIVED"
    HALTED_KILLSWITCH = "HALTED_KILLSWITCH"


class ActorType(StrEnum):
    HUMAN_OPERATOR = "HUMAN_OPERATOR"
    AI_AGENT = "AI_AGENT"
    SYSTEM = "SYSTEM"


class Ed25519Signature(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    signer_id: str = Field(min_length=1)
    signature: str = Field(pattern=r"^[0-9a-f]{128}$")


class TransitionEvent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str = Field(min_length=1)
    engagement_id: str = Field(min_length=1)
    from_state: EngagementState
    to_state: EngagementState
    actor_type: ActorType
    actor_id: str = Field(min_length=1)
    occurred_at: AwareDatetime
    hitl_signature: Ed25519Signature | None = None

    def canonical_envelope(self) -> bytes:
        payload = self.model_dump(mode="json", exclude={"hitl_signature"})
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
