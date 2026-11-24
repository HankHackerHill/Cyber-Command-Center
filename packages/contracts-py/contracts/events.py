"""Signed engagement transitions and non-transition audit records."""

import json
import math
from decimal import Decimal
from enum import StrEnum
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, JsonValue, field_validator


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


def _audit_text(text: str) -> str:
    # PostgreSQL JSONB cannot store U+0000 or unpaired UTF-16 surrogates.
    if "\x00" in text:
        raise ValueError("audit text contains a null character")
    text.encode("utf-8")
    return text


def _audit_object(value: object) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ValueError("expected a JSON object")
    result: dict[str, JsonValue] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ValueError("JSON object keys must be strings")
        result[_audit_text(key)] = _audit_value(item)
    return result


def _audit_value(value: object) -> JsonValue:
    if isinstance(value, dict):
        return _audit_object(value)
    if isinstance(value, list):
        return [_audit_value(item) for item in value]
    if isinstance(value, str):
        return _audit_text(value)
    if value is None:
        return None
    if isinstance(value, int):
        # Ensure the canonical Python JSON encoder can write the integer.
        str(value)
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("expected a finite JSON number")
        # JSONB expands exponents and removes the sign of zero. Canonicalize
        # integral numbers before hashing, including when they arrive as floats.
        return int(Decimal(str(value))) if value.is_integer() else value
    raise ValueError("expected a JSON value")


class AuditEvent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    actor_kind: ActorType
    actor_id: str = Field(strict=True, min_length=1)
    event_type: str = Field(strict=True, min_length=1)
    payload: dict[str, JsonValue]

    @field_validator("actor_id", "event_type")
    @classmethod
    def valid_text(cls, value: str) -> str:
        return _audit_text(value)

    @field_validator("payload", mode="before")
    @classmethod
    def valid_payload(cls, value: object) -> dict[str, JsonValue]:
        try:
            return _audit_object(value)
        except RecursionError as exc:
            raise ValueError("audit payload nesting exceeds the supported depth") from exc


class RecordedAuditEvent(AuditEvent):
    event_id: UUID
    engagement_id: UUID
    occurred_at: AwareDatetime


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
