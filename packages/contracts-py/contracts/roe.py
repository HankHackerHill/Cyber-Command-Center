"""Versioned rules of engagement and their owning engagement."""

from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Network, IPv6Network
from typing import Annotated, Literal, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from .events import EngagementState


class AssessmentType(StrEnum):
    WEB_API = "WEB_API"
    CLOUD_CONFIG = "CLOUD_CONFIG"


class ExecutionMode(StrEnum):
    MANUAL = "MANUAL"
    AUTONOMOUS_PASSIVE = "AUTONOMOUS_PASSIVE"
    HYBRID = "HYBRID"


Sha256Hex = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Weekday = Literal["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"]


class ValidWindow(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    not_before: Annotated[datetime, AwareDatetime]
    not_after: Annotated[datetime, AwareDatetime]
    allowed_days_utc: tuple[Weekday, ...]

    @model_validator(mode="after")
    def check_order(self) -> Self:
        if self.not_before >= self.not_after:
            raise ValueError("not_after must be later than not_before")
        return self


class ScopeBoundaries(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    allowed_cidrs: tuple[IPv4Network | IPv6Network, ...]
    allowed_identifiers: tuple[str, ...]
    excluded_paths: tuple[str, ...]
    allowed_http_methods: tuple[str, ...]


class TrafficConstraints(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    max_requests_per_second: int = Field(ge=0)
    max_concurrent_workers: int = Field(ge=0)
    required_attribution_header: str
    circuit_breaker_5xx_threshold: int = Field(gt=0)


class RoeSignatures(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    lead_operator_sig: str = Field(pattern=r"^ed25519:[0-9a-f]{128}$")
    policy_hash_sha256: Sha256Hex


class RoeManifest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    manifest_urn: Literal["urn:secops:roe:v1"]
    engagement_id: str = Field(min_length=1)
    assessment_types: tuple[AssessmentType, ...] = Field(min_length=1)
    execution_mode: ExecutionMode
    valid_window: ValidWindow
    scope_boundaries: ScopeBoundaries
    traffic_constraints: TrafficConstraints
    signatures: RoeSignatures


class Engagement(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(min_length=1)
    current_state: EngagementState = EngagementState.INIT_SCOPING
    roe_manifest: RoeManifest | None = None
    roe_signature_hash: Sha256Hex | None = None

    @model_validator(mode="after")
    def check_manifest_owner(self) -> Self:
        if self.roe_manifest is not None and self.roe_manifest.engagement_id != self.id:
            raise ValueError("RoE manifest belongs to another engagement")
        return self
