"""Findings and supporting asset records."""

from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from .events import ActorType


class FindingStatus(StrEnum):
    HYPOTHESIS = "HYPOTHESIS"
    PENDING_VALIDATION = "PENDING_VALIDATION"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    REMEDIATED = "REMEDIATED"


class EdgeKind(StrEnum):
    SECRET_REUSE = "SECRET_REUSE"
    IAM_ASSUME = "IAM_ASSUME"
    NET_REACH = "NET_REACH"
    K8S_RBAC = "K8S_RBAC"


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    engagement_id: str
    title: str
    confidence_score: float = Field(ge=0, le=1, multiple_of=0.01)
    cvss_score: float | None = Field(default=None, ge=0, le=10, multiple_of=0.1)
    status: FindingStatus = FindingStatus.HYPOTHESIS


class AssetNode(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    engagement_id: str
    asset_category: str
    canonical_identifier: str
    metadata: dict[str, JsonValue]
    discovered_by: ActorType


class AssetEdge(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    engagement_id: str
    src_node: UUID
    dst_node: UUID
    edge_kind: EdgeKind
    traversal_cost: float = Field(ge=0, allow_inf_nan=False)
    proven_by_finding: str | None = None


class AttackChain(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    engagement_id: str
    path_node_ids: tuple[UUID, ...] = Field(min_length=1)
