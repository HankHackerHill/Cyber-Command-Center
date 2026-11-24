"""Offline worker schemas and the static assignment matrix.

Artifacts are supplied by the trusted dispatch boundary. Workers interpret these
records and emit only typed observations. No worker receives a tool for reading
files, making requests, dispatching validation, or editing persisted state.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
import json
from types import MappingProxyType
from typing import Annotated, ClassVar, Self

from contracts.events import EngagementState
from pydantic import BaseModel, ConfigDict, Field, JsonValue, StringConstraints, model_validator


class Agent(StrEnum):
    RECON = "recon"
    AUDIT = "audit"
    TRIAGE = "triage"
    GRAPH = "graph"
    REMEDIATION = "remediation"


ArtifactRef = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_-]{0,63}$")]
ObservationCode = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]


class Artifact(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    ref: ArtifactRef
    data: dict[str, JsonValue]

    @model_validator(mode="after")
    def validate_data_size(self) -> Self:
        # Validate UTF-8 and finite JSON before the data enters prompt assembly.
        try:
            encoded = json.dumps(
                self.data, allow_nan=False, ensure_ascii=False, separators=(",", ":"),
            ).encode("utf-8")
        except (ValueError, RecursionError) as exc:
            raise ValueError("artifact data must be finite UTF-8 JSON") from exc
        if len(encoded) > 64 * 1024:
            raise ValueError("artifact data exceeds 64 KiB")
        return self


class ArtifactInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    artifacts: tuple[Artifact, ...] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def unique_refs(self) -> Self:
        if len({artifact.ref for artifact in self.artifacts}) != len(self.artifacts):
            raise ValueError("artifact references must be unique")
        return self


class Observation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    code: ObservationCode
    evidence_ref: ArtifactRef
    confidence_score: float = Field(ge=0, le=1, multiple_of=0.01, allow_inf_nan=False)


class ReviewOutput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    labels: ClassVar[Mapping[str, str]] = MappingProxyType({})
    findings: tuple[Observation, ...] = Field(max_length=32)

    @model_validator(mode="after")
    def validate_findings(self) -> Self:
        seen: set[tuple[str, str]] = set()
        for finding in self.findings:
            key = (finding.evidence_ref, finding.code)
            if finding.code not in self.labels:
                raise ValueError("unsupported observation code for this skill")
            if key in seen:
                raise ValueError("duplicate observation code for an artifact")
            seen.add(key)
        return self


@dataclass(frozen=True)
class SkillSpec:
    name: str
    agent: Agent
    output_model: type[ReviewOutput]
    input_model: type[ArtifactInput] = ArtifactInput

    @property
    def labels(self) -> Mapping[str, str]:
        return self.output_model.labels

    @property
    def input_schema(self) -> str:
        return f"{self.input_model.__module__}:{self.input_model.__name__}"

    @property
    def output_schema(self) -> str:
        return f"{self.output_model.__module__}:{self.output_model.__name__}"

    def validate_evidence(self, supplied: ArtifactInput, output: ReviewOutput) -> None:
        refs = {artifact.ref for artifact in supplied.artifacts}
        if any(finding.evidence_ref not in refs for finding in output.findings):
            raise ValueError("observation references an artifact outside the supplied input")


@dataclass(frozen=True)
class WorkerSpec:
    agent: Agent
    concurrency: int
    input_tokens: int
    phase: EngagementState
    skills: tuple[str, ...]


# The domain modules only declare schemas over the types above.
from . import audit, graph, recon, remediation, triage

SKILLS: Mapping[str, SkillSpec] = MappingProxyType({
    specification.name: specification
    for domain in (recon, audit, triage, graph, remediation)
    for specification in domain.SKILLS
})

WORKERS: Mapping[Agent, WorkerSpec] = MappingProxyType({
    agent: WorkerSpec(
        agent,
        concurrency,
        tokens,
        phase,
        tuple(skill.name for skill in SKILLS.values() if skill.agent == agent),
    )
    for agent, concurrency, tokens, phase in (
        (Agent.RECON, 4, 40_000, EngagementState.DISCOVERY_PASSIVE),
        (Agent.AUDIT, 2, 60_000, EngagementState.ANALYTICAL_TRIAGE),
        (Agent.TRIAGE, 2, 30_000, EngagementState.ANALYTICAL_TRIAGE),
        (Agent.GRAPH, 1, 15_000, EngagementState.ANALYTICAL_TRIAGE),
        (Agent.REMEDIATION, 2, 50_000, EngagementState.REMEDIATION_SYNTHESIS),
    )
})
