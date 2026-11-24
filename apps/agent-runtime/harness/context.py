"""Load the versioned skill catalog and assemble canonical, bounded context."""

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Annotated

from contracts.findings import AssetNode, Finding
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from workers import SKILLS, Agent, ArtifactInput


class SkillBudget(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    input_tokens: int = Field(default=50_000, gt=0, le=1_000_000)
    output_tokens: int = Field(default=8_000, gt=0, le=1_000_000)


class SkillMetadata(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    name: str
    version: Annotated[str, StringConstraints(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")]
    agent: Agent
    input_schema: str
    output_schema: str
    token_budget: SkillBudget = SkillBudget()
    fixtures: tuple[str, ...] = Field(min_length=1, max_length=32)


@dataclass(frozen=True)
class Skill:
    name: str
    version: str
    agent: Agent
    prompt: str
    token_budget: SkillBudget
    fixtures: tuple[Path, ...]


@dataclass(frozen=True)
class HistoricalFinding:
    finding: Finding
    observed_at: datetime | None = None


class ContextBudgetExceeded(ValueError):
    """The mandatory task input cannot fit the context byte budget."""


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def read_json_file(path: Path, max_bytes: int) -> str:
    """Read the JSON subset of YAML with duplicate keys and NaN rejected."""
    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate object key")
            result[key] = value
        return result

    def invalid_constant(_: str) -> object:
        raise ValueError("nonfinite JSON value")

    with path.open("rb") as stream:
        data = stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("JSON file exceeds its byte limit")
    text = data.decode("utf-8")
    json.loads(text, object_pairs_hook=object_pairs, parse_constant=invalid_constant)
    return text


def load_registry(root: Path | None = None) -> Mapping[str, Skill]:
    directory = root if root is not None else Path(__file__).resolve().parents[1] / "skills"
    found = {path.name for path in directory.iterdir() if path.is_dir()}
    if found != set(SKILLS):
        raise ValueError("skill directories do not match the worker registry")
    registry: dict[str, Skill] = {}
    for name, specification in sorted(SKILLS.items()):
        skill_dir = directory / name
        metadata = SkillMetadata.model_validate_json(read_json_file(skill_dir / "skill.yaml", 16_384))
        if (metadata.name, metadata.agent, metadata.input_schema, metadata.output_schema) != (
            name, specification.agent, specification.input_schema, specification.output_schema,
        ):
            raise ValueError(f"skill metadata does not match the worker registry for {name}")
        with (skill_dir / "prompt.md").open("rb") as stream:
            prompt = stream.read(32_769).decode("utf-8")
        if not prompt.strip() or len(prompt.encode("utf-8")) > 32_768:
            raise ValueError(f"invalid prompt for {name}")
        fixtures: list[Path] = []
        for fixture in metadata.fixtures:
            relative = Path(fixture)
            path = skill_dir / relative
            if (len(relative.parts) != 2 or relative.parts[0] != "examples"
                    or path.suffix != ".json" or not path.is_file()
                    or path.resolve().parent != (skill_dir / "examples").resolve() or path in fixtures):
                raise ValueError(f"invalid fixture reference for {name}")
            fixtures.append(path)
        registry[name] = Skill(name, metadata.version, metadata.agent, prompt, metadata.token_budget, tuple(fixtures))
    return MappingProxyType(registry)


def _utc_microseconds(value: datetime | None) -> int:
    if value is None or value.utcoffset() is None:
        return -1
    normalized = value.astimezone(timezone.utc)
    return ((normalized.toordinal() * 24 + normalized.hour) * 3600
            + normalized.minute * 60 + normalized.second) * 1_000_000 + normalized.microsecond


def _node_recency(node: AssetNode) -> int:
    value = node.metadata.get("observed_at")
    if isinstance(value, str):
        try:
            return _utc_microseconds(datetime.fromisoformat(value))
        except (ValueError, OverflowError):
            pass
    return -1


def _node_confidence(node: AssetNode) -> float:
    value = node.metadata.get("confidence_score")
    if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= 1:
        return float(value)
    return 0.0


def assemble_context(
    skill: Skill, task_input: ArtifactInput, *, assets: Iterable[AssetNode] = (),
    findings: Iterable[HistoricalFinding] = (), byte_budget: int = 65_536, top_k: int = 20,
) -> str:
    """Keep task input and append the highest ranked evidence prefix that fits.

    Rank confidence first, followed by UTC recency, collection, and stable ID.
    Missing recency sorts last. Once an item exceeds the budget, its entire
    lower-priority suffix is removed. Historical candidates are limited to top_k.
    """
    if byte_budget <= 0 or top_k < 0:
        raise ValueError("invalid context limits")
    collections: dict[str, list[object]] = {"asset_nodes": [], "historical_findings": []}
    body = {"skill": skill.name, "version": skill.version, "task_input": task_input.model_dump(mode="json"),
            **collections}
    base = canonical_json(body)
    if len(base.encode("utf-8")) > byte_budget:
        raise ContextBudgetExceeded("required task input exceeds context budget")
    ranked_findings = sorted(findings, key=lambda item: (
        -item.finding.confidence_score, -_utc_microseconds(item.observed_at), item.finding.id,
    ))[:top_k]
    candidates = [(-_node_confidence(node), -_node_recency(node), "asset_nodes", str(node.id),
                   node.model_dump(mode="json")) for node in assets]
    for item in ranked_findings:
        candidates.append((-item.finding.confidence_score, -_utc_microseconds(item.observed_at),
                           "historical_findings", item.finding.id, item.finding.model_dump(mode="json")))
    remaining = byte_budget - len(base.encode("utf-8"))
    for _, _, collection, _, value in sorted(candidates, key=lambda item: item[:4] + (canonical_json(item[4]),)):
        members = collections[collection]
        cost = len(canonical_json(value).encode("utf-8")) + int(bool(members))
        if cost > remaining:
            break
        members.append(value)
        remaining -= cost
    return canonical_json(body)
