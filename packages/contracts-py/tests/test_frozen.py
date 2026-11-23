import json
from collections.abc import Iterator
from importlib import import_module
from inspect import isclass
from pathlib import Path
from pkgutil import iter_modules

import pytest
from pydantic import BaseModel, ValidationError

import contracts
from contracts.events import Ed25519Signature, TransitionEvent
from contracts.findings import AssetEdge, AssetNode, AttackChain, Finding, FindingStatus
from contracts.ledger import LedgerRecord
from contracts.plans import ValidationPlan
from contracts.roe import Engagement, RoeManifest
from contracts.tasks import WorkflowTask

FIXTURES = Path(__file__).resolve().parents[3] / "tests" / "fixtures"


def examples() -> Iterator[BaseModel]:
    manifest = RoeManifest.model_validate_json((FIXTURES / "roe_sample.json").read_bytes())
    engagement = Engagement(id=manifest.engagement_id, roe_manifest=manifest)
    yield from (engagement, manifest, manifest.valid_window, manifest.scope_boundaries,
                manifest.traffic_constraints, manifest.signatures)

    sig = Ed25519Signature(signer_id="sample", signature="00" * 64)
    yield sig
    event = TransitionEvent.model_validate({
        "event_id": "evt-1", "engagement_id": engagement.id, "from_state": "INIT_SCOPING",
        "to_state": "ROE_LOCKED", "actor_id": sig.signer_id, "actor_type": "HUMAN_OPERATOR",
        "occurred_at": "2026-12-01T10:00:00Z", "hitl_signature": sig,
    })
    yield event
    yield LedgerRecord(seq_id=1, event=event, prev_record_hash="0" * 64, record_hash="1" * 64)
    yield ValidationPlan.model_validate({
        "id": "plan-1", "engagement_id": engagement.id, "blast_radius": "READ_ONLY",
    })
    yield WorkflowTask.model_validate({
        "id": "task-1", "engagement_id": engagement.id, "mode": "MANUAL",
    })
    yield Finding(id="fnd-0001", engagement_id=engagement.id, title="Sample", confidence_score=0.5)

    graph = json.loads((FIXTURES / "graph_known.json").read_bytes())
    for node in graph["nodes"]:
        yield AssetNode.model_validate(dict(node, engagement_id=engagement.id))
    for edge in graph["edges"]:
        yield AssetEdge.model_validate(dict(edge, engagement_id=engagement.id))
    yield AttackChain.model_validate({
        "id": "chain-1", "engagement_id": engagement.id,
        "path_node_ids": graph["expected"]["shortest_path_entry_to_tier0"]["path_node_ids"],
    })


def test_examples_cover_all_contract_models() -> None:
    models: set[type[BaseModel]] = set()
    for module_info in iter_modules(contracts.__path__, "contracts."):
        module = import_module(module_info.name)
        models.update(value for value in vars(module).values()
                      if isclass(value) and issubclass(value, BaseModel)
                      and value.__module__ == module.__name__)
    assert {type(example) for example in examples()} == models


@pytest.mark.parametrize("model", list(examples()), ids=lambda model: type(model).__name__)
def test_frozen_and_forbid(model: BaseModel) -> None:
    cls = type(model)
    field = next(iter(cls.model_fields))
    with pytest.raises(ValidationError) as frozen:
        setattr(model, field, getattr(model, field))
    assert frozen.value.errors()[0]["type"] == "frozen_instance"
    with pytest.raises(ValidationError) as extra:
        cls.model_validate(dict(model.model_dump(), unexpected="value"))
    assert extra.value.errors()[0]["type"] == "extra_forbidden"


@pytest.mark.parametrize("score", [-0.01, 1.01])
def test_confidence_bounds(score: float) -> None:
    with pytest.raises(ValidationError):
        Finding(id="f", engagement_id="eng", title="Sample", confidence_score=score)


@pytest.mark.parametrize("score", [0.0, 1.0])
def test_finding_defaults_to_hypothesis(score: float) -> None:
    finding = Finding(id="f", engagement_id="eng", title="Sample", confidence_score=score)
    assert finding.status == FindingStatus.HYPOTHESIS
