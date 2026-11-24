"""Deterministic evidence pruning and actual per-domain scheduling bounds."""

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
from threading import Event, Lock
from uuid import UUID

from contracts.events import ActorType
from contracts.findings import AssetNode, Finding
from contracts.plans import BlastRadius
from contracts.tasks import TaskMode, TaskStatus
import pytest

from harness.context import ContextBudgetExceeded, HistoricalFinding, assemble_context, load_registry
from harness.runner import LocalBackend, Runner
from supervisor import Dispatch, Outcome, PostgresStore, QueueEntry, Supervisor, hitl_rail
from workers import SKILLS, WORKERS, Agent


ENGAGEMENT = UUID(int=1)
NOW = datetime(2025, 1, 2, tzinfo=timezone.utc)


def node(identifier: int, score: float, when: datetime) -> AssetNode:
    return AssetNode(id=UUID(int=identifier), engagement_id=str(ENGAGEMENT), asset_category="fixture",
                     canonical_identifier="synthetic-β", metadata={"confidence_score": score,
                     "observed_at": when.isoformat()}, discovered_by=ActorType.SYSTEM)


def observed(identifier: str, score: float, when: datetime) -> HistoricalFinding:
    return HistoricalFinding(Finding(id=identifier, engagement_id=str(ENGAGEMENT),
                                     title=f"Synthetic finding {identifier}", confidence_score=score), when)


def test_context_bytes_rank_by_confidence_then_recency_then_id() -> None:
    skill = load_registry()["scanner_dedupe"]
    inputs = SKILLS[skill.name].input_model
    original = inputs.model_validate_json('{"artifacts":[{"ref":"one","data":{"a":"café","b":true}}]}')
    reordered = inputs.model_validate_json('{"artifacts":[{"data":{"b":true,"a":"café"},"ref":"one"}]}')
    assets = [node(6, 0.2, NOW), node(2, 0.9, NOW)]
    findings = [observed("high-old", 0.95, NOW - timedelta(days=5)), observed("other", 0.9, NOW),
                observed("later", 0.9, NOW), observed("older", 0.9, NOW - timedelta(hours=1))]
    ranked = assemble_context(skill, original, assets=assets, findings=findings, top_k=3)
    assert ranked == assemble_context(skill, reordered, assets=reversed(assets), findings=reversed(findings), top_k=3)
    assert [item["id"] for item in json.loads(ranked)["historical_findings"]] == ["high-old", "later", "other"]
    expected = assemble_context(skill, original, assets=assets[1:], findings=findings[:1])
    assert assemble_context(skill, reordered, assets=assets, findings=findings,
                            byte_budget=len(expected.encode("utf-8"))) == expected
    base = assemble_context(skill, original)
    assert len(base.encode("utf-8")) > len(base)
    with pytest.raises(ContextBudgetExceeded):
        assemble_context(skill, original, byte_budget=len(base.encode("utf-8")) - 1)


def dispatch(task_id: str, skill: str, *, confidence: float = 0.5, criticality: float = 1,
             radius: BlastRadius = BlastRadius.READ_ONLY, mode: TaskMode = TaskMode.AI_AUTONOMOUS_PASSIVE) -> Dispatch:
    return Dispatch(engagement_id=ENGAGEMENT, task_id=task_id, skill=skill, mode=mode, confidence=confidence,
                    asset_criticality=criticality, blast_radius=radius, input={})


def test_enqueue_priority_and_destructive_rail_override() -> None:
    gated = TaskMode.AI_PROPOSED_HITL_GATED
    low = dispatch("low", "compliance_map", confidence=0.1, criticality=0.2, radius=BlastRadius.DESTRUCTIVE)
    high = dispatch("high", "scanner_dedupe", confidence=0.8, criticality=0.75, mode=gated)
    entries = tuple(QueueEntry.from_dispatch(task) for task in (high, low))
    assert [entry.priority for entry in entries] == [Decimal("0.6"), Decimal("0.06")]
    assert [entry.dispatch.task_id for entry in hitl_rail(entries)] == ["low", "high"]
    rescored = high.model_copy(update={"confidence": 0.2})
    assert QueueEntry.from_dispatch(rescored).priority == Decimal("0.15")


def test_routing_and_caps_are_applied_to_running_tasks(monkeypatch: pytest.MonkeyPatch) -> None:
    supervisor = Supervisor(PostgresStore("unused"), Runner(LocalBackend("test:generate", "test:tokenize")))
    entries = [dispatch(f"{agent.value}-{i}", spec.skills[i % len(spec.skills)], confidence=1.0 - i / 20)
               for agent, spec in WORKERS.items() for i in range(spec.concurrency + 1)]
    active: Counter[Agent] = Counter()
    peak: Counter[Agent] = Counter()
    completed: Counter[Agent] = Counter()
    lock = Lock()
    opened = Event()
    release = Event()

    def run(task: Dispatch) -> Outcome:
        agent = SKILLS[task.skill].agent
        assert task.task_id.startswith(f"{agent.value}-")
        with lock:
            active[agent] += 1
            peak[agent] = max(active[agent], peak[agent])
            if sum(active.values()) == sum(spec.concurrency for spec in WORKERS.values()):
                opened.set()
        assert release.wait(10)
        with lock:
            active[agent] -= 1
            completed[agent] += 1
        return Outcome(task.engagement_id, task.task_id, TaskStatus.DONE)

    monkeypatch.setattr(supervisor, "run_one", run)
    with ThreadPoolExecutor(max_workers=1) as pool:
        batch = pool.submit(supervisor.run_pending, tuple(reversed(entries)))
        try:
            assert opened.wait(10)
            with lock:
                assert dict(active) == {agent: spec.concurrency for agent, spec in WORKERS.items()}
                assert not completed
        finally:
            release.set()
        result = batch.result(timeout=10)
    assert dict(peak) == {agent: spec.concurrency for agent, spec in WORKERS.items()}
    assert len(result) == len(entries)
    assert [item.task_id for item in result] == [entry.task_id for entry in sorted(
        entries, key=lambda task: (-QueueEntry.from_dispatch(task).priority, task.task_id),
    )]
