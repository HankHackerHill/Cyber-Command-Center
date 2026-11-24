"""Run a bounded batch of offline task reviews.

The operator supplies a private JSON array of Dispatch records. Frozen workflow
rows supply engagement, mode, and status; the catalog supplies skill inputs,
priority inputs, and the operator's explicit decision to dispatch a gated review.
Use --enqueue to create absent rows without changing existing ones. Deploy with
an operator-installed offline model adapter and a dedicated PostgreSQL role:
SELECT on the tables read here, INSERT on workflow_tasks/findings/validation_plans,
and UPDATE (status) on workflow_tasks. Keep credentials in DATABASE_URL, outside
of task inputs. The operator must authenticate dispatch before writing the catalog.
"""

import argparse
import hashlib
import logging
import os
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import asdict, dataclass
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Literal, Self
from uuid import UUID

import psycopg
from contracts.events import EngagementState
from contracts.findings import AssetNode, Finding, FindingStatus
from contracts.plans import BlastRadius, ValidationPlan
from contracts.tasks import TaskMode, TaskStatus, WorkflowTask
from prometheus_client import write_to_textfile
from psycopg import Connection
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, JsonValue, StringConstraints, TypeAdapter, model_validator

from harness.context import ContextBudgetExceeded, HistoricalFinding, Skill, assemble_context, canonical_json, load_registry, read_json_file
from harness.fallback import MODEL_CHAINS
from harness.metrics import RunMetrics
from harness.runner import LocalBackend, Runner, TokenBudget
from workers import SKILLS, WORKERS, Agent, WorkerSpec


LOGGER = logging.getLogger("redops.agent_runtime")
TaskId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")]
Score = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
BLAST_WEIGHT = {BlastRadius.READ_ONLY: 1, BlastRadius.REVERSIBLE: 2, BlastRadius.DESTRUCTIVE: 3}
_SLOT_NAMESPACE = 540_005
_MAX_BATCH = 1_024


class HistoryRef(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    id: Annotated[str, Field(min_length=1, max_length=256)]
    observed_at: AwareDatetime | None = None


class Dispatch(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    engagement_id: UUID
    task_id: TaskId
    mode: TaskMode
    skill: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
    input: dict[str, JsonValue]
    approved_for_dispatch: bool = False
    confidence: Score = 0
    blast_radius: BlastRadius = BlastRadius.READ_ONLY
    asset_criticality: Score = 1
    asset_ids: tuple[UUID, ...] = Field(default=(), max_length=128)
    historical_findings: tuple[HistoryRef, ...] = Field(default=(), max_length=128)

    @model_validator(mode="after")
    def validate_selection(self) -> Self:
        if self.skill not in SKILLS:
            raise ValueError("unregistered skill")
        if len(set(self.asset_ids)) != len(self.asset_ids):
            raise ValueError("duplicate asset selection")
        if len({item.id for item in self.historical_findings}) != len(self.historical_findings):
            raise ValueError("duplicate historical finding selection")
        return self


@dataclass(frozen=True)
class QueueEntry:
    dispatch: Dispatch
    priority: Decimal

    @classmethod
    def from_dispatch(cls, dispatch: Dispatch) -> Self:
        score = Decimal(str(dispatch.confidence)) * BLAST_WEIGHT[dispatch.blast_radius]
        return cls(dispatch, score * Decimal(str(dispatch.asset_criticality)))


@dataclass(frozen=True)
class Outcome:
    engagement_id: UUID
    task_id: str
    status: TaskStatus | Literal["DEFERRED", "UNCHANGED"]
    reason: str | None = None
    findings: int = 0


def _order(entries: Sequence[QueueEntry], *, hitl: bool = False) -> list[QueueEntry]:
    return sorted(entries, key=lambda item: (
        not (hitl and item.dispatch.blast_radius is BlastRadius.DESTRUCTIVE),
        -item.priority, item.dispatch.engagement_id, item.dispatch.task_id,
    ))


def hitl_rail(entries: Sequence[QueueEntry]) -> tuple[QueueEntry, ...]:
    """Return operator dispatch proposals, with destructive tags first."""
    proposals = [item for item in entries if item.dispatch.blast_radius is BlastRadius.DESTRUCTIVE
                 or (item.dispatch.mode is TaskMode.AI_PROPOSED_HITL_GATED
                     and not item.dispatch.approved_for_dispatch)]
    return tuple(_order(proposals, hitl=True))


class PostgresStore:
    def __init__(self, database_url: str, *, schema: str | None = None) -> None:
        self.database_url = database_url
        self.schema = schema

    def connect(self) -> Connection:
        conn = psycopg.connect(self.database_url, connect_timeout=5, autocommit=True)
        if self.schema is not None:
            try:
                conn.execute("SELECT set_config('search_path', quote_ident(%s), false)", (self.schema,))
            except BaseException:
                conn.close()
                raise
        return conn

    def enqueue(self, dispatch: Dispatch) -> QueueEntry:
        """Register the frozen row once and recompute priority from this dispatch."""
        entry = QueueEntry.from_dispatch(dispatch)
        with self.connect() as conn, conn.transaction():
            conn.execute("SET LOCAL statement_timeout = '4s'")
            conn.execute(
                """INSERT INTO workflow_tasks (engagement_id,id,mode)
                   VALUES (%s,%s,%s) ON CONFLICT (engagement_id,id) DO NOTHING""",
                (dispatch.engagement_id, dispatch.task_id, dispatch.mode.value),
            )
            row = conn.execute(
                "SELECT mode FROM workflow_tasks WHERE engagement_id=%s AND id=%s", _key(dispatch),
            ).fetchone()
            if row is None or row[0] != dispatch.mode.value:
                raise ValueError("dispatch mode does not match the frozen task row")
        return entry

    @staticmethod
    def claim(conn: Connection, dispatch: Dispatch) -> WorkflowTask | None:
        row = conn.execute(
            """SELECT mode,status FROM workflow_tasks WHERE engagement_id=%s AND id=%s
               FOR UPDATE SKIP LOCKED""", _key(dispatch),
        ).fetchone()
        if row is None:
            return None
        return WorkflowTask(id=dispatch.task_id, engagement_id=str(dispatch.engagement_id),
                            mode=TaskMode(row[0]), status=TaskStatus(row[1]))

    @staticmethod
    def phase(conn: Connection, engagement_id: UUID) -> tuple[EngagementState, int | None] | None:
        row = conn.execute(
            """SELECT e.current_state, (SELECT l.seq_id FROM immutable_audit_log AS l
               WHERE l.engagement_id=e.id AND l.payload ? 'from_state' ORDER BY l.seq_id DESC LIMIT 1)
               FROM engagements AS e WHERE e.id=%s""", (engagement_id,),
        ).fetchone()
        return (EngagementState(row[0]), int(row[1]) if row[1] is not None else None) if row else None

    @staticmethod
    def context_rows(conn: Connection, dispatch: Dispatch) -> tuple[list[AssetNode], list[HistoricalFinding]]:
        recency: dict[str, datetime | None] = {item.id: item.observed_at for item in dispatch.historical_findings}
        assets: list[AssetNode] = []
        findings: list[HistoricalFinding] = []
        with conn.cursor(row_factory=psycopg.rows.dict_row) as cursor:
            if dispatch.asset_ids:
                cursor.execute(
                    """SELECT id,engagement_id::text AS engagement_id,asset_category,
                              canonical_identifier,metadata,discovered_by
                       FROM asset_nodes WHERE engagement_id=%s AND id=ANY(%s)""",
                    (dispatch.engagement_id, list(dispatch.asset_ids)),
                )
                assets = [AssetNode.model_validate(row) for row in cursor]
            if recency:
                cursor.execute(
                    """SELECT id,engagement_id::text AS engagement_id,title,confidence_score,cvss_score,status
                       FROM findings WHERE engagement_id=%s AND id=ANY(%s)""",
                    (dispatch.engagement_id, list(recency)),
                )
                findings = [HistoricalFinding(Finding.model_validate(row), recency[row["id"]]) for row in cursor]
        if len(assets) != len(dispatch.asset_ids) or len(findings) != len(recency):
            raise ValueError("context selection does not belong to the engagement")
        return assets, findings

    @staticmethod
    def update_status(conn: Connection, dispatch: Dispatch, status: TaskStatus) -> None:
        conn.execute("UPDATE workflow_tasks SET status=%s WHERE engagement_id=%s AND id=%s",
                     (status.value, *_key(dispatch)))

    @staticmethod
    def insert_results(conn: Connection, findings: Sequence[Finding], plan: ValidationPlan | None) -> None:
        for finding in findings:
            conn.execute(
                """INSERT INTO findings (engagement_id,id,title,confidence_score,status)
                   VALUES (%s,%s,%s,%s,'HYPOTHESIS')""",
                (finding.engagement_id, finding.id, finding.title, Decimal(str(finding.confidence_score))),
            )
        if plan is not None:
            conn.execute(
                "INSERT INTO validation_plans (engagement_id,id,blast_radius) VALUES (%s,%s,%s)",
                (plan.engagement_id, plan.id, plan.blast_radius.value),
            )


def _key(dispatch: Dispatch) -> tuple[UUID, str]:
    return dispatch.engagement_id, dispatch.task_id


def _result_id(dispatch: Dispatch, *parts: str) -> str:
    identity = canonical_json([str(dispatch.engagement_id), dispatch.task_id, *parts])
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _try_slot(conn: Connection, worker: WorkerSpec) -> bool:
    first = list(Agent).index(worker.agent) * 100
    # Individual queries acquire exactly one cross-process slot, if available.
    for slot in range(first, first + worker.concurrency):
        row = conn.execute("SELECT pg_try_advisory_xact_lock(%s,%s)", (_SLOT_NAMESPACE, slot)).fetchone()
        if row is not None and row[0] is True:
            return True
    return False


class PhaseChanged(Exception):
    pass


class Supervisor:
    def __init__(
        self, store: PostgresStore, runner: Runner, registry: Mapping[str, Skill] | None = None,
        *, timeout: float = 30.0, context_bytes: int = 65_536,
        model_chains: Mapping[str, tuple[str, ...]] | None = None,
    ) -> None:
        if not 0 < timeout <= 600 or not 0 < context_bytes <= 1_048_576:
            raise ValueError("invalid supervisor limits")
        self.store = store
        self.runner = runner
        self.registry = registry if registry is not None else load_registry()
        self.timeout = timeout
        self.context_bytes = context_bytes
        self.model_chains = model_chains if model_chains is not None else MODEL_CHAINS

    def run_pending(self, dispatches: Sequence[Dispatch]) -> tuple[Outcome, ...]:
        _validate_batch(dispatches)
        entries = _order([QueueEntry.from_dispatch(item) for item in dispatches])
        with ExitStack() as stack:
            pools = {agent: stack.enter_context(ThreadPoolExecutor(max_workers=WORKERS[agent].concurrency))
                     for agent in {SKILLS[item.dispatch.skill].agent for item in entries}}
            jobs = [pools[SKILLS[item.dispatch.skill].agent].submit(self.run_one, item.dispatch) for item in entries]
            return tuple(job.result() for job in jobs)

    def run_one(self, dispatch: Dispatch) -> Outcome:
        try:
            with self.store.connect() as conn, conn.transaction():
                # READ COMMITTED lets the final query observe changes during inference.
                conn.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                conn.execute("SET LOCAL statement_timeout = '4s'")
                conn.execute("SET LOCAL lock_timeout = '100ms'")
                conn.execute("SELECT set_config('idle_in_transaction_session_timeout', %s, true)",
                             (f"{self.timeout + 10:g}s",))
                outcome = self._run_locked(conn, dispatch)
        except PhaseChanged:
            outcome = Outcome(*_key(dispatch), "DEFERRED", "ENGAGEMENT_PHASE_CHANGED")
        except psycopg.Error:
            outcome = Outcome(*_key(dispatch), "DEFERRED", "DATABASE_TRANSACTION_UNCONFIRMED")
        LOGGER.info("%s", canonical_json({"event": "task_outcome", **_outcome_json(outcome)}))
        return outcome

    def _run_locked(self, conn: Connection, dispatch: Dispatch) -> Outcome:
        key = _key(dispatch)
        skill_spec = SKILLS[dispatch.skill]
        worker = WORKERS[skill_spec.agent]
        if not _try_slot(conn, worker):
            return Outcome(*key, "DEFERRED", "WORKER_CAPACITY")
        task = self.store.claim(conn, dispatch)
        if task is None:
            return Outcome(*key, "DEFERRED", "TASK_LOCKED_OR_MISSING")
        if task.mode is not dispatch.mode:
            return Outcome(*key, "UNCHANGED", "TASK_MODE_MISMATCH")
        if task.mode is TaskMode.MANUAL_ONLY or task.status not in {TaskStatus.QUEUED, TaskStatus.PAUSED_HITL}:
            return Outcome(*key, "UNCHANGED", "TASK_NOT_DISPATCHABLE")
        if (dispatch.blast_radius is BlastRadius.DESTRUCTIVE
                or ((task.mode is TaskMode.AI_PROPOSED_HITL_GATED or task.status is TaskStatus.PAUSED_HITL)
                    and not dispatch.approved_for_dispatch)):
            self.store.update_status(conn, dispatch, TaskStatus.PAUSED_HITL)
            return Outcome(*key, TaskStatus.PAUSED_HITL, "HUMAN_REVIEW_REQUIRED")
        phase = self.store.phase(conn, dispatch.engagement_id)
        if phase is None or phase[0] is not worker.phase:
            return Outcome(*key, "DEFERRED", "ENGAGEMENT_PHASE_DENIED")
        skill = self.registry[dispatch.skill]
        try:
            supplied = skill_spec.input_model.model_validate_json(canonical_json(dispatch.input))
            assets, history = self.store.context_rows(conn, dispatch)
            context = assemble_context(skill, supplied, assets=assets, findings=history, byte_budget=self.context_bytes)
        except ContextBudgetExceeded:
            return self._reject(conn, dispatch, phase, "CONTEXT_BUDGET_EXCEEDED")
        except (ValueError, OverflowError, RecursionError):
            return self._reject(conn, dispatch, phase, "INVALID_TASK_INPUT")

        self.store.update_status(conn, dispatch, TaskStatus.RUNNING)
        result = self.runner.run(
            task_id=f"{dispatch.engagement_id}/{dispatch.task_id}", agent=worker.agent.value,
            skill=skill.name, prompt=skill.prompt, context=context, output_model=skill_spec.output_model,
            budget=TokenBudget(input_tokens=skill.token_budget.input_tokens,
                               output_tokens=skill.token_budget.output_tokens, total_tokens=worker.input_tokens),
            models=self.model_chains[worker.agent.value], timeout=self.timeout,
            validate_output=lambda output: skill_spec.validate_evidence(supplied, output),
        )
        LOGGER.info("%s", canonical_json({
            "event": "task_trace", "engagement_id": str(dispatch.engagement_id), "task_id": dispatch.task_id,
            "agent": worker.agent.value, "skill": skill.name, "version": skill.version,
            "rejection": result.reason, "measurements": asdict(result.stats),
            "reasoning_trace": [asdict(step) for step in result.reasoning_trace],
        }))
        if result.output is None:
            return self._reject(conn, dispatch, phase, result.reason or "MODEL_REJECTED")
        outputs = sorted(result.output.findings, key=lambda item: (item.evidence_ref, item.code))
        findings = [Finding(
            id=_result_id(dispatch, "finding", item.evidence_ref, item.code), engagement_id=str(dispatch.engagement_id),
            title=skill_spec.labels[item.code], confidence_score=item.confidence_score, status=FindingStatus.HYPOTHESIS,
        ) for item in outputs]
        plan = ValidationPlan(id=_result_id(dispatch, "plan"), engagement_id=str(dispatch.engagement_id),
                              blast_radius=dispatch.blast_radius) if findings else None
        # Inserts take the existing FK key-share lock on the engagement. M2 takes
        # FOR UPDATE on the same row before every transition. Check the phase and
        # transition epoch after acquiring that lock; mismatch rolls back all
        # inserts and the task update. No engagement lock spans model execution.
        self.store.insert_results(conn, findings, plan)
        self._require_phase(conn, dispatch, phase)
        self.store.update_status(conn, dispatch, TaskStatus.DONE)
        return Outcome(*key, TaskStatus.DONE, findings=len(findings))

    def _require_phase(
        self, conn: Connection, dispatch: Dispatch, phase: tuple[EngagementState, int | None],
    ) -> None:
        if self.store.phase(conn, dispatch.engagement_id) != phase:
            raise PhaseChanged

    def _reject(
        self, conn: Connection, dispatch: Dispatch, phase: tuple[EngagementState, int | None], reason: str,
    ) -> Outcome:
        self._require_phase(conn, dispatch, phase)
        self.store.update_status(conn, dispatch, TaskStatus.REJECTED)
        return Outcome(*_key(dispatch), TaskStatus.REJECTED, reason)


def _outcome_json(outcome: Outcome) -> dict[str, object]:
    return {**asdict(outcome), "engagement_id": str(outcome.engagement_id)}


_CATALOG: TypeAdapter[tuple[Dispatch, ...]] = TypeAdapter(tuple[Dispatch, ...], config=ConfigDict(strict=True))


def _validate_batch(dispatches: Sequence[Dispatch]) -> None:
    if len(dispatches) > _MAX_BATCH:
        raise ValueError("too many tasks in dispatch batch")
    if len(dispatches) != len({_key(item) for item in dispatches}):
        raise ValueError("duplicate dispatch identity")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("catalog", type=Path, help="trusted, engagement-scoped JSON dispatch catalog")
    parser.add_argument("--adapter", required=True, help="operator-installed offline model module:callable")
    parser.add_argument("--tokenizer", required=True, help="operator-installed exact tokenizer module:callable")
    parser.add_argument("--adapter-path", type=Path, action="append", default=[])
    parser.add_argument("--enqueue", action="store_true", help="create missing workflow task rows")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--metrics-file", type=Path, help="write Prometheus textfile collector metrics")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        catalog = _CATALOG.validate_json(read_json_file(args.catalog, 8 * 1024 * 1024))
        _validate_batch(catalog)
        store = PostgresStore(os.environ["DATABASE_URL"])
        registry = load_registry()
        metrics = RunMetrics()
        runner = Runner(LocalBackend(adapter=args.adapter, count_tokens=args.tokenizer,
                                     import_paths=tuple(args.adapter_path)), metrics=metrics)
        supervisor = Supervisor(store, runner, registry, timeout=args.timeout)
        if args.enqueue:
            for dispatch in catalog:
                store.enqueue(dispatch)
        outcomes = supervisor.run_pending(catalog)
        rail = hitl_rail([QueueEntry.from_dispatch(item) for item in catalog])
        print(canonical_json({"outcomes": [_outcome_json(item) for item in outcomes], "hitl_rail": [
            {"engagement_id": str(item.dispatch.engagement_id), "task_id": item.dispatch.task_id,
             "blast_radius": item.dispatch.blast_radius, "priority": str(item.priority)} for item in rail
        ]}))
        if args.metrics_file is not None:
            write_to_textfile(str(args.metrics_file), metrics.registry)
    except (OSError, KeyError, ValueError, RecursionError, psycopg.Error) as exc:
        LOGGER.error("agent runtime setup or storage failure (%s)", type(exc).__name__)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
