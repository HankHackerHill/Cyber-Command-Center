"""Exercise M5's transaction boundaries against an isolated copy of MS0."""

from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from threading import Event
from typing import ParamSpec, TypeVar
from uuid import UUID, uuid4

from contracts.events import ActorType, EngagementState, TransitionEvent
from contracts.plans import BlastRadius
from contracts.tasks import TaskMode, TaskStatus
import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
import pytest

from harness.context import canonical_json, load_registry
from harness.runner import LocalBackend, ModelReply, ModelRequest, Runner
from supervisor import Dispatch, HistoryRef, PostgresStore, Supervisor, hitl_rail


REPOSITORY = Path(__file__).resolve().parents[3]
P = ParamSpec("P")
T = TypeVar("T")


@dataclass(frozen=True)
class Database:
    dsn: str
    worker_dsn: str

    def connect(self) -> psycopg.Connection[tuple[object, ...]]:
        return psycopg.connect(self.dsn)

    def engagement(self, phase: EngagementState) -> UUID:
        engagement_id = uuid4()
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO engagements (id, current_state) VALUES (%s, %s)",
                (engagement_id, phase.value),
            )
        return engagement_id

    def status(self, dispatch: Dispatch) -> str:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT status::text FROM workflow_tasks WHERE engagement_id = %s AND id = %s",
                (dispatch.engagement_id, dispatch.task_id),
            ).fetchone()
        assert row is not None
        return str(row[0])

    def findings(self, engagement_id: UUID) -> list[tuple[object, ...]]:
        with self.connect() as conn:
            return conn.execute(
                "SELECT id, status::text, confidence_score FROM findings WHERE engagement_id = %s ORDER BY id",
                (engagement_id,),
            ).fetchall()

    def plans(self, engagement_id: UUID) -> list[tuple[object, ...]]:
        with self.connect() as conn:
            return conn.execute(
                """SELECT id, blast_radius::text, approver_sig, second_approver_sig
                   FROM validation_plans WHERE engagement_id = %s ORDER BY id""",
                (engagement_id,),
            ).fetchall()


@pytest.fixture
def database() -> Iterator[Database]:
    url = os.getenv("M5_TEST_DATABASE_URL")
    if url is None:
        pytest.skip("Set M5_TEST_DATABASE_URL to a disposable loopback PostgreSQL database")
    settings = conninfo_to_dict(url)
    loopback = {"127.0.0.1", "::1"}
    if (settings.get("host") not in loopback or "service" in settings
            or settings.get("hostaddr", settings["host"]) not in loopback):
        pytest.fail("M5_TEST_DATABASE_URL must name an explicit loopback host")
    schema = f"m5_test_{uuid4().hex}"
    ident = sql.Identifier(schema)
    role = f"{schema}_worker"
    role_ident = sql.Identifier(role)
    options = f"{settings.get('options', '')} -csearch_path={schema}"
    isolated_dsn = make_conninfo(url, options=options)
    worker_dsn = make_conninfo(url, options=f"{options} -crole={role}")
    with psycopg.connect(url, autocommit=True) as owner:
        owner.execute(sql.SQL("CREATE SCHEMA {}").format(ident))
        try:
            with psycopg.connect(isolated_dsn) as conn:
                conn.execute((REPOSITORY / "db/schema.sql").read_text(), prepare=False)
                conn.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(role_ident))
                conn.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(ident, role_ident))
                conn.execute(sql.SQL(
                    "GRANT SELECT ON ALL TABLES IN SCHEMA {} TO {}",
                ).format(ident, role_ident))
                conn.execute(sql.SQL(
                    "GRANT INSERT ON workflow_tasks, findings, validation_plans TO {}",
                ).format(role_ident))
                conn.execute(sql.SQL("GRANT UPDATE (status) ON workflow_tasks TO {}").format(role_ident))
            yield Database(isolated_dsn, worker_dsn)
        finally:
            owner.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(ident))
            owner.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(role_ident))


def count_tokens(model: str, text: str) -> int:
    return len(text.encode("utf-8"))


def generate_fixture(request: ModelRequest) -> ModelReply:
    packet = json.loads(request.text)
    context = json.loads(packet["context"])
    artifacts = context["task_input"]["artifacts"]
    assert len(artifacts) == 1
    artifact = artifacts[0]
    if artifact["data"].get("malformed") is True:
        return ModelReply(text="invalid json")
    if artifact["data"].get("check_context") is True:
        assert [record["canonical_identifier"] for record in context["asset_nodes"]] == ["review.docs.invalid"]
        assert [record["id"] for record in context["historical_findings"]] == ["prior-review"]
    assert artifact["data"].get("synthetic_review") is True
    code = {
        "confidence_score": "supported_hypothesis",
        "path_rank": "recorded_path_priority",
    }[context["skill"]]
    return ModelReply(text=json.dumps({"findings": [
        {"code": code, "evidence_ref": artifact["ref"], "confidence_score": 0.9},
    ]}))


def runtime(database: Database) -> tuple[PostgresStore, Runner, Supervisor]:
    store = PostgresStore(database.worker_dsn)
    runner = Runner(LocalBackend(
        adapter="test_supervisor_db:generate_fixture",
        count_tokens="test_supervisor_db:count_tokens",
        import_paths=(Path(__file__).resolve().parent, REPOSITORY / "packages/contracts-py"),
    ))
    return store, runner, Supervisor(store=store, runner=runner, registry=load_registry(), timeout=5)


def sample(
    engagement_id: UUID, *, task_id: str = "synthetic-review",
    mode: TaskMode = TaskMode.AI_AUTONOMOUS_PASSIVE, skill: str = "confidence_score",
    blast_radius: BlastRadius = BlastRadius.READ_ONLY,
    approved: bool = False, malformed: bool = False,
    asset_ids: tuple[UUID, ...] = (), historical_findings: tuple[HistoryRef, ...] = (),
    check_context: bool = False,
) -> Dispatch:
    return Dispatch(
        engagement_id=engagement_id, task_id=task_id, mode=mode, skill=skill,
        input={"artifacts": [{
            "ref": "synthetic_evidence",
            "data": {"synthetic_review": True, "malformed": malformed, "check_context": check_context},
        }]},
        confidence=0.9, blast_radius=blast_radius, asset_criticality=1,
        approved_for_dispatch=approved,
        asset_ids=asset_ids, historical_findings=historical_findings,
    )


def assert_no_artifacts(database: Database, engagement_id: UUID) -> None:
    assert database.findings(engagement_id) == []
    assert database.plans(engagement_id) == []


def after_call(function: Callable[P, T], callback: Callable[[], None]) -> Callable[P, T]:
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        result = function(*args, **kwargs)
        callback()
        return result

    return wrapper


def test_success_is_insert_only_and_replay_preserves_human_status(database: Database) -> None:
    engagement_id = database.engagement(EngagementState.ANALYTICAL_TRIAGE)
    task = sample(engagement_id)
    store, _, supervisor = runtime(database)
    with store.connect() as conn:
        row = conn.execute(
            "SELECT has_column_privilege(current_user, 'engagements', 'current_state', 'UPDATE')",
        ).fetchone()
        assert row == (False,)
    store.enqueue(task)
    outcome, = supervisor.run_pending((task,))
    assert outcome.status == TaskStatus.DONE
    assert database.status(task) == TaskStatus.DONE
    findings = database.findings(engagement_id)
    assert len(findings) == 1
    assert findings[0][1] == "HYPOTHESIS"
    assert str(findings[0][2]) == "0.90"
    plans = database.plans(engagement_id)
    assert len(plans) == 1
    assert plans[0][1:] == ("READ_ONLY", None, None)

    # This fixture change represents a later human review. M5 must not overwrite it.
    with database.connect() as conn:
        conn.execute(
            "UPDATE findings SET status = 'CONFIRMED' WHERE engagement_id = %s",
            (engagement_id,),
        )
    store.enqueue(task)
    replay, = supervisor.run_pending((task,))
    assert replay.status == "UNCHANGED"
    assert database.status(task) == TaskStatus.DONE
    assert database.findings(engagement_id) == [(findings[0][0], "CONFIRMED", findings[0][2])]
    assert database.plans(engagement_id) == plans


def test_double_model_failure_commits_only_rejection(database: Database) -> None:
    engagement_id = database.engagement(EngagementState.ANALYTICAL_TRIAGE)
    task = sample(engagement_id, malformed=True)
    store, _, supervisor = runtime(database)
    store.enqueue(task)
    outcome, = supervisor.run_pending((task,))
    assert outcome.status == TaskStatus.REJECTED
    assert database.status(task) == TaskStatus.REJECTED
    assert_no_artifacts(database, engagement_id)


def test_late_database_failure_rolls_back_findings_and_task_completion(database: Database) -> None:
    engagement_id = database.engagement(EngagementState.ANALYTICAL_TRIAGE)
    task = sample(engagement_id)
    store, _, supervisor = runtime(database)
    store.enqueue(task)
    with database.connect() as conn:
        conn.execute("""
            CREATE FUNCTION fail_plan_insert() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                RAISE EXCEPTION 'synthetic plan write failure';
            END;
            $$;
            CREATE TRIGGER test_failed_commit BEFORE INSERT ON validation_plans
                FOR EACH ROW EXECUTE FUNCTION fail_plan_insert();
        """, prepare=False)
    outcome, = supervisor.run_pending((task,))
    assert outcome.reason == "DATABASE_TRANSACTION_UNCONFIRMED"
    assert database.status(task) == TaskStatus.QUEUED
    assert_no_artifacts(database, engagement_id)


def test_manual_wrong_phase_and_unapproved_gated_tasks_do_not_run(database: Database) -> None:
    right_phase = database.engagement(EngagementState.ANALYTICAL_TRIAGE)
    wrong_phase = database.engagement(EngagementState.HALTED_KILLSWITCH)
    manual = sample(right_phase, task_id="manual", mode=TaskMode.MANUAL_ONLY)
    halted = sample(wrong_phase, task_id="halted")
    gated = sample(right_phase, task_id="gated", mode=TaskMode.AI_PROPOSED_HITL_GATED)
    tasks = (manual, halted, gated)
    store, _, supervisor = runtime(database)
    for task in tasks:
        store.enqueue(task)
    supervisor.run_pending(tasks)
    assert database.status(manual) == TaskStatus.QUEUED
    assert database.status(halted) == TaskStatus.QUEUED
    assert database.status(gated) == TaskStatus.PAUSED_HITL
    assert_no_artifacts(database, right_phase)
    assert_no_artifacts(database, wrong_phase)

    dispatched = sample(right_phase, task_id="gated", mode=TaskMode.AI_PROPOSED_HITL_GATED, approved=True)
    supervisor.run_pending((dispatched,))
    assert database.status(dispatched) == TaskStatus.DONE
    assert len(database.findings(right_phase)) == 1


def test_destructive_tag_stays_in_review_without_an_unsigned_plan(database: Database) -> None:
    engagement_id = database.engagement(EngagementState.ANALYTICAL_TRIAGE)
    task = sample(
        engagement_id, mode=TaskMode.AI_PROPOSED_HITL_GATED,
        blast_radius=BlastRadius.DESTRUCTIVE, approved=True,
    )
    store, _, supervisor = runtime(database)
    entry = store.enqueue(task)
    assert hitl_rail((entry,)) == (entry,)
    supervisor.run_pending((task,))
    assert database.status(task) == TaskStatus.PAUSED_HITL
    assert_no_artifacts(database, engagement_id)


def test_context_reads_only_selected_records_in_the_same_engagement(database: Database) -> None:
    engagement_id = database.engagement(EngagementState.ANALYTICAL_TRIAGE)
    other_id = database.engagement(EngagementState.ANALYTICAL_TRIAGE)
    asset_id, foreign_asset_id = uuid4(), uuid4()
    with database.connect() as conn:
        for owner, identifier, name in (
            (engagement_id, asset_id, "review.docs.invalid"),
            (other_id, foreign_asset_id, "unrelated.docs.invalid"),
        ):
            conn.execute(
                """INSERT INTO asset_nodes
                   (engagement_id, id, asset_category, canonical_identifier, metadata, discovered_by)
                   VALUES (%s, %s, 'host', %s, '{}'::jsonb, 'SYSTEM')""",
                (owner, identifier, name),
            )
        conn.execute(
            """INSERT INTO findings (engagement_id, id, title, confidence_score)
               VALUES (%s, 'prior-review', 'Synthetic historical review', 0.75),
                      (%s, 'foreign-review', 'Unrelated review', 0.75)""",
            (engagement_id, other_id),
        )

    prior = HistoryRef(id="prior-review", observed_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
    allowed = sample(
        engagement_id, task_id="scoped", asset_ids=(asset_id,),
        historical_findings=(prior,), check_context=True,
    )
    foreign_asset = sample(engagement_id, task_id="foreign-asset", asset_ids=(foreign_asset_id,))
    foreign_finding = sample(
        engagement_id, task_id="foreign-finding", historical_findings=(HistoryRef(id="foreign-review"),),
    )
    store, _, supervisor = runtime(database)
    tasks = (allowed, foreign_asset, foreign_finding)
    for task in tasks:
        store.enqueue(task)
    outcomes = {item.task_id: item for item in supervisor.run_pending(tasks)}
    assert outcomes[allowed.task_id].status == TaskStatus.DONE
    assert outcomes[foreign_asset.task_id].reason == outcomes[foreign_finding.task_id].reason == "INVALID_TASK_INPUT"
    assert database.status(foreign_asset) == database.status(foreign_finding) == TaskStatus.REJECTED
    assert len(database.findings(engagement_id)) == 2
    assert len(database.plans(engagement_id)) == 1
    assert len(database.findings(other_id)) == 1
    assert database.plans(other_id) == []


@pytest.mark.parametrize("returned_to_phase", [False, True])
def test_killswitch_can_commit_before_m5_and_invalidates_its_result(
    database: Database, monkeypatch: pytest.MonkeyPatch, returned_to_phase: bool,
) -> None:
    engagement_id = database.engagement(EngagementState.ANALYTICAL_TRIAGE)
    task = sample(engagement_id)
    store, runner, supervisor = runtime(database)
    store.enqueue(task)

    def stop_before_result_commit() -> None:
        # Mimic only the state lock used by M2. The observed database role for
        # this test mutation is the fixture owner, separate from the M5 role.
        with database.connect() as conn:
            conn.execute("SET LOCAL lock_timeout = '250ms'")
            conn.execute("SELECT id FROM engagements WHERE id = %s FOR UPDATE", (engagement_id,))
            conn.execute(
                "UPDATE engagements SET current_state = 'HALTED_KILLSWITCH' WHERE id = %s",
                (engagement_id,),
            )
            event = TransitionEvent(
                event_id=str(uuid4()), engagement_id=str(engagement_id),
                from_state=EngagementState.ANALYTICAL_TRIAGE, to_state=EngagementState.HALTED_KILLSWITCH,
                actor_type=ActorType.SYSTEM, actor_id="m5-test-killswitch",
                occurred_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            )
            body = canonical_json(event.model_dump(mode="json"))
            digest = hashlib.sha256(bytes(32) + body.encode("utf-8")).hexdigest()
            conn.execute(
                """INSERT INTO immutable_audit_log (payload, prev_record_hash, record_hash)
                   VALUES (%s::jsonb, %s, %s)""",
                (body, "0" * 64, digest),
            )
        if returned_to_phase:
            # Fixture the same-state/new-epoch condition without requiring
            # M2's separate manual-reset and signed progression integration.
            with database.connect() as conn:
                conn.execute(
                    "UPDATE engagements SET current_state = 'ANALYTICAL_TRIAGE' WHERE id = %s",
                    (engagement_id,),
                )

    monkeypatch.setattr(runner, "run", after_call(runner.run, stop_before_result_commit))
    outcome, = supervisor.run_pending((task,))
    assert outcome.reason == "ENGAGEMENT_PHASE_CHANGED"
    assert database.status(task) == TaskStatus.QUEUED
    assert_no_artifacts(database, engagement_id)


def test_graph_slot_is_shared_by_separate_supervisors(
    database: Database, monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_engagement = database.engagement(EngagementState.ANALYTICAL_TRIAGE)
    second_engagement = database.engagement(EngagementState.ANALYTICAL_TRIAGE)
    first = sample(first_engagement, skill="path_rank")
    second = sample(second_engagement, skill="path_rank")
    first_store, first_runner, first_supervisor = runtime(database)
    second_store, _, second_supervisor = runtime(database)
    first_store.enqueue(first)
    second_store.enqueue(second)

    captured, release = Event(), Event()

    def hold_first_slot() -> None:
        captured.set()
        assert release.wait(timeout=10)

    monkeypatch.setattr(first_runner, "run", after_call(first_runner.run, hold_first_slot))
    with ThreadPoolExecutor(max_workers=1) as executor:
        in_flight = executor.submit(first_supervisor.run_one, first)
        try:
            assert captured.wait(timeout=10)
            contested = second_supervisor.run_one(second)
            assert contested.reason == "WORKER_CAPACITY"
            assert database.status(second) == TaskStatus.QUEUED
            assert_no_artifacts(database, second_engagement)
        finally:
            release.set()
        assert in_flight.result(timeout=10).status == TaskStatus.DONE

    assert second_supervisor.run_one(second).status == TaskStatus.DONE
    assert len(database.findings(first_engagement)) == len(database.findings(second_engagement)) == 1
