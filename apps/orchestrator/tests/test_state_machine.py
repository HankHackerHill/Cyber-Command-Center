"""Live database acceptance tests for the authoritative transition graph."""

import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from threading import Barrier
from uuid import UUID, uuid4

import httpx
import psycopg
import pytest
from contracts.events import ActorType, Ed25519Signature, EngagementState, TransitionEvent
from contracts.ledger import LedgerRecord
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from ledger import GENESIS_HASH, get_state, hash_record, read_ledger, record_review_transition
from main import create_app


@pytest.fixture(scope="module")
def urls() -> tuple[str, str]:
    database = os.environ.get("ORCHESTRATOR_TEST_DATABASE_URL")
    redis = os.environ.get("ORCHESTRATOR_TEST_REDIS_URL")
    if not database or not redis:
        pytest.skip("Set ORCHESTRATOR_TEST_DATABASE_URL and ORCHESTRATOR_TEST_REDIS_URL")
    return database, redis


def archive_request(
    engagement: UUID, source: EngagementState, actor: str, key: Ed25519PrivateKey,
) -> TransitionEvent:
    event = TransitionEvent(
        event_id=str(uuid4()), engagement_id=str(engagement),
        from_state=source, to_state=EngagementState.COMPLETED_ARCHIVED,
        actor_type=ActorType.HUMAN_OPERATOR, actor_id=actor,
        occurred_at=datetime.now(timezone.utc),
    )
    signature = Ed25519Signature(
        signer_id=actor, signature=key.sign(event.canonical_envelope()).hex(),
    )
    return event.model_copy(update={"hitl_signature": signature})


def transition_request(
    engagement: UUID, source: EngagementState, destination: EngagementState,
    key: Ed25519PrivateKey | None = None, actor_type: ActorType = ActorType.HUMAN_OPERATOR,
    *, plan_id: UUID | None = None, plan_hash: str | None = None,
) -> TransitionEvent:
    event = TransitionEvent(
        event_id=str(uuid4()), engagement_id=str(engagement), from_state=source, to_state=destination,
        actor_type=actor_type, actor_id="scope-reviewer", occurred_at=datetime.now(timezone.utc),
        approved_plan_id=plan_id, approved_plan_hash=plan_hash,
    )
    if key is None:
        return event
    return event.model_copy(update={"hitl_signature": Ed25519Signature(
        signer_id=event.actor_id, signature=key.sign(event.canonical_envelope()).hex(),
    )})


def seed_plan(db: psycopg.Connection, engagement: UUID) -> tuple[UUID, str]:
    """Independently compute the digest of the exact five columns the signer reviews."""
    plan_id = uuid4()
    approver = {"signer_id": "réviseur", "signature": Ed25519PrivateKey.generate().sign(plan_id.bytes).hex()}
    db.execute(
        """INSERT INTO validation_plans (engagement_id, id, blast_radius, approver_sig)
           VALUES (%s, %s, 'READ_ONLY', %s::jsonb)""",
        (engagement, str(plan_id), json.dumps(approver)),
    )
    plan = {
        "engagement_id": str(engagement), "id": str(plan_id), "blast_radius": "READ_ONLY",
        "approver_sig": approver, "second_approver_sig": None,
    }
    canonical = json.dumps(plan, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return plan_id, hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def assert_journal(
    client: TestClient, database: str, engagement: UUID, state: EngagementState,
    events: list[TransitionEvent], key: Ed25519PrivateKey | None = None,
) -> list[LedgerRecord]:
    """Compare API and committed DB data, independently recomputing every byte/hash."""
    state_response = client.get(f"/engagements/{engagement}/state")
    assert state_response.status_code == 200, state_response.text
    assert state_response.json() == {"state": state.value}
    response = client.get(f"/engagements/{engagement}/ledger")
    assert response.status_code == 200, response.text
    records = [LedgerRecord.model_validate(row) for row in response.json()]
    with psycopg.connect(database) as reader:
        assert get_state(reader, engagement) == state
        assert read_ledger(reader, engagement, 0) == records
    assert [record.event for record in records] == events
    previous, sequence = GENESIS_HASH, 0
    for record, event in zip(records, events, strict=True):
        assert record.seq_id > sequence
        assert record.prev_record_hash == previous
        envelope = json.dumps(
            event.model_dump(mode="json", exclude={"hitl_signature"}), sort_keys=True,
            separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
        assert event.canonical_envelope() == envelope
        if event.hitl_signature is not None:
            assert key is not None
            key.public_key().verify(bytes.fromhex(event.hitl_signature.signature), envelope)
        body = json.dumps(event.model_dump(mode="json"), sort_keys=True, ensure_ascii=False,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
        assert record.record_hash == hashlib.sha256(bytes.fromhex(previous) + body).hexdigest()
        previous, sequence = record.record_hash, record.seq_id
    return records


def test_competing_signed_archives_commit_one_winner(urls: tuple[str, str]) -> None:
    database, redis = urls
    engagement = uuid4()
    source = EngagementState.REMEDIATION_SYNTHESIS
    history = TransitionEvent(
        engagement_id=str(engagement), event_id=str(uuid4()), from_state=EngagementState.EVIDENCE_VERIFICATION,
        to_state=source, actor_id="historical-operator", actor_type=ActorType.HUMAN_OPERATOR,
        occurred_at=datetime.now(timezone.utc),
    )
    previous_hash = hash_record(GENESIS_HASH, history)
    with psycopg.connect(database) as connection:
        connection.execute("INSERT INTO engagements (id, current_state) VALUES (%s, %s)", (engagement, source))
        connection.execute(
            """INSERT INTO immutable_audit_log (payload, prev_record_hash, record_hash)
               VALUES (%s::jsonb, %s, %s)""", (history.model_dump_json(), GENESIS_HASH, previous_hash),
        )

    keys = {actor: Ed25519PrivateKey.generate() for actor in ("human-A", "human-B")}
    events = [archive_request(engagement, source, actor, key) for actor, key in keys.items()]
    app = create_app(
        database_url=database, redis_url=redis,
        trusted_public_keys={actor: key.public_key() for actor, key in keys.items()},
    )
    with TestClient(app) as client:
        ready = Barrier(2, timeout=10)

        def post(event: TransitionEvent) -> httpx.Response:
            ready.wait()
            response = client.post(f"/engagements/{engagement}/transition", json=event.model_dump(mode="json"))
            assert isinstance(response, httpx.Response)
            return response

        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(post, events))

    assert sorted(r.status_code for r in responses) == [200, 409], [r.text for r in responses]
    ordered = sorted(zip(events, responses, strict=True), key=lambda pair: pair[1].status_code)
    (winner, applied), (_, rejected) = ordered
    assert applied.json()["status"] == "applied"
    assert rejected.json()["reason"] == "STATE_MISMATCH"
    with psycopg.connect(database) as reader:
        assert get_state(reader, engagement) == EngagementState.COMPLETED_ARCHIVED
        prior, final = read_ledger(reader, engagement, 0)
    assert prior.event == history
    assert final.seq_id > prior.seq_id
    assert prior.record_hash == final.prev_record_hash == previous_hash
    assert final.event == winner
    assert final.record_hash == hash_record(previous_hash, winner) == applied.json()["ledger_hash"]


def test_signed_archival_is_bound_to_its_engagement(urls: tuple[str, str]) -> None:
    database, redis = urls
    engagement, other = uuid4(), uuid4()
    source = EngagementState.RETEST_VERIFICATION
    with psycopg.connect(database) as connection, connection.cursor() as cursor:
        cursor.executemany("INSERT INTO engagements (id, current_state) VALUES (%s, %s)",
                           [(engagement, source), (other, source)])
    key = Ed25519PrivateKey.generate()
    event = archive_request(engagement, source, "archivist", key)
    app = create_app(database_url=database, redis_url=redis,
                     trusted_public_keys={event.actor_id: key.public_key()})
    with TestClient(app) as client:
        payload = event.model_dump(mode="json")
        mismatch = client.post(f"/engagements/{other}/transition", json=payload)
        assert 400 <= mismatch.status_code < 500, mismatch.text
        assert mismatch.json()["reason"] == "ENGAGEMENT_ID_MISMATCH"
        with psycopg.connect(database) as reader:
            for engagement_id in (engagement, other):
                assert get_state(reader, engagement_id) == source
                assert read_ledger(reader, engagement_id, 0) == []
        accepted = client.post(f"/engagements/{engagement}/transition", json=payload)
        assert accepted.status_code == 200, accepted.text
        assert accepted.json()["status"] == "applied"
    with psycopg.connect(database) as reader:
        assert get_state(reader, engagement) == EngagementState.COMPLETED_ARCHIVED
        final, = read_ledger(reader, engagement, 0)
    assert final.event == event
    assert final.prev_record_hash == GENESIS_HASH
    assert final.record_hash == hash_record(GENESIS_HASH, event) == accepted.json()["ledger_hash"]


def test_archive_denial_is_atomic_for_each_invalid_signature(urls: tuple[str, str]) -> None:
    database, redis = urls
    engagement = uuid4()
    source = EngagementState.REMEDIATION_SYNTHESIS
    with psycopg.connect(database) as connection:
        connection.execute("INSERT INTO engagements (id, current_state) VALUES (%s, %s)", (engagement, source))

    key = Ed25519PrivateKey.generate()
    event = archive_request(engagement, source, "archivist", key)
    assert event.hitl_signature is not None
    wrong_signer = event.hitl_signature.model_copy(update={"signer_id": "another-operator"})
    app = create_app(database_url=database, redis_url=redis,
                     trusted_public_keys={event.actor_id: key.public_key()})
    with TestClient(app) as client, psycopg.connect(database, autocommit=True) as reader:
        for modified in (
            event.model_copy(update={"event_id": str(uuid4())}),
            event.model_copy(update={"hitl_signature": None}),
            event.model_copy(update={"hitl_signature": wrong_signer}),
        ):
            response = client.post(f"/engagements/{engagement}/transition", json=modified.model_dump(mode="json"))
            assert response.status_code == 403, response.text
            assert response.json()["reason"] == "HUMAN_SIGNATURE_REQUIRED"
            assert get_state(reader, engagement) == source
            assert read_ledger(reader, engagement, 0) == []


@pytest.mark.parametrize(
    ("source", "destination"),
    [
        (EngagementState.INIT_SCOPING, EngagementState.ROE_LOCKED),
        (EngagementState.ROE_LOCKED, EngagementState.DISCOVERY_PASSIVE),
        (EngagementState.DISCOVERY_PASSIVE, EngagementState.ANALYTICAL_TRIAGE),
        (EngagementState.ANALYTICAL_TRIAGE, EngagementState.AWAITING_HITL_GATE),
        (EngagementState.AWAITING_HITL_GATE, EngagementState.CONTROLLED_VALIDATION),
        (EngagementState.AWAITING_HITL_GATE, EngagementState.ANALYTICAL_TRIAGE),
        (EngagementState.CONTROLLED_VALIDATION, EngagementState.EVIDENCE_VERIFICATION),
        (EngagementState.DISCOVERY_PASSIVE, EngagementState.REMEDIATION_SYNTHESIS),
        (EngagementState.ANALYTICAL_TRIAGE, EngagementState.REMEDIATION_SYNTHESIS),
        (EngagementState.EVIDENCE_VERIFICATION, EngagementState.REMEDIATION_SYNTHESIS),
        (EngagementState.EVIDENCE_VERIFICATION, EngagementState.ANALYTICAL_TRIAGE),
        (EngagementState.REMEDIATION_SYNTHESIS, EngagementState.RETEST_VERIFICATION),
        (EngagementState.REMEDIATION_SYNTHESIS, EngagementState.COMPLETED_ARCHIVED),
        (EngagementState.RETEST_VERIFICATION, EngagementState.REMEDIATION_SYNTHESIS),
        (EngagementState.RETEST_VERIFICATION, EngagementState.COMPLETED_ARCHIVED),
    ],
)
def test_all_running_nonstop_handoffs(
    urls: tuple[str, str], source: EngagementState, destination: EngagementState,
) -> None:
    database, redis = urls
    engagement = uuid4()
    key = Ed25519PrivateKey.generate()
    previous = GENESIS_HASH
    events: list[TransitionEvent] = []
    with psycopg.connect(database) as connection:
        connection.execute("INSERT INTO engagements (id, current_state) VALUES (%s, %s)", (engagement, source))
        plan_id, plan_hash = (
            seed_plan(connection, engagement) if destination == EngagementState.CONTROLLED_VALIDATION
            else (None, None)
        )
        event = transition_request(
            engagement, source, destination,
            key if destination in {
                EngagementState.ROE_LOCKED, EngagementState.CONTROLLED_VALIDATION,
                EngagementState.COMPLETED_ARCHIVED,
            } else None, plan_id=plan_id, plan_hash=plan_hash,
        )
        if source == EngagementState.EVIDENCE_VERIFICATION:
            history = event.model_copy(update={
                "event_id": str(uuid4()), "from_state": EngagementState.CONTROLLED_VALIDATION, "to_state": source,
            })
            events.append(history)
            previous = hash_record(GENESIS_HASH, history)
            connection.execute(
                """INSERT INTO immutable_audit_log (payload, prev_record_hash, record_hash)
                   VALUES (%s::jsonb, %s, %s)""", (history.model_dump_json(), GENESIS_HASH, previous),
            )

    app = create_app(database_url=database, redis_url=redis,
                     trusted_public_keys={event.actor_id: key.public_key()})
    with TestClient(app) as client:
        path = f"/engagements/{engagement}/transition"
        payload = event.model_dump(mode="json", exclude_none=True)
        applied = client.post(path, json=payload)
        assert applied.status_code == 200, applied.text
        digest = hash_record(previous, event)
        assert applied.json() == {"status": "applied", "next_state": destination.value, "ledger_hash": digest}

        with psycopg.connect(database) as reader:
            assert get_state(reader, engagement) == destination
            records = read_ledger(reader, engagement, 0)
        assert [r.record_hash for r in records] == ([previous, digest] if previous != GENESIS_HASH else [digest])
        latest = records[-1]
        assert latest.prev_record_hash == previous
        assert latest.event == event
        events.append(event)
        assert assert_journal(client, database, engagement, destination, events, key) == records

        # Replay the identical valid envelope so the row-lock state check decides.
        stale = client.post(path, json=payload)
        assert stale.status_code == 409, stale.text
        assert stale.json()["reason"] == "STATE_MISMATCH"
        with psycopg.connect(database) as reader:
            assert get_state(reader, engagement) == destination
            assert read_ledger(reader, engagement, 0) == records


def test_remediation_preserves_and_checks_optional_signature(urls: tuple[str, str]) -> None:
    database, redis = urls
    engagement = uuid4()
    source = EngagementState.EVIDENCE_VERIFICATION
    with psycopg.connect(database) as db:
        db.execute("INSERT INTO engagements (id, current_state) VALUES (%s, %s)", (engagement, source))

    key = Ed25519PrivateKey.generate()
    event = TransitionEvent(
        event_id=str(uuid4()), engagement_id=str(engagement), from_state=source,
        to_state=EngagementState.REMEDIATION_SYNTHESIS, actor_type=ActorType.HUMAN_OPERATOR,
        actor_id="reviewer", occurred_at=datetime.now(timezone.utc),
    )
    signed = event.model_copy(update={"hitl_signature": Ed25519Signature(
        signer_id=event.actor_id, signature=key.sign(event.canonical_envelope()).hex(),
    )})
    app = create_app(database_url=database, redis_url=redis, trusted_public_keys={event.actor_id: key.public_key()})
    with TestClient(app) as client, psycopg.connect(database, autocommit=True) as reader:
        payload = signed.model_dump(mode="json")
        path = f"/engagements/{engagement}/transition"
        denied = client.post(path, json={**payload, "event_id": str(uuid4())})
        assert denied.status_code == 403 and denied.json()["reason"] == "INVALID_SIGNATURE"
        assert get_state(reader, engagement) == source and not read_ledger(reader, engagement, 0)
        assert client.post(path, json=payload).status_code == 200
        record, = read_ledger(reader, engagement, 0)
        assert record.event == signed


@pytest.mark.parametrize(
    ("source", "destination"),
    [
        (EngagementState.INIT_SCOPING, EngagementState.ROE_LOCKED),
        (EngagementState.AWAITING_HITL_GATE, EngagementState.CONTROLLED_VALIDATION),
    ],
)
def test_human_gate_is_denied_without_writes(
    urls: tuple[str, str], source: EngagementState, destination: EngagementState,
) -> None:
    database, redis = urls
    engagement = uuid4()
    with psycopg.connect(database) as db:
        db.execute("INSERT INTO engagements (id, current_state) VALUES (%s, %s)", (engagement, source))

    key = Ed25519PrivateKey.generate()
    signed = transition_request(engagement, source, destination, key)
    app = create_app(database_url=database, redis_url=redis,
                     trusted_public_keys={signed.actor_id: key.public_key()})
    invalid = [
        signed.model_copy(update={"hitl_signature": None}),
        signed.model_copy(update={"event_id": str(uuid4())}),
    ]
    for actor_type in (ActorType.AI_AGENT, ActorType.SYSTEM):
        # These envelopes have valid trusted-key signatures, but non-human actors.
        nonhuman = transition_request(engagement, source, destination, key, actor_type)
        assert nonhuman.hitl_signature is not None
        key.public_key().verify(bytes.fromhex(nonhuman.hitl_signature.signature), nonhuman.canonical_envelope())
        invalid.append(nonhuman)
    with TestClient(app) as client:
        assert_journal(client, database, engagement, source, [])
        for event in invalid:
            response = client.post(f"/engagements/{engagement}/transition", json=event.model_dump(mode="json"))
            assert response.status_code == 403, response.text
            assert response.json()["reason"] == "HUMAN_SIGNATURE_REQUIRED"
            assert_journal(client, database, engagement, source, [])


def test_plan_gate_rejections_preserve_state_and_ledger(urls: tuple[str, str]) -> None:
    database, redis = urls
    engagement, other = uuid4(), uuid4()
    source = EngagementState.AWAITING_HITL_GATE
    destination = EngagementState.CONTROLLED_VALIDATION
    with psycopg.connect(database) as db:
        db.execute("INSERT INTO engagements (id, current_state) VALUES (%s, %s), (%s, %s)",
                   (engagement, source, other, source))
        plan_id, plan_hash = seed_plan(db, engagement)
        foreign_id, foreign_hash = seed_plan(db, other)

    key = Ed25519PrivateKey.generate()

    def approval(plan: UUID | None, digest: str | None) -> TransitionEvent:
        return transition_request(engagement, source, destination, key, plan_id=plan, plan_hash=digest)

    signed = approval(plan_id, plan_hash)
    app = create_app(database_url=database, redis_url=redis,
                     trusted_public_keys={signed.actor_id: key.public_key()})
    with TestClient(app) as client:
        def reject(event: TransitionEvent, status: int, reason: str) -> None:
            result = client.post(f"/engagements/{engagement}/transition", json=event.model_dump(mode="json"))
            assert result.status_code == status, result.text
            assert result.json() == {"reason": reason}
            assert_journal(client, database, engagement, source, [])

        for incomplete in (approval(None, None), approval(None, plan_hash), approval(plan_id, None)):
            reject(incomplete, 422, "PLAN_BINDING_REQUIRED")
        reject(approval(uuid4(), plan_hash), 404, "PLAN_NOT_FOUND")
        reject(approval(foreign_id, foreign_hash), 404, "PLAN_NOT_FOUND")
        reject(approval(plan_id, "0" * 64), 409, "PLAN_HASH_MISMATCH")
        reject(signed.model_copy(update={"approved_plan_hash": "1" * 64}), 403, "HUMAN_SIGNATURE_REQUIRED")
        reject(signed.model_copy(update={"approved_plan_id": foreign_id}), 403, "HUMAN_SIGNATURE_REQUIRED")

        legacy_payload = signed.model_dump(mode="json")
        legacy_payload["approved_plan_id"] = "a" * 64
        legacy = client.post(f"/engagements/{engagement}/transition", json=legacy_payload)
        assert legacy.status_code == 422 and legacy.json() == {"reason": "INVALID_EVENT"}
        assert_journal(client, database, engagement, source, [])

        # A reviewer may have fetched and signed a snapshot before another writer amended the row.
        with psycopg.connect(database) as db:
            db.execute(
                """UPDATE validation_plans SET approver_sig =
                       jsonb_set(approver_sig, '{signer_id}', to_jsonb('changed-reviewer'::text))
                   WHERE engagement_id = %s AND id = %s""", (engagement, str(plan_id)),
            )
        reject(signed, 409, "PLAN_HASH_MISMATCH")


def test_plan_row_protected_until_ledger_commit(urls: tuple[str, str]) -> None:
    database, _ = urls
    engagement = uuid4()
    source = EngagementState.AWAITING_HITL_GATE
    with psycopg.connect(database) as db:
        db.execute("INSERT INTO engagements (id, current_state) VALUES (%s, %s)", (engagement, source))
        plan_id, plan_hash = seed_plan(db, engagement)
    key = Ed25519PrivateKey.generate()
    event = transition_request(engagement, source, EngagementState.CONTROLLED_VALIDATION, key,
                               plan_id=plan_id, plan_hash=plan_hash)
    update = "UPDATE validation_plans SET blast_radius = 'REVERSIBLE' WHERE engagement_id = %s AND id = %s"
    with psycopg.connect(database) as writer, psycopg.connect(database, autocommit=True) as editor:
        editor.execute("SET lock_timeout = '100ms'")
        with writer.transaction():
            record_review_transition(writer, engagement, event, {event.actor_id: key.public_key()})
            with pytest.raises(psycopg.errors.LockNotAvailable):
                editor.execute(update, (engagement, str(plan_id)))
        assert editor.execute(update, (engagement, str(plan_id))).rowcount == 1
        receipt, = read_ledger(editor, engagement, 0)
        assert receipt.event == event


@pytest.mark.parametrize(
    "states",
    [
        pytest.param([
            EngagementState.INIT_SCOPING, EngagementState.ROE_LOCKED,
            EngagementState.DISCOVERY_PASSIVE, EngagementState.ANALYTICAL_TRIAGE,
            EngagementState.AWAITING_HITL_GATE, EngagementState.CONTROLLED_VALIDATION,
            EngagementState.EVIDENCE_VERIFICATION, EngagementState.REMEDIATION_SYNTHESIS,
            EngagementState.COMPLETED_ARCHIVED,
        ], id="main-progression"),
        pytest.param([
            EngagementState.INIT_SCOPING, EngagementState.ROE_LOCKED,
            EngagementState.DISCOVERY_PASSIVE, EngagementState.ANALYTICAL_TRIAGE,
            EngagementState.AWAITING_HITL_GATE, EngagementState.ANALYTICAL_TRIAGE,
            EngagementState.AWAITING_HITL_GATE, EngagementState.CONTROLLED_VALIDATION,
            EngagementState.EVIDENCE_VERIFICATION, EngagementState.ANALYTICAL_TRIAGE,
            EngagementState.AWAITING_HITL_GATE, EngagementState.CONTROLLED_VALIDATION,
            EngagementState.EVIDENCE_VERIFICATION, EngagementState.ANALYTICAL_TRIAGE,
            EngagementState.REMEDIATION_SYNTHESIS, EngagementState.RETEST_VERIFICATION,
            EngagementState.REMEDIATION_SYNTHESIS, EngagementState.RETEST_VERIFICATION,
            EngagementState.COMPLETED_ARCHIVED,
        ], id="triage-and-retest-loops"),
    ],
)
def test_full_signed_assessment_progression(urls: tuple[str, str], states: list[EngagementState]) -> None:
    database, redis = urls
    engagement = uuid4()
    with psycopg.connect(database) as db:
        db.execute("INSERT INTO engagements (id) VALUES (%s)", (engagement,))
        plan_id, expected_plan_hash = seed_plan(db, engagement)
    key = Ed25519PrivateKey.generate()
    app = create_app(database_url=database, redis_url=redis,
                     trusted_public_keys={"scope-reviewer": key.public_key()})
    events: list[TransitionEvent] = []
    previous_approval: TransitionEvent | None = None
    with TestClient(app) as client:
        listed = client.get(f"/engagements/{engagement}/plans")
        assert listed.status_code == 200, listed.text
        plan, = listed.json()
        assert plan["id"] == str(plan_id) and plan["engagement_id"] == str(engagement)
        reviewed = json.dumps(plan, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        plan_hash = hashlib.sha256(reviewed.encode("utf-8")).hexdigest()
        assert plan_hash == expected_plan_hash
        assert_journal(client, database, engagement, states[0], [])
        for source, destination in zip(states[:-1], states[1:], strict=True):
            # Every hop is signed; in particular, all three human-only targets.
            needs_plan = destination == EngagementState.CONTROLLED_VALIDATION
            path = f"/engagements/{engagement}/transition"
            if needs_plan and previous_approval is not None:
                replay = client.post(path, json=previous_approval.model_dump(mode="json"))
                assert replay.status_code == 409 and replay.json() == {"reason": "EVENT_REPLAY"}
                assert_journal(client, database, engagement, source, events, key)
            event = transition_request(engagement, source, destination, key,
                                       plan_id=plan_id if needs_plan else None,
                                       plan_hash=plan_hash if needs_plan else None)
            response = client.post(path, json=event.model_dump(mode="json"))
            assert response.status_code == 200, response.text
            if needs_plan:
                previous_approval = event
            events.append(event)
            records = assert_journal(client, database, engagement, destination, events, key)
            assert response.json() == {
                "status": "applied", "next_state": destination.value,
                "ledger_hash": records[-1].record_hash,
            }
            # Cursor reads must expose this hop alone without replaying prior rows.
            since = records[-2].seq_id if len(records) > 1 else 0
            delta = client.get(f"/engagements/{engagement}/ledger", params={"since": since})
            assert delta.status_code == 200, delta.text
            assert [LedgerRecord.model_validate(row) for row in delta.json()] == records[-1:]


def test_different_legal_transitions_race_from_existing_tail(urls: tuple[str, str]) -> None:
    database, redis = urls
    engagement = uuid4()
    source = EngagementState.DISCOVERY_PASSIVE
    history = transition_request(engagement, EngagementState.ROE_LOCKED, source)
    previous = hash_record(GENESIS_HASH, history)
    with psycopg.connect(database) as db:
        db.execute("INSERT INTO engagements (id, current_state) VALUES (%s, %s)", (engagement, source))
        db.execute(
            """INSERT INTO immutable_audit_log (payload, prev_record_hash, record_hash)
               VALUES (%s::jsonb, %s, %s)""", (history.model_dump_json(), GENESIS_HASH, previous),
        )
    events = [
        transition_request(engagement, source, EngagementState.ANALYTICAL_TRIAGE),
        transition_request(engagement, source, EngagementState.REMEDIATION_SYNTHESIS),
    ]
    assert events[0].to_state != events[1].to_state
    app = create_app(database_url=database, redis_url=redis, trusted_public_keys={})
    with TestClient(app) as client:
        before = assert_journal(client, database, engagement, source, [history])
        ready = Barrier(2, timeout=10)

        def post(event: TransitionEvent) -> httpx.Response:
            ready.wait()
            response = client.post(f"/engagements/{engagement}/transition", json=event.model_dump(mode="json"))
            assert isinstance(response, httpx.Response)
            return response

        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(post, events))
        assert sorted(response.status_code for response in responses) == [200, 409], [r.text for r in responses]
        winner, applied = next((event, response) for event, response in zip(events, responses, strict=True)
                               if response.status_code == 200)
        loser, rejected = next((event, response) for event, response in zip(events, responses, strict=True)
                               if response.status_code == 409)
        assert rejected.json()["reason"] == "STATE_MISMATCH"
        records = assert_journal(client, database, engagement, winner.to_state, [history, winner])
        assert records[:-1] == before
        assert records[-1].prev_record_hash == previous
        assert records[-1].event != loser
        assert applied.json() == {
            "status": "applied", "next_state": winner.to_state.value, "ledger_hash": records[-1].record_hash,
        }


def test_manual_reset_requires_signed_human_and_extends_real_stop(urls: tuple[str, str]) -> None:
    database, redis = urls
    engagement = uuid4()
    with psycopg.connect(database) as db:
        db.execute("INSERT INTO engagements (id) VALUES (%s)", (engagement,))
    key = Ed25519PrivateKey.generate()
    app = create_app(database_url=database, redis_url=redis,
                     trusted_public_keys={"scope-reviewer": key.public_key()})
    with TestClient(app) as client:
        locked = transition_request(engagement, EngagementState.INIT_SCOPING, EngagementState.ROE_LOCKED, key)
        assert client.post(f"/engagements/{engagement}/transition", json=locked.model_dump(mode="json")).status_code == 200
        stopped = client.post(f"/engagements/{engagement}/killswitch")
        assert stopped.status_code == 200, stopped.text
        with psycopg.connect(database) as reader:
            prior, stop = read_ledger(reader, engagement, 0)
        assert isinstance(stop.event, TransitionEvent)
        assert stop.event.actor_type == ActorType.SYSTEM
        assert stop.event.actor_id == "orchestrator:killswitch"
        assert stop.event.from_state == EngagementState.ROE_LOCKED
        assert stop.event.to_state == EngagementState.HALTED_KILLSWITCH
        assert stop.record_hash == stopped.json()["ledger_hash"]
        assert stop.prev_record_hash == prior.record_hash
        events = [locked, stop.event]
        before = assert_journal(client, database, engagement, EngagementState.HALTED_KILLSWITCH, events, key)
        reset = transition_request(engagement, EngagementState.HALTED_KILLSWITCH, EngagementState.ROE_LOCKED, key)
        for invalid in (
            reset.model_copy(update={"hitl_signature": None}),
            reset.model_copy(update={"event_id": str(uuid4())}),
            transition_request(engagement, reset.from_state, reset.to_state, key, ActorType.AI_AGENT),
            transition_request(engagement, reset.from_state, reset.to_state, key, ActorType.SYSTEM),
        ):
            denied = client.post(f"/engagements/{engagement}/transition", json=invalid.model_dump(mode="json"))
            assert denied.status_code == 403, denied.text
            assert denied.json()["reason"] == "HUMAN_SIGNATURE_REQUIRED"
            assert assert_journal(client, database, engagement, reset.from_state, events, key) == before
        response = client.post(f"/engagements/{engagement}/transition", json=reset.model_dump(mode="json"))
        assert response.status_code == 200, response.text
        events.append(reset)
        records = assert_journal(client, database, engagement, EngagementState.ROE_LOCKED, events, key)
        assert records[:-1] == before
        assert records[-1].prev_record_hash == stop.record_hash
        assert records[-1].record_hash == response.json()["ledger_hash"]


def test_new_transition_rolls_back_when_journal_insert_fails(urls: tuple[str, str]) -> None:
    database, _ = urls
    engagement = uuid4()
    key = Ed25519PrivateKey.generate()
    event = transition_request(engagement, EngagementState.INIT_SCOPING, EngagementState.ROE_LOCKED, key)
    with psycopg.connect(database, autocommit=True) as db:
        db.execute("INSERT INTO engagements (id) VALUES (%s)", (engagement,))
        # Session-local failure injection leaves the shared append-only table intact.
        db.execute(
            """CREATE TEMP TABLE immutable_audit_log (
                   LIKE public.immutable_audit_log INCLUDING ALL, CHECK (false)
               )"""
        )
        with pytest.raises(psycopg.errors.CheckViolation):
            record_review_transition(db, engagement, event, {event.actor_id: key.public_key()})
        assert get_state(db, engagement) == event.from_state
        assert read_ledger(db, engagement, 0) == []
    with psycopg.connect(database) as reader:
        assert get_state(reader, engagement) == event.from_state
        assert read_ledger(reader, engagement, 0) == []
