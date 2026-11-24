import json
from uuid import UUID

import pytest
from pydantic import ValidationError

from contracts import AuditEvent, LedgerRecord, RecordedAuditEvent

ACTOR = {"actor_kind": "SYSTEM", "actor_id": "scoped-proxy", "event_type": "POLICY_DENIED"}
IDS = {
    "event_id": "ebdc5c22-b2fe-49ea-8c93-fcf2b58558e8",
    "engagement_id": "e40ab37e-3b17-48ec-a1e2-1671f9dcdd25",
    "occurred_at": "2026-01-01T01:00:00Z",
}


def test_audit_submission_and_persisted_record_round_trip() -> None:
    submitted = AuditEvent.model_validate(dict(ACTOR, payload={"reason": "SCOPE_DENIED"}))
    row = dict(submitted.model_dump(mode="json"), **IDS)
    stored = RecordedAuditEvent.model_validate(row)
    assert stored.event_id == UUID(IDS["event_id"])
    assert stored.model_dump(mode="json") == row
    ledger = LedgerRecord.model_validate({
        "seq_id": 3, "payload": row, "record_hash": "f" * 64, "prev_record_hash": "e" * 64,
    })
    assert isinstance(ledger.event, RecordedAuditEvent)
    assert ledger.model_dump(mode="json", by_alias=True)["payload"] == row
    assert LedgerRecord.model_validate_json(ledger.model_dump_json(by_alias=True)) == ledger


@pytest.mark.parametrize("field", ["event_id", "engagement_id", "occurred_at", "from_state", "to_state"])
def test_submission_rejects_server_fields_and_state_changes(field: str) -> None:
    with pytest.raises(ValidationError):
        AuditEvent.model_validate(dict(ACTOR, payload={}, **{field: "untrusted"}))


@pytest.mark.parametrize("payload", [
    [], {3: "key"}, {"nested": [{b"key": 1}]}, {"scalar": b"bytes"}, {"tuple": (3,)},
    {"nested": [float("nan")]}, {"nested": [float("inf")]}, {"nested": [float("-inf")]},
    {"bad\x00key": True}, {"nested": [{"bad": "text\x00end"}]}, {"bad": "\ud800"},
])
def test_requires_postgres_compatible_json_object(payload: object) -> None:
    with pytest.raises(ValidationError):
        AuditEvent.model_validate(dict(ACTOR, payload=payload))


@pytest.mark.parametrize("field", ["actor_id", "event_type"])
def test_top_level_text_is_also_jsonb_compatible(field: str) -> None:
    with pytest.raises(ValidationError):
        AuditEvent.model_validate({**ACTOR, field: "bad\x00text", "payload": {}})


def test_jsonb_numeric_normalization_preserves_canonical_event() -> None:
    submitted = {"items": [None, True, "é", -0.0, 3.0, 1e20, 3e-10]}
    persisted = {"items": [None, True, "é", 0, 3, 100000000000000000000, 0.0000000003]}
    before = AuditEvent.model_validate(dict(ACTOR, payload=submitted))
    after = AuditEvent.model_validate(dict(ACTOR, payload=persisted))
    assert before.model_dump_json() == after.model_dump_json()
    canonical = json.dumps(before.model_dump(mode="json"), separators=(",", ":"), ensure_ascii=False)
    assert '[null,true,"é",0,3,100000000000000000000,3e-10]' in canonical
