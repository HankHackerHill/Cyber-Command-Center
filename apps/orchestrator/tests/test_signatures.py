import json
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from signatures import load_operator_public_keys, verify_human_signature
from contracts.events import ActorType, Ed25519Signature, EngagementState, TransitionEvent


def signed_record(
    key: Ed25519PrivateKey,
    *,
    actor_type: ActorType = ActorType.HUMAN_OPERATOR,
    signer_id: str = "op-A",
) -> TransitionEvent:
    event = TransitionEvent(
        event_id="evt-1",
        engagement_id="eng-1",
        from_state=EngagementState.INIT_SCOPING,
        to_state=EngagementState.ROE_LOCKED,
        actor_type=actor_type,
        actor_id="op-A",
        occurred_at=datetime(2026, 12, 1, 9, tzinfo=timezone.utc),
    )
    signature = Ed25519Signature(
        signer_id=signer_id, signature=key.sign(event.canonical_envelope()).hex()
    )
    return event.model_copy(update={"hitl_signature": signature})


def test_signature_requires_the_trusted_key_for_the_actor() -> None:
    key = Ed25519PrivateKey.generate()
    event = signed_record(key)
    keys = {event.actor_id: key.public_key()}
    restored = TransitionEvent.model_validate_json(event.model_dump_json())
    assert verify_human_signature(restored, keys)
    assert not verify_human_signature(event, {})
    assert not verify_human_signature(event, {event.actor_id: Ed25519PrivateKey.generate().public_key()})
    assert not verify_human_signature(event.model_copy(update={"hitl_signature": None}), keys)


def test_rejects_one_byte_tamper() -> None:
    key = Ed25519PrivateKey.generate()
    event = signed_record(key)
    altered = event.model_copy(update={"event_id": "evt-2"})
    before, after = event.canonical_envelope(), altered.canonical_envelope()
    assert sum(left != right for left, right in zip(before, after, strict=True)) == 1
    assert not verify_human_signature(altered, {event.actor_id: key.public_key()})


def test_rejects_signature_attributed_to_another_signer() -> None:
    key = Ed25519PrivateKey.generate()
    event = signed_record(key, signer_id="op-B")
    assert not verify_human_signature(event, {"op-A": key.public_key(), "op-B": key.public_key()})


@pytest.mark.parametrize("actor_type", [ActorType.SYSTEM, ActorType.AI_AGENT])
def test_only_human_records_qualify(actor_type: ActorType) -> None:
    key = Ed25519PrivateKey.generate()
    event = signed_record(key, actor_type=actor_type)
    assert not verify_human_signature(event, {event.actor_id: key.public_key()})


def test_public_keys_are_optional(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ORCHESTRATOR_OPERATOR_PUBLIC_KEYS", raising=False)
    assert load_operator_public_keys() == {}


def test_loads_operator_public_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    key = Ed25519PrivateKey.generate()
    second = Ed25519PrivateKey.generate().public_key()
    monkeypatch.setenv("ORCHESTRATOR_OPERATOR_PUBLIC_KEYS", json.dumps({
        "op-A": key.public_key().public_bytes_raw().hex().upper(),
        "op-B": second.public_bytes_raw().hex(),
    }))
    keys = load_operator_public_keys()
    assert keys["op-B"] == second
    assert verify_human_signature(signed_record(key), keys)


@pytest.mark.parametrize("value", [
    "", "[]", "invalid-json", '{"op-A": null}',
    json.dumps({"op-A": "11" * 31}), json.dumps({"op-A": "xx" * 32}),
    json.dumps({"": "22" * 32}), json.dumps({"op-A": "11" * 32, "op-B": "short"}),
    '{"op-A":"' + "11" * 32 + '","op-A":"' + "22" * 32 + '"}',
])
def test_invalid_trust_store_fails_closed(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, value: str,
) -> None:
    monkeypatch.setenv("ORCHESTRATOR_OPERATOR_PUBLIC_KEYS", value)
    assert load_operator_public_keys() == {}
    assert caplog.messages == [
        "Invalid ORCHESTRATOR_OPERATOR_PUBLIC_KEYS configuration. "
        "Signature verification has no trusted operator keys."
    ]
