from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from signatures import verify_human_signature
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
