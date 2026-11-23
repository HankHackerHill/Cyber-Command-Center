import json

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from contracts.events import ActorType, Ed25519Signature, EngagementState, TransitionEvent
from contracts.plans import BlastRadius, ValidationPlan


UNSIGNED = {
    "event_id": "event-001",
    "engagement_id": "eng_9f82a1c4",
    "from_state": "INIT_SCOPING",
    "to_state": "ROE_LOCKED",
    "actor_type": "HUMAN_OPERATOR",
    "actor_id": "op-É",
    "occurred_at": "2026-12-01T08:00:00Z",
}
ENVELOPE = (
    '{"actor_id":"op-É","actor_type":"HUMAN_OPERATOR","engagement_id":"eng_9f82a1c4",'
    '"event_id":"event-001","from_state":"INIT_SCOPING","occurred_at":"2026-12-01T08:00:00Z",'
    '"to_state":"ROE_LOCKED"}'
).encode("utf-8")


def test_signed_envelope_round_trip() -> None:
    event = TransitionEvent.model_validate(UNSIGNED)
    assert event.canonical_envelope() == ENVELOPE
    key = Ed25519PrivateKey.generate()
    signature = Ed25519Signature(signer_id=event.actor_id, signature=key.sign(ENVELOPE).hex())
    signed = event.model_copy(update={"hitl_signature": signature})
    restored = TransitionEvent.model_validate_json(signed.model_dump_json())
    assert restored.hitl_signature == signature
    assert restored.canonical_envelope() == ENVELOPE
    key.public_key().verify(bytes.fromhex(signature.signature), restored.canonical_envelope())
    assert json.loads(ENVELOPE) == restored.model_dump(mode="json", exclude={"hitl_signature"})


def test_each_unsigned_field_is_bound_by_signature() -> None:
    alternatives = {
        "event_id": "event-002",
        "engagement_id": "eng-002",
        "from_state": EngagementState.HALTED_KILLSWITCH,
        "to_state": EngagementState.DISCOVERY_PASSIVE,
        "actor_type": ActorType.AI_AGENT,
        "actor_id": "op-B",
        "occurred_at": "2026-12-01T08:00:01Z",
    }
    assert alternatives.keys() == TransitionEvent.model_fields.keys() - {"hitl_signature"}
    key = Ed25519PrivateKey.generate()
    signature = key.sign(ENVELOPE)
    for field, replacement in alternatives.items():
        tampered = TransitionEvent.model_validate({**UNSIGNED, field: replacement})
        payload = tampered.canonical_envelope()
        assert payload != ENVELOPE, field
        with pytest.raises(InvalidSignature):
            key.public_key().verify(signature, payload)


def test_destructive_plan_requires_independent_approvals() -> None:
    plan = {
        "id": "plan-001",
        "engagement_id": "eng_9f82a1c4",
        "blast_radius": BlastRadius.DESTRUCTIVE,
    }
    first = Ed25519Signature(
        signer_id="op-A", signature=Ed25519PrivateKey.generate().sign(b"plan-001").hex()
    )
    second = Ed25519Signature(
        signer_id="op-B", signature=Ed25519PrivateKey.generate().sign(b"plan-001").hex()
    )
    same_operator = second.model_copy(update={"signer_id": first.signer_id})
    copied_signature = second.model_copy(update={"signature": first.signature})
    for approvals in (
        {},
        {"approver_sig": first},
        {"second_approver_sig": second},
        {"approver_sig": first, "second_approver_sig": same_operator},
        {"approver_sig": first, "second_approver_sig": copied_signature},
    ):
        with pytest.raises(ValidationError, match="destructive plans require"):
            ValidationPlan.model_validate({**plan, **approvals})
    approved = ValidationPlan.model_validate(
        {**plan, "approver_sig": first, "second_approver_sig": second}
    )
    assert approved.second_approver_sig == second
