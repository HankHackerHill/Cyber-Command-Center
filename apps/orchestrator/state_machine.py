"""Authoritative engagement transition graph and pre-lock signature guards."""

from collections.abc import Mapping
from enum import StrEnum
from re import fullmatch
from uuid import UUID

from contracts.events import EngagementState, TransitionEvent
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from signatures import verify_human_signature


class Reason(StrEnum):
    INVALID_EVENT = "INVALID_EVENT"
    INVALID_MANIFEST = "INVALID_MANIFEST"
    ENGAGEMENT_NOT_FOUND = "ENGAGEMENT_NOT_FOUND"
    ENGAGEMENT_ID_MISMATCH = "ENGAGEMENT_ID_MISMATCH"
    ILLEGAL_TRANSITION = "ILLEGAL_TRANSITION"
    HUMAN_SIGNATURE_REQUIRED = "HUMAN_SIGNATURE_REQUIRED"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    STATE_MISMATCH = "STATE_MISMATCH"
    EVENT_REPLAY = "EVENT_REPLAY"
    PLAN_BINDING_REQUIRED = "PLAN_BINDING_REQUIRED"
    PLAN_NOT_FOUND = "PLAN_NOT_FOUND"
    PLAN_HASH_MISMATCH = "PLAN_HASH_MISMATCH"
    TRANSITION_UNAVAILABLE = "TRANSITION_UNAVAILABLE"


class TransitionDenied(Exception):
    def __init__(self, reason: Reason, status_code: int) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status_code = status_code


HUMAN_ONLY_TARGET_STATES = frozenset({
    EngagementState.ROE_LOCKED,
    EngagementState.CONTROLLED_VALIDATION,
    EngagementState.COMPLETED_ARCHIVED,
})

# Halt edges are dispatched through the idempotent killswitch handler by the API.
ALLOWED_TRANSITIONS = frozenset({
    (EngagementState.INIT_SCOPING, EngagementState.ROE_LOCKED),
    (EngagementState.ROE_LOCKED, EngagementState.DISCOVERY_PASSIVE),
    (EngagementState.DISCOVERY_PASSIVE, EngagementState.ANALYTICAL_TRIAGE),
    (EngagementState.DISCOVERY_PASSIVE, EngagementState.REMEDIATION_SYNTHESIS),
    (EngagementState.ANALYTICAL_TRIAGE, EngagementState.AWAITING_HITL_GATE),
    (EngagementState.ANALYTICAL_TRIAGE, EngagementState.REMEDIATION_SYNTHESIS),
    (EngagementState.AWAITING_HITL_GATE, EngagementState.CONTROLLED_VALIDATION),
    (EngagementState.AWAITING_HITL_GATE, EngagementState.ANALYTICAL_TRIAGE),
    (EngagementState.CONTROLLED_VALIDATION, EngagementState.EVIDENCE_VERIFICATION),
    (EngagementState.EVIDENCE_VERIFICATION, EngagementState.REMEDIATION_SYNTHESIS),
    (EngagementState.EVIDENCE_VERIFICATION, EngagementState.ANALYTICAL_TRIAGE),
    (EngagementState.REMEDIATION_SYNTHESIS, EngagementState.RETEST_VERIFICATION),
    (EngagementState.REMEDIATION_SYNTHESIS, EngagementState.COMPLETED_ARCHIVED),
    (EngagementState.RETEST_VERIFICATION, EngagementState.REMEDIATION_SYNTHESIS),
    (EngagementState.RETEST_VERIFICATION, EngagementState.COMPLETED_ARCHIVED),
    (EngagementState.HALTED_KILLSWITCH, EngagementState.ROE_LOCKED),
}) | frozenset(
    (source, EngagementState.HALTED_KILLSWITCH) for source in EngagementState
)


def parse_engagement_id(text: str) -> UUID:
    if text.startswith("{") and text.endswith("}"):
        text = text[1:-1]
    # PostgreSQL permits a hyphen after each group of four hex digits.
    if not fullmatch(r"(?:[0-9a-fA-F]{4}-?){7}[0-9a-fA-F]{4}", text):
        raise TransitionDenied(Reason.ENGAGEMENT_ID_MISMATCH, 422)
    return UUID(text)


def require_engagement_id(engagement_id: UUID, event: TransitionEvent) -> None:
    if parse_engagement_id(event.engagement_id) != engagement_id:
        raise TransitionDenied(Reason.ENGAGEMENT_ID_MISMATCH, 422)


def require_review_transition(
    event: TransitionEvent,
    trusted_keys: Mapping[str, Ed25519PublicKey],
) -> None:
    """Validate the submitted edge and its signer before acquiring a database lock."""
    source, target = event.from_state, event.to_state
    if (source, target) not in ALLOWED_TRANSITIONS:
        raise TransitionDenied(Reason.ILLEGAL_TRANSITION, 409)
    signature_required = target in HUMAN_ONLY_TARGET_STATES
    if signature_required or event.hitl_signature is not None:
        if not verify_human_signature(event, trusted_keys):
            reason = Reason.HUMAN_SIGNATURE_REQUIRED if signature_required else Reason.INVALID_SIGNATURE
            raise TransitionDenied(reason, 403)
