"""Transition guards for evidence review, remediation, and signed closure."""

from collections.abc import Mapping
from enum import StrEnum
from re import fullmatch
from uuid import UUID

from contracts.events import EngagementState, TransitionEvent
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from signatures import verify_human_signature


class Reason(StrEnum):
    INVALID_EVENT = "INVALID_EVENT"
    ENGAGEMENT_NOT_FOUND = "ENGAGEMENT_NOT_FOUND"
    ENGAGEMENT_ID_MISMATCH = "ENGAGEMENT_ID_MISMATCH"
    ILLEGAL_TRANSITION = "ILLEGAL_TRANSITION"
    HUMAN_SIGNATURE_REQUIRED = "HUMAN_SIGNATURE_REQUIRED"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    STATE_MISMATCH = "STATE_MISMATCH"
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

REVIEW_SOURCES = {
    EngagementState.EVIDENCE_VERIFICATION: frozenset({EngagementState.CONTROLLED_VALIDATION}),
    EngagementState.REMEDIATION_SYNTHESIS: frozenset({
        EngagementState.DISCOVERY_PASSIVE,
        EngagementState.ANALYTICAL_TRIAGE,
        EngagementState.EVIDENCE_VERIFICATION,
        EngagementState.RETEST_VERIFICATION,
    }),
    EngagementState.COMPLETED_ARCHIVED: frozenset({
        EngagementState.REMEDIATION_SYNTHESIS,
        EngagementState.RETEST_VERIFICATION,
    }),
}


def require_engagement_id(engagement_id: UUID, event: TransitionEvent) -> None:
    text = event.engagement_id
    if text.startswith("{") and text.endswith("}"):
        text = text[1:-1]
    # PostgreSQL permits a hyphen after each group of four hex digits.
    if not fullmatch(r"(?:[0-9a-fA-F]{4}-?){7}[0-9a-fA-F]{4}", text) or UUID(text) != engagement_id:
        raise TransitionDenied(Reason.ENGAGEMENT_ID_MISMATCH, 422)


def require_review_transition(
    event: TransitionEvent,
    trusted_keys: Mapping[str, Ed25519PublicKey],
) -> None:
    """Validate the submitted edge and its signer before acquiring a database lock."""
    source, target = event.from_state, event.to_state
    permitted_sources = REVIEW_SOURCES.get(target)
    if (
        target == source or target == EngagementState.INIT_SCOPING
        or source == EngagementState.COMPLETED_ARCHIVED
        or (source == EngagementState.HALTED_KILLSWITCH and target != EngagementState.ROE_LOCKED)
        or (target == EngagementState.CONTROLLED_VALIDATION and source != EngagementState.AWAITING_HITL_GATE)
        or (permitted_sources is not None and source not in permitted_sources)
    ):
        raise TransitionDenied(Reason.ILLEGAL_TRANSITION, 409)
    signature_required = target in HUMAN_ONLY_TARGET_STATES
    if signature_required or event.hitl_signature is not None:
        if not verify_human_signature(event, trusted_keys):
            reason = Reason.HUMAN_SIGNATURE_REQUIRED if signature_required else Reason.INVALID_SIGNATURE
            raise TransitionDenied(reason, 403)
    if permitted_sources is None:
        raise TransitionDenied(Reason.TRANSITION_UNAVAILABLE, 403)
