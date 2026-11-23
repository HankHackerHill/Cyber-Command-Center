"""Verify the attribution of a signed human audit record."""

from collections.abc import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from contracts.events import ActorType, TransitionEvent


def verify_human_signature(
    event: TransitionEvent,
    trusted_public_keys: Mapping[str, Ed25519PublicKey],
) -> bool:
    signature = event.hitl_signature
    if event.actor_type != ActorType.HUMAN_OPERATOR or signature is None:
        return False
    if signature.signer_id != event.actor_id:
        return False
    key = trusted_public_keys.get(event.actor_id)
    if key is None:
        return False
    try:
        key.verify(bytes.fromhex(signature.signature), event.canonical_envelope())
    except (InvalidSignature, ValueError):
        return False
    return True
