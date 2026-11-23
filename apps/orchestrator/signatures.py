"""Verify the attribution of a signed human audit record."""

import json
import logging
import os
from collections.abc import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from contracts.events import ActorType, TransitionEvent


def _decode_keys(entries: list[tuple[str, object]]) -> dict[str, Ed25519PublicKey]:
    keys: dict[str, Ed25519PublicKey] = {}
    for signer, encoded in entries:
        if not signer.strip() or signer in keys:
            raise ValueError("invalid or duplicate signer ID")
        if not isinstance(encoded, str) or len(encoded) != 64:
            raise ValueError("expected a 32-byte public key in hexadecimal")
        keys[signer] = Ed25519PublicKey.from_public_bytes(bytes.fromhex(encoded))
    return keys


def load_operator_public_keys() -> dict[str, Ed25519PublicKey]:
    """Load the operator trust store atomically, defaulting to zero trusted signers."""
    value = os.getenv("ORCHESTRATOR_OPERATOR_PUBLIC_KEYS")
    if value is None:
        return {}
    try:
        keys = json.loads(value, object_pairs_hook=_decode_keys)
        if not isinstance(keys, dict):
            raise ValueError("expected a JSON object")
        return keys
    except (ValueError, RecursionError):
        logging.getLogger(__name__).error(
            "Invalid ORCHESTRATOR_OPERATOR_PUBLIC_KEYS configuration. "
            "Signature verification has no trusted operator keys."
        )
        return {}


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
