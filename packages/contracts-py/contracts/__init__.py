"""MS0 wire contracts. Contract is the root of the generated TypeScript schema."""

from .events import TransitionEvent
from .findings import AssetEdge, AssetNode, AttackChain, Finding
from .ledger import LedgerRecord
from .plans import ValidationPlan
from .roe import Engagement, RoeManifest
from .tasks import WorkflowTask

Contract = (
    Engagement | RoeManifest | TransitionEvent | LedgerRecord | AssetNode | AssetEdge
    | AttackChain | Finding | WorkflowTask | ValidationPlan
)

__all__ = [
    "AssetEdge", "AssetNode", "AttackChain", "Contract", "Engagement", "Finding",
    "LedgerRecord", "RoeManifest", "TransitionEvent", "ValidationPlan", "WorkflowTask",
]
