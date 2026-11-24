"""MS0 wire contracts. Contract is the root of the generated TypeScript schema."""

from .events import AuditEvent, RecordedAuditEvent, TransitionEvent
from .findings import AssetEdge, AssetNode, AttackChain, Finding
from .ledger import LedgerRecord
from .plans import ValidationPlan
from .roe import Engagement, RoeManifest
from .tasks import WorkflowTask

Contract = (
    Engagement | RoeManifest | TransitionEvent | AuditEvent | RecordedAuditEvent | LedgerRecord | AssetNode | AssetEdge
    | AttackChain | Finding | WorkflowTask | ValidationPlan
)

__all__ = [
    "AssetEdge", "AssetNode", "AttackChain", "AuditEvent", "Contract", "Engagement", "Finding",
    "LedgerRecord", "RecordedAuditEvent", "RoeManifest", "TransitionEvent", "ValidationPlan", "WorkflowTask",
]
