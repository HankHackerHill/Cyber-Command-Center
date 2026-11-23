"""A persisted transition plus its position and links in the audit ledger."""

from pydantic import BaseModel, ConfigDict, Field

from .events import TransitionEvent
from .roe import Sha256Hex


class LedgerRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    seq_id: int = Field(gt=0)
    event: TransitionEvent
    prev_record_hash: Sha256Hex
    record_hash: Sha256Hex
