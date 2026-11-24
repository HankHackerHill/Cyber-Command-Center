"""A persisted transition plus its position and links in the audit ledger."""

from pydantic import AliasChoices, BaseModel, ConfigDict, Field

from .events import TransitionEvent
from .roe import Sha256Hex


class LedgerRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    seq_id: int = Field(gt=0)
    event: TransitionEvent = Field(
        validation_alias=AliasChoices("event", "payload"), serialization_alias="payload"
    )
    prev_record_hash: Sha256Hex
    record_hash: Sha256Hex
