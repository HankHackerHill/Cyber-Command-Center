"""Import defensive exposure scores for opaque inventory references."""

from typing import Literal

from contracts.findings import AssetNode
from pydantic import Field

from . import AssetReference, ReviewedRecord, make_node


Severity = Literal["low", "medium", "high"]
_SEVERITY = {"low": 0, "medium": 1, "high": 2}


class ExposureRecord(ReviewedRecord):
    asset_ref: AssetReference
    severity: Severity
    observation_count: int = Field(ge=1, le=1_000_000)


def _priority(record: ExposureRecord) -> tuple[int, int]:
    return _SEVERITY[record.severity], record.observation_count


def collect(engagement_id: str, records: tuple[ExposureRecord, ...]) -> list[AssetNode]:
    reviews: dict[str, ExposureRecord] = {}
    for record in records:
        prior = reviews.get(record.asset_ref)
        if prior is None or _priority(record) > _priority(prior):
            reviews[record.asset_ref] = record
    ordered = sorted(reviews.values(), key=lambda record: (-_SEVERITY[record.severity], record.asset_ref))
    return [make_node(engagement_id, "exposure_review", record.asset_ref, {
        "source": "shodan", "severity": record.severity, "observation_count": record.observation_count,
    }) for record in ordered]
