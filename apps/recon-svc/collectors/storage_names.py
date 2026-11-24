"""Import known naming-convention observations from reviewed inventory."""

from collections import defaultdict
from typing import Literal

from contracts.findings import AssetNode

from . import AssetReference, ReviewedRecord, make_node


class NamingRecord(ReviewedRecord):
    asset_ref: AssetReference
    provider: Literal["aws", "azure", "gcp"]
    naming_pattern: Literal["environment", "service", "team", "other"]


def collect(engagement_id: str, records: tuple[NamingRecord, ...]) -> list[AssetNode]:
    reviews: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for record in records:
        reviews[record.asset_ref].add((record.provider, record.naming_pattern))
    return [make_node(engagement_id, "storage_review", ref, {
        "source": "storage_names",
        "observations": [{"provider": provider, "naming_pattern": pattern}
                         for provider, pattern in sorted(reviews[ref])],
    }) for ref in sorted(reviews)]
