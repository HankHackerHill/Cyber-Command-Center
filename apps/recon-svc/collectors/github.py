"""Import redacted repository exposure review labels."""

from collections import defaultdict
from typing import Annotated, Literal

from contracts.findings import AssetNode
from pydantic import AfterValidator, StringConstraints

from . import ReviewedRecord, make_node


def _normalize_repository(value: str) -> str:
    if value.partition("/")[2] in {".", ".."}:
        raise ValueError("invalid repository name")
    return value.lower()


class RepositoryRecord(ReviewedRecord):
    repository: Annotated[
        str, StringConstraints(pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9_.-]{1,100}$"),
        AfterValidator(_normalize_repository),
    ]
    indicator: Literal["credential_exposure", "secret_in_history"]


def collect(engagement_id: str, records: tuple[RepositoryRecord, ...]) -> list[AssetNode]:
    review: dict[str, set[str]] = defaultdict(set)
    for record in records:
        review[record.repository].add(record.indicator)
    return [make_node(engagement_id, "repository", slug, {
        "source": "github", "redacted_indicators": [indicator for indicator in sorted(review[slug])],
    }) for slug in sorted(review)]
