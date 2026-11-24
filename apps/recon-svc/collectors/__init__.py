"""Normalize bounded, operator-supplied public-data review records.

Collectors operate on data already in hand. Names and addresses in a record
are identifiers, never instructions to resolve or contact a destination.
"""

from collections.abc import Callable
from enum import StrEnum
import json
import re
from typing import Annotated, Generic, TypeVar
from uuid import NAMESPACE_URL, UUID, uuid5

from contracts.events import ActorType
from contracts.findings import AssetNode
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, JsonValue, StringConstraints


MAX_RECORDS = 256
MAX_BODY_BYTES = 131_072


class Source(StrEnum):
    CT = "ct"
    DNS = "dns"
    GITHUB = "github"
    SHODAN = "shodan"
    STORAGE_NAMES = "storage_names"


class ReviewedRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


Record = TypeVar("Record", bound=ReviewedRecord)
AssetReference = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_-]{0,63}$")]
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)


def normalize_hostname(value: str) -> str:
    if not value.isascii():
        raise ValueError("hostname must use ASCII DNS labels")
    name = value.removesuffix(".").lower()
    labels = name.split(".")
    if (len(name) > 253 or len(labels) < 2 or labels[-1].isdigit()
            or any(not _HOST_LABEL.fullmatch(label) for label in labels)):
        raise ValueError("invalid DNS hostname")
    return name


Hostname = Annotated[str, StringConstraints(max_length=254), AfterValidator(normalize_hostname)]


def canonical_engagement_id(value: str) -> str:
    try:
        return str(UUID(value))
    except ValueError:
        # The frozen contract also supports opaque engagement IDs.
        return value


EngagementId = Annotated[
    str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$"),
    AfterValidator(canonical_engagement_id),
]


class ImportBatch(ReviewedRecord, Generic[Record]):
    engagement_id: EngagementId
    records: tuple[Record, ...] = Field(max_length=MAX_RECORDS)


def make_node(engagement_id: str, category: str, identifier: str, metadata: dict[str, JsonValue]) -> AssetNode:
    identity = json.dumps(["redops:asset_node:v1", engagement_id, category, identifier], separators=(",", ":"))
    return AssetNode(id=uuid5(NAMESPACE_URL, identity), engagement_id=engagement_id,
                     asset_category=category, canonical_identifier=identifier,
                     metadata=metadata, discovered_by=ActorType.SYSTEM)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    fields: dict[str, object] = {}
    for key, value in pairs:
        if key in fields:
            raise ValueError("duplicate JSON field")
        fields[key] = value
    return fields


def _invalid_constant(_: str) -> None:
    raise ValueError("nonfinite JSON value")


def _reader(
    schema: type[ImportBatch[Record]], collector: Callable[[str, tuple[Record, ...]], list[AssetNode]],
) -> Callable[[bytes], list[AssetNode]]:
    def read(body: bytes) -> list[AssetNode]:
        batch = schema.model_validate_json(body)
        return collector(batch.engagement_id, batch.records)

    return read


from . import ct, dns, github, shodan, storage_names

_READERS = {
    Source.CT: _reader(ImportBatch[ct.CertificateRecord], ct.collect),
    Source.DNS: _reader(ImportBatch[dns.DnsRecord], dns.collect),
    Source.GITHUB: _reader(ImportBatch[github.RepositoryRecord], github.collect),
    Source.SHODAN: _reader(ImportBatch[shodan.ExposureRecord], shodan.collect),
    Source.STORAGE_NAMES: _reader(ImportBatch[storage_names.NamingRecord], storage_names.collect),
}


def import_records(source: Source, body: bytes) -> list[AssetNode]:
    """Validate a reviewed export and return its canonical asset nodes."""
    if len(body) > MAX_BODY_BYTES:
        raise ValueError("review batch exceeds byte bound")
    # Reject ambiguous JSON before validating the source-specific frozen schema.
    try:
        json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except RecursionError as exc:
        raise ValueError("review batch exceeds JSON depth limit") from exc
    return _READERS[source](body)
