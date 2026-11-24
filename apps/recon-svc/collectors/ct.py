"""Import reviewed certificate transparency hostname associations."""

from collections import defaultdict
from typing import Annotated

from contracts.findings import AssetNode
from pydantic import AfterValidator, StringConstraints

from . import Hostname, ReviewedRecord, make_node


class CertificateRecord(ReviewedRecord):
    hostname: Hostname
    certificate_sha256: Annotated[
        str, StringConstraints(pattern=r"^[0-9a-fA-F]{64}$"), AfterValidator(str.lower),
    ]


def collect(engagement_id: str, records: tuple[CertificateRecord, ...]) -> list[AssetNode]:
    fingerprints: dict[str, set[str]] = defaultdict(set)
    for record in records:
        fingerprints[record.hostname].add(record.certificate_sha256)
    return [make_node(engagement_id, "dns_name", name, {
        "source": "ct", "certificate_sha256": [digest for digest in sorted(fingerprints[name])],
    }) for name in sorted(fingerprints)]
