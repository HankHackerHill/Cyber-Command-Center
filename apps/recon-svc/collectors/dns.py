"""Import supplied passive DNS associations without resolving them."""

from collections import defaultdict
from ipaddress import IPv4Address, IPv6Address
from typing import Literal

from contracts.findings import AssetNode
from pydantic import Field, ValidationInfo, field_validator

from . import Hostname, ReviewedRecord, make_node, normalize_hostname


class DnsRecord(ReviewedRecord):
    hostname: Hostname
    record_type: Literal["A", "AAAA", "CNAME"]
    value: str = Field(min_length=1, max_length=254)

    @field_validator("value")
    @classmethod
    def normalize_value(cls, value: str, info: ValidationInfo) -> str:
        record_type = info.data.get("record_type")
        if record_type == "A":
            return str(IPv4Address(value))
        if record_type == "AAAA":
            if "%" in value:
                raise ValueError("scoped IPv6 addresses are invalid in DNS records")
            return str(IPv6Address(value))
        if record_type == "CNAME":
            return normalize_hostname(value)
        return value  # Pydantic reports the missing or invalid record type.


def collect(engagement_id: str, records: tuple[DnsRecord, ...]) -> list[AssetNode]:
    associations: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for record in records:
        associations[record.hostname].add((record.record_type, record.value))
    return [make_node(engagement_id, "dns_name", name, {
        "source": "dns",
        "records": [{"record_type": kind, "value": value} for kind, value in sorted(associations[name])],
    }) for name in sorted(associations)]
