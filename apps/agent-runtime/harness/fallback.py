"""Ordered offline model aliases for each agent."""

from collections.abc import Mapping
from types import MappingProxyType


MODEL_CHAINS: Mapping[str, tuple[str, ...]] = MappingProxyType({
    agent: (f"{agent}-primary", f"{agent}-fallback")
    for agent in ("recon", "audit", "triage", "graph", "remediation")
})
