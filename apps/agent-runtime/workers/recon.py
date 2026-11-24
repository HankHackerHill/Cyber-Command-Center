"""Review supplied discovery exports and redacted inventory evidence."""

from types import MappingProxyType

from . import Agent, ReviewOutput, SkillSpec


class CtLogCorrelateOutput(ReviewOutput):
    labels = MappingProxyType({
        "public_certificate_observed": "Export contains a certificate inventory match",
        "unmatched_certificate": "Export contains an unmatched certificate inventory record",
    })


class DnsPassiveMapOutput(ReviewOutput):
    labels = MappingProxyType({
        "dns_inventory_observed": "Archived DNS observation matches the asset inventory",
        "conflicting_dns_observation": "Archived DNS observations disagree",
    })


class GithubSecretScanOutput(ReviewOutput):
    labels = MappingProxyType({
        "redacted_secret_indicator": "Repository export contains a redacted secret indicator",
        "uncertain_secret_indicator": "Repository export contains an uncertain credential indicator",
    })


class ShodanSurfaceRankOutput(ReviewOutput):
    labels = MappingProxyType({
        "exposed_service_observation": "Supplied inventory records a publicly visible service",
        "stale_surface_observation": "Supplied service visibility record is stale",
    })


SKILLS = (
    SkillSpec("ct_log_correlate", Agent.RECON, CtLogCorrelateOutput),
    SkillSpec("dns_passive_map", Agent.RECON, DnsPassiveMapOutput),
    SkillSpec("github_secret_scan", Agent.RECON, GithubSecretScanOutput),
    SkillSpec("shodan_surface_rank", Agent.RECON, ShodanSurfaceRankOutput),
)
