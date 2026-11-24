"""Summarize supplied graph reports for defensive control review."""

from types import MappingProxyType

from . import Agent, ReviewOutput, SkillSpec


class PathRankOutput(ReviewOutput):
    labels = MappingProxyType({
        "recorded_path_priority": "Graph report records a dependency prioritized for control review",
        "ambiguous_path_evidence": "Graph report lacks evidence supporting its dependency classification",
    })


class Tier0ReachOutput(ReviewOutput):
    labels = MappingProxyType({
        "recorded_tier0_exposure": "Graph report records a Tier-0 dependency for review",
        "incomplete_tier0_inventory": "Graph report records an incomplete Tier-0 inventory",
    })


SKILLS = (
    SkillSpec("path_rank", Agent.GRAPH, PathRankOutput),
    SkillSpec("tier0_reach", Agent.GRAPH, Tier0ReachOutput),
)
