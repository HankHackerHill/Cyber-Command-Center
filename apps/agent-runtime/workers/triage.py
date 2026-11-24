"""Summarize existing evidence for defensive triage."""

from types import MappingProxyType

from . import Agent, ReviewOutput, SkillSpec


class ScannerDedupeOutput(ReviewOutput):
    labels = MappingProxyType({
        "duplicate_observations": "Supplied observations describe the same control issue",
        "distinct_observations": "Supplied observations describe distinct control issues",
    })


class WeaknessChainOutput(ReviewOutput):
    labels = MappingProxyType({
        "related_control_gaps": "Supplied observations record related control gaps",
        "insufficient_correlation": "Supplied observations do not establish a control relationship",
    })


class ConfidenceScoreOutput(ReviewOutput):
    labels = MappingProxyType({
        "supported_hypothesis": "Supplied evidence supports a hypothesis for human review",
        "insufficient_evidence": "Supplied evidence is insufficient to support the hypothesis",
    })


SKILLS = (
    SkillSpec("scanner_dedupe", Agent.TRIAGE, ScannerDedupeOutput),
    SkillSpec("weakness_chain", Agent.TRIAGE, WeaknessChainOutput),
    SkillSpec("confidence_score", Agent.TRIAGE, ConfidenceScoreOutput),
)
