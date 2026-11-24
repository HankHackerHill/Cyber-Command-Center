"""Classify supplied remediation proposals and control evidence."""

from types import MappingProxyType

from . import Agent, ReviewOutput, SkillSpec


class PatchDraftOutput(ReviewOutput):
    labels = MappingProxyType({
        "proposed_control_change": "Supplied proposal identifies a control change for human review",
        "needs_manual_design": "Available remediation evidence requires human design review",
    })


class ComplianceMapOutput(ReviewOutput):
    labels = MappingProxyType({
        "evidence_control_match": "Supplied evidence maps to the stated control requirement",
        "evidence_control_gap": "Supplied evidence leaves a stated control requirement unsupported",
    })


SKILLS = (
    SkillSpec("patch_draft", Agent.REMEDIATION, PatchDraftOutput),
    SkillSpec("compliance_map", Agent.REMEDIATION, ComplianceMapOutput),
)
