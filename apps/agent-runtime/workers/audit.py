"""Review supplied specifications, configuration summaries and tool schemas."""

from types import MappingProxyType
from typing import Self

from pydantic import BaseModel, ConfigDict, JsonValue, model_validator

from . import Agent, ArtifactInput, ReviewOutput, SkillSpec


class OpenapiAuthzMatrixOutput(ReviewOutput):
    labels = MappingProxyType({
        "missing_auth_requirement": "API specification omits an authorization requirement",
        "inconsistent_auth_policy": "API specification contains inconsistent authorization requirements",
    })


class IamEffectivePermissionsOutput(ReviewOutput):
    labels = MappingProxyType({
        "broad_permission": "Supplied permission summary records broad access",
        "ambiguous_permission": "Supplied permission summary lacks evaluation context",
    })


class IacMisconfigScanOutput(ReviewOutput):
    labels = MappingProxyType({
        "permissive_configuration": "Infrastructure configuration records a permissive control",
        "missing_encryption_control": "Configuration does not document an encryption control",
    })


class JsBundleSecretScanOutput(ReviewOutput):
    labels = MappingProxyType({
        "redacted_secret_indicator": "Bundle analysis records a redacted credential indicator",
        "sensitive_configuration_reference": "Bundle analysis records a sensitive configuration reference",
    })


class ToolSchema(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    fixture_urn: str | None = None
    tool_name: str
    description: str
    parameters: dict[str, JsonValue]
    state_changing: bool
    human_confirmation_required: bool


class LlmToolAuditInput(ArtifactInput):
    @model_validator(mode="after")
    def validate_tool_schemas(self) -> Self:
        for artifact in self.artifacts:
            ToolSchema.model_validate(artifact.data)
        return self


class LlmToolAuditOutput(ReviewOutput):
    labels = MappingProxyType({
        "unvalidated_recipient": "Tool schema does not document tenant allowlist validation for a recipient",
        "excessive_agency": "State-changing tool does not require human confirmation",
        "unbounded_array": "Tool schema contains an array without a maximum item count",
    })


SKILLS = (
    SkillSpec("openapi_authz_matrix", Agent.AUDIT, OpenapiAuthzMatrixOutput),
    SkillSpec("iam_effective_permissions", Agent.AUDIT, IamEffectivePermissionsOutput),
    SkillSpec("iac_misconfig_scan", Agent.AUDIT, IacMisconfigScanOutput),
    SkillSpec("js_bundle_secret_scan", Agent.AUDIT, JsBundleSecretScanOutput),
    SkillSpec("llm_tool_audit", Agent.AUDIT, LlmToolAuditOutput, LlmToolAuditInput),
)
