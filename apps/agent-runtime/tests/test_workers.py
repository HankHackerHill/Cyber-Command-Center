"""Authority and provenance checks for offline worker payloads."""

import json

from pydantic import ValidationError
import pytest

from workers import ArtifactInput, SKILLS


def test_output_has_only_fixed_observations_and_binds_supplied_evidence() -> None:
    spec = SKILLS["openapi_authz_matrix"]
    supplied = spec.input_model.model_validate_json(
        '{"artifacts":[{"ref":"api_review","data":{"security":[]}}]}'
    )
    entry = {
        "evidence_ref": "api_review",
        "code": "missing_auth_requirement",
        "confidence_score": 0.94,
    }
    output = spec.output_model.model_validate_json(json.dumps({"findings": [entry]}))
    spec.validate_evidence(supplied, output)
    assert spec.labels[output.findings[0].code] == (
        "API specification omits an authorization requirement"
    )
    with pytest.raises(ValidationError, match="frozen_instance"):
        setattr(output.findings[0], "evidence_ref", "changed")
    for supplied_extra in (
        {"status": "CONFIRMED"},
        {"approver_sig": "fake"},
        {"execution": {"method": "POST"}},
        {"title": "uncurated model output"},
    ):
        with pytest.raises(ValidationError, match="extra_forbidden"):
            spec.output_model.model_validate_json(
                json.dumps({"findings": [dict(entry, **supplied_extra)]})
            )
    with pytest.raises(ValidationError, match="unsupported observation code"):
        spec.output_model.model_validate_json(
            json.dumps({"findings": [dict(entry, code="related_control_gaps")]})
        )
    with pytest.raises(ValidationError, match="duplicate observation"):
        spec.output_model.model_validate_json(json.dumps({"findings": [entry, entry]}))
    unbound = spec.output_model.model_validate_json(
        json.dumps({"findings": [dict(entry, evidence_ref="removed_by_pruning")]})
    )
    with pytest.raises(ValueError, match="outside the supplied input"):
        spec.validate_evidence(supplied, unbound)


@pytest.mark.parametrize("payload", [
    {"artifacts": [{"ref": "dup", "data": {}}, {"ref": "dup", "data": {}}]},
    {"artifacts": [{"ref": "../fixture", "data": {}}]},
    {"artifacts": [{"ref": "test", "data": {"wide": "x" * (65 * 1024)}}]},
    {"artifacts": [{"ref": "test", "data": {"nonfinite": float("inf")}}]},
])
def test_invalid_artifact_payload_cannot_enter_context(payload: object) -> None:
    with pytest.raises(ValidationError):
        ArtifactInput.model_validate_json(json.dumps(payload))


def test_llm_tool_schema_input_rejects_answer_key() -> None:
    spec = SKILLS["llm_tool_audit"]
    payload = {
        "artifacts": [{
            "ref": "test_tool",
            "data": {
                "tool_name": "record_review",
                "description": "Creates a review record",
                "parameters": {"type": "object"},
                "state_changing": True,
                "human_confirmation_required": True,
                "expected_agent_flags": ["test-only"],
            },
        }],
    }
    with pytest.raises(ValidationError, match="expected_agent_flags"):
        spec.input_model.model_validate_json(json.dumps(payload))
