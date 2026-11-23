import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from contracts.roe import Engagement, RoeManifest, ScopeBoundaries, ValidWindow


FIXTURE = Path(__file__).resolve().parents[3] / "tests/fixtures/roe_sample.json"


def test_roe_fixture_round_trip() -> None:
    raw = FIXTURE.read_bytes()
    manifest = RoeManifest.model_validate_json(raw)
    assert manifest.model_dump(mode="json") == json.loads(raw)


@pytest.mark.parametrize(
    "start,end",
    [
        ("2026-12-01T08:00:00", "2026-12-12T22:00:00Z"),
        ("2026-12-01T08:00:00Z", "2026-12-12T22:00:00"),
        ("2026-12-01T08:00:00Z", "2026-12-01T08:00:00Z"),
        ("2026-12-02T08:00:00Z", "2026-12-01T08:00:00Z"),
    ],
)
def test_window_rejects_ambiguous_or_empty_interval(start: str, end: str) -> None:
    with pytest.raises(ValidationError):
        ValidWindow.model_validate(
            {"not_before": start, "not_after": end, "allowed_days_utc": ["MON"]}
        )


def test_invalid_cidr_rejected() -> None:
    scope = json.loads(FIXTURE.read_bytes())["scope_boundaries"]
    scope["allowed_cidrs"] = ["198.51.100.0/33"]
    with pytest.raises(ValidationError):
        ScopeBoundaries.model_validate(scope)


def test_rejects_manifest_for_another_engagement() -> None:
    manifest = RoeManifest.model_validate_json(FIXTURE.read_bytes())
    with pytest.raises(ValidationError, match="another engagement"):
        Engagement(id=manifest.engagement_id + "-other", roe_manifest=manifest)
