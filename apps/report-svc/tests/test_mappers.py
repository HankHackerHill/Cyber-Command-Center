"""Independent score vectors and classification boundaries for M9."""

import pytest

from mappers.cvss4 import score_vector
from mappers.cwe import lookup_cwe
from mappers.frameworks import map_frameworks


BASE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"


# Expected values computed with FIRSTdotorg/cvss-v4-calculator c5b0d409
# (cvss_score.js, cvss_lookup.js, max_composed.js and max_severity.js).
@pytest.mark.parametrize(
    ("suffix", "expected"),
    [
        ("", 8.8),
        ("/E:U", 6.7),
        ("/CR:L/IR:L/AR:L", 7.8),
        ("/E:U/CR:L/IR:L/AR:L", 4.3),
        ("/MSI:S/MSA:S", 9.8),
        ("/S:P/AU:Y/R:I/V:C/RE:H/U:Red", 8.8),
        ("/E:X/CR:X/IR:X/AR:X", 8.8),
    ],
)
def test_cvss4_metric_groups(suffix: str, expected: float) -> None:
    assert score_vector(BASE + suffix) == expected


def test_cvss4_zero_impact() -> None:
    assert score_vector(BASE.replace("/VC:H/VI:L/", "/VC:N/VI:N/")) == 0.0


def test_decimal_half_tie_rounds_up() -> None:
    # RedHatProductSecurity/cvss-v4-calculator b0930b7, roundToDecimalPlaces.
    # Binary subtraction can represent the exact 5.95 intermediate just below the tie.
    vector = "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:N/VC:N/VI:H/VA:L/SC:N/SI:N/SA:L/CR:L/AU:Y"
    assert score_vector(vector) == 6.0


@pytest.mark.parametrize(
    "vector",
    [
        BASE.replace("4.0", "3.1"),
        BASE.replace("/AT:N", ""),
        BASE.replace("/AV:N", "/AV:X"),
        BASE.replace("/AV:N/AC:L", "/AC:L/AV:N"),
        BASE + "/E:U/E:A",
        BASE + "/UNKNOWN:A",
        BASE + "/",
    ],
)
def test_malformed_vectors_are_rejected(vector: str) -> None:
    with pytest.raises(ValueError, match="CVSS v4.0"):
        score_vector(vector)


def test_weakness_catalog_and_control_associations() -> None:
    assert lookup_cwe("CWE-862") == "Missing Authorization"
    assert map_frameworks("CWE-862") == (
        "SOC 2 (2017 TSC) CC6.3", "ISO/IEC 27001:2022 A.8.3", "PCI DSS v4.0.1 7.2",
    )
    assert map_frameworks("CWE-89") == (
        "SOC 2 (2017 TSC) CC8.1", "ISO/IEC 27001:2022 A.8.28", "PCI DSS v4.0.1 6.2.4",
    )


def test_no_invented_mapping_for_unmapped_or_unknown_weakness() -> None:
    assert lookup_cwe("CWE-676") == "Use of Potentially Dangerous Function"
    assert map_frameworks("CWE-676") == ()
    for identifier in ("CWE-1000", "CWE-999999", "89", "possible SQL injection"):
        assert lookup_cwe(identifier) is None
        assert map_frameworks(identifier) == ()
