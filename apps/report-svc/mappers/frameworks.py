"""Candidate control associations for assessor review.

Associations identify where a control owner can look for relevant evidence. PCI
DSS applicability depends on the assessed payment environment, the data involved,
and whether the affected software is bespoke. No association determines a
compliance result. The labels reference the 2017 AICPA Trust Services Criteria
(revised points of focus 2022), ISO/IEC 27001:2022 Annex A, and PCI DSS v4.0.1.
"""

from typing import Final


def _controls(soc: str, iso: str, pci: str) -> tuple[str, ...]:
    return (
        f"SOC 2 (2017 TSC) {soc}",
        f"ISO/IEC 27001:2022 A.{iso}",
        f"PCI DSS v4.0.1 {pci}",
    )


# Versioned assessment crosswalk. Keys represent CWE definitions that a reviewer
# has mapped explicitly. Unknown classifications have no inferred controls.
_SECURE_DEVELOPMENT: Final = _controls("CC8.1", "8.28", "6.2.4")
_AUTHORIZATION: Final = _controls("CC6.3", "8.3", "7.2")
_AUTHENTICATION: Final = _controls("CC6.1", "8.5", "8.3")
_CREDENTIALS: Final = _controls("CC6.1", "5.17", "8.6")
_TRANSIT: Final = _controls("CC6.7", "8.24", "4.2.1")
_STORAGE: Final = _controls("CC6.1", "8.24", "3.5.1")
_LOGGING: Final = _controls("CC7.2", "8.15", "10.2")

_CROSSWALK: Final[dict[str, tuple[str, ...]]] = {
    "CWE-20": _SECURE_DEVELOPMENT,
    "CWE-22": _SECURE_DEVELOPMENT,
    "CWE-78": _SECURE_DEVELOPMENT,
    "CWE-79": _SECURE_DEVELOPMENT,
    "CWE-89": _SECURE_DEVELOPMENT,
    "CWE-94": _SECURE_DEVELOPMENT,
    "CWE-117": _LOGGING,
    "CWE-119": _SECURE_DEVELOPMENT,
    "CWE-120": _SECURE_DEVELOPMENT,
    "CWE-125": _SECURE_DEVELOPMENT,
    "CWE-259": _CREDENTIALS,
    "CWE-269": _AUTHORIZATION,
    "CWE-276": _AUTHORIZATION,
    "CWE-284": _AUTHORIZATION,
    "CWE-285": _AUTHORIZATION,
    "CWE-287": _AUTHENTICATION,
    "CWE-295": _TRANSIT,
    "CWE-306": _AUTHENTICATION,
    "CWE-312": _STORAGE,
    "CWE-319": _TRANSIT,
    "CWE-352": _SECURE_DEVELOPMENT,
    "CWE-416": _SECURE_DEVELOPMENT,
    "CWE-434": _SECURE_DEVELOPMENT,
    "CWE-502": _SECURE_DEVELOPMENT,
    "CWE-613": _AUTHENTICATION,
    "CWE-639": _AUTHORIZATION,
    "CWE-732": _AUTHORIZATION,
    "CWE-778": _LOGGING,
    "CWE-787": _SECURE_DEVELOPMENT,
    "CWE-798": _CREDENTIALS,
    "CWE-862": _AUTHORIZATION,
    "CWE-863": _AUTHORIZATION,
    "CWE-918": _SECURE_DEVELOPMENT,
}


def map_frameworks(identifier: str) -> tuple[str, ...]:
    """Return associated control references in SOC 2, ISO, PCI order."""
    return _CROSSWALK.get(identifier, ())
