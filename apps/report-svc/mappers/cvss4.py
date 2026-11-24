"""CVSS v4.0 scoring, using the FIRST MacroVector algorithm in cvss 3.6."""

from cvss import CVSS4  # type: ignore[import-untyped]
from cvss.constants4 import METRICS  # type: ignore[import-untyped]
from cvss.exceptions import CVSS4Error  # type: ignore[import-untyped]


def score_vector(vector: str) -> float:
    """Score all supplied metric groups; reject vectors outside the v4.0 grammar."""
    try:
        assessment = CVSS4(vector)
    except CVSS4Error as exc:
        raise ValueError("Invalid CVSS v4.0 vector") from exc

    # FIRST specification §7, Table 23. The library checks names, values,
    # duplicates and mandatory metrics but accepts metrics in arbitrary order.
    names = [field.partition(":")[0] for field in vector.split("/")[1:]]
    if names != [metric for metric in METRICS if metric in names]:
        raise ValueError("CVSS v4.0 metrics must appear in specification order")
    return float(assessment.scores()[0])
