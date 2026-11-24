"""Verify what a report reader receives in both document formats."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from dataclasses import replace
from io import BytesIO
from pathlib import Path
from uuid import UUID
from xml.etree import ElementTree as ET
from zipfile import ZipFile

import pytest
from pypdf import PdfReader

from render import NarrativeHop, ReportChain, ReportData, ReportFinding, Section, render_report

WORD_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
ARTIFACT = "/artifacts/" + "ae" * 32
SECOND_ARTIFACT = "/artifacts/" + "b4" * 32
OWNER = "d01269c1-1180-454b-b41e-499db0484bbc"
VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
ENTRY = UUID("11111111-1111-4111-8111-111111111111")
INTERMEDIATE = UUID("22222222-2222-4222-8222-222222222222")
TERMINAL = UUID("33333333-3333-4333-8333-333333333333")


def example_report() -> ReportData:
    return ReportData(
        engagement_id=OWNER,
        manifest_hash="12" * 32,
        roe_signature_hash="34" * 32,
        manifest_json='{"scope":"read-only review"}',
        ledger_excerpt_json='[{"event_id":"scope-locked-31","seq_id":31}]',
        teardown_receipt_json='{"receipt_id":"cleanup-581","result":"complete"}',
        findings=(
            ReportFinding(
                id="OBS-001", title="Missing audit entries", status="CONFIRMED",
                cvss_vector=VECTOR, cvss_score=10.0, cwe="CWE-778",
                framework_mappings=("SOC 2 CC7.2",),
                evidence_links=(ARTIFACT,),
                reproduction_steps=("Compare the approved sample with the audit export.",),
                remediation="Enable audit logging and verify the retention policy.",
            ),
            ReportFinding(
                id="OBS-002", title="Retention setting reviewed", status="FALSE_POSITIVE",
            ),
        ),
        attack_narratives=("The inventory and audit export identify the same reviewed asset.",),
    )


def example_chain_report() -> ReportData:
    data = example_report()
    first = replace(data.findings[0], cwe="CWE-778 — Insufficient Logging")
    second = replace(data.findings[1], evidence_links=(SECOND_ARTIFACT,))
    return replace(data, findings=(first, second), chains=(ReportChain(
        id="reviewed-chain-01",
        hops=(NarrativeHop(first, "Compared archived audit records.", ENTRY, INTERMEDIATE),
              NarrativeHop(second, None, INTERMEDIATE, TERMINAL)),
        impact_summary="The audit record is incomplete.", tier0_reached=True, path_cost=3.5,
        operator_override="The operator recorded a narrower interpretation.",
    ),))


def docx_paragraphs(docx: bytes) -> list[str]:
    with ZipFile(BytesIO(docx)) as package:
        document = ET.fromstring(package.read("word/document.xml"))
    return [
        "".join(fragment.text or "" for fragment in paragraph.iter(f"{WORD_NS}t"))
        for paragraph in document.iter(f"{WORD_NS}p")
    ]


def pdf_pages(pdf: bytes) -> list[str]:
    return [page.extract_text() for page in PdfReader(BytesIO(pdf)).pages]


def normalized(text: str) -> str:
    return " ".join(text.split())


def test_byte_identical_in_fresh_processes() -> None:
    """Catch process-local font subset identifiers, random UUIDs and hash ordering."""
    root = Path(__file__).resolve().parents[1]
    command = (
        "from hashlib import sha256\n"
        "from render import Section, render_report\n"
        "from test_render import example_chain_report\n"
        "document = render_report(example_chain_report(), list(Section))\n"
        "print(sha256(document.pdf).hexdigest(), sha256(document.docx).hexdigest())"
    )
    actual = render_report(example_chain_report(), list(Section))
    expected = f"{hashlib.sha256(actual.pdf).hexdigest()} {hashlib.sha256(actual.docx).hexdigest()}"
    for seed in ("132", "874"):
        search_path = os.pathsep.join((str(root), str(root / "tests"), *sys.path))
        process = subprocess.run(
            [sys.executable, "-c", command], cwd=root, check=True, capture_output=True,
            text=True, timeout=45, env={**os.environ, "PYTHONPATH": search_path, "PYTHONHASHSEED": seed},
        )
        assert process.stdout.strip() == expected


def test_finding_content_stays_text_in_exported_files() -> None:
    from pypdf.generic import ArrayObject, DictionaryObject

    data = example_report()
    literal = '<i>label & {{owner}}</i>'
    address = "https://outside.invalid/plain-text"
    finding = replace(data.findings[0], title=literal, reproduction_steps=(address,))
    output = render_report(replace(data, findings=(finding,)), [Section.FINDING_DETAILS])
    for content in ("\n".join(docx_paragraphs(output.docx)), "\n".join(pdf_pages(output.pdf))):
        assert literal in content
        assert address in content
        # Depending on printable line width, long evidence identifiers may wrap.
        assert ARTIFACT in "".join(content.split())

    with ZipFile(BytesIO(output.docx)) as package:
        for path in package.namelist():
            if path.endswith(".rels"):
                for relation in ET.fromstring(package.read(path)):
                    assert "outside.invalid" not in relation.attrib["Target"]
    for page in PdfReader(BytesIO(output.pdf)).pages:
        annotations = page.get("/Annots")
        if isinstance(annotations, ArrayObject):
            for reference in annotations:
                annotation = reference.get_object()
                if not isinstance(annotation, DictionaryObject):
                    continue
                action = annotation.get("/A")
                if isinstance(action, DictionaryObject):
                    assert action.get("/S") not in ("/JavaScript", "/Launch")
                    assert "outside.invalid" not in str(action.get("/URI", ""))


def test_multiline_finding_survives_pdf_pagination() -> None:
    data = example_report()
    notes = tuple(f"Observation {i:03d}. Compare the archived monitoring record." for i in range(1, 101))
    finding = replace(data.findings[0], reproduction_steps=notes)
    output = render_report(replace(data, findings=(finding,)), [Section.FINDING_DETAILS])
    pages = [normalized(page) for page in pdf_pages(output.pdf)]
    first = next(i for i, page in enumerate(pages) if "Observation 001." in page)
    last = next(i for i, page in enumerate(pages) if "Observation 100." in page)
    assert first < last
    for content in (" ".join(pages), normalized("\n".join(docx_paragraphs(output.docx)))):
        for i in range(1, 101):
            assert f"Observation {i:03d}." in content


def test_section_selection_keeps_provenance_and_omits_unselected_findings() -> None:
    data = example_report()
    subset = render_report(data, [Section.ATTACK_NARRATIVES])
    for text in ("\n".join(docx_paragraphs(subset.docx)), "\n".join(pdf_pages(subset.pdf))):
        contents = normalized(text)
        assert "Assessment report" in contents
        assert "Attack narratives" in contents
        assert data.attack_narratives[0] in contents
        assert "Appendix" in contents
        assert "cleanup-581" in contents
        assert "Findings register" not in contents
        assert data.findings[0].title not in contents


def test_remediation_prioritizes_confirmed_findings_by_score() -> None:
    data = example_report()
    high, false_positive = data.findings
    zero = replace(
        high, id="OBS-000", title="Label reviewed",
        cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
        cvss_score=0.0, remediation="Archive the reviewed label.",
    )
    report = replace(data, findings=(zero, high, replace(false_positive, remediation="Spurious recommendation.")))
    output = render_report(report, [Section.REMEDIATION])
    for text in ("\n".join(docx_paragraphs(output.docx)), "\n".join(pdf_pages(output.pdf))):
        content = normalized(text)
        assert high.remediation is not None and zero.remediation is not None
        assert content.index(high.remediation) < content.index(zero.remediation)
        assert "Spurious recommendation." not in content


# Compare delivered text rather than font subset IDs, pagination or ZIP encoding.
# A separate fresh-process test checks the stronger byte reproducibility property.
SECTION_SNAPSHOTS = {
    "Assessment report": (
        f"Engagement {OWNER}", "Signed RoE manifest SHA-256", "12" * 32,
        "RoE signature SHA-256", "34" * 32,
    ),
    "Executive summary": (
        "2 reviewed findings. 1 confirmed. 1 false positive.",
        "Highest confirmed CVSS v4.0 score: 10.0 (OBS-001 · Missing audit entries).",
    ),
    "Methodology": (
        "The signed rules of engagement define assessment scope. The findings register uses the "
        "recorded disposition. Finding details identify the supporting evidence.",
        "Methodology references", "Penetration Testing Execution Standard (PTES) — Reporting.",
        "NIST SP 800-115 — Technical Guide to Information Security Testing and Assessment.",
        "OWASP Web Security Testing Guide (WSTG) — Reporting.",
        "Severity uses FIRST CVSS v4.0 when a vector is available. Framework mappings identify "
        "controls relevant to review. A compliance determination requires separate assessment "
        "of the control and its operation.",
    ),
    "Findings register": (
        "ID Title CVSS v4.0 CWE Status Framework mappings",
        "OBS-001 Missing audit entries 10.0 CWE-778 CONFIRMED SOC 2 CC7.2",
        "OBS-002 Retention setting reviewed Unscored Unmapped FALSE_POSITIVE Unmapped",
    ),
    "Finding details": (
        "OBS-001 · Missing audit entries", "Status: CONFIRMED", "CVSS v4.0: 10.0", VECTOR,
        "Evidence links (M7 paths)", ARTIFACT, "Reproduction steps",
        "1. Compare the approved sample with the audit export.",
        "OBS-002 · Retention setting reviewed", "Status: FALSE_POSITIVE", "CVSS v4.0: Unscored",
        "Evidence links (M7 paths)", "No evidence links supplied.", "Reproduction steps",
        "No reviewed reproduction steps supplied.",
    ),
    "Attack narratives": (
        "OPERATOR_PROVIDED · Supplemental narratives",
        "The inventory and audit export identify the same reviewed asset.",
    ),
    "Prioritized remediation": (
        "1. OBS-001 · Missing audit entries", "CVSS v4.0: 10.0",
        "Enable audit logging and verify the retention policy.",
    ),
    "Appendix": (
        "Scope manifest", '{"scope":"read-only review"}',
        "Audit-ledger excerpt", '[{"event_id":"scope-locked-31","seq_id":31}]',
        "Workspace teardown receipt", '{"receipt_id":"cleanup-581","result":"complete"}',
    ),
}


def split_sections(lines: list[str]) -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in lines:
        if line in SECTION_SNAPSHOTS:
            assert line not in sections
            current = []
            sections[line] = current
        elif line.strip():
            assert current is not None, f"Text before cover: {line!r}"
            current.append(line)
    assert list(sections) == list(SECTION_SNAPSHOTS)
    return {heading: normalized(" ".join(content)) for heading, content in sections.items()}


@pytest.fixture(scope="module")
def exported_sections() -> tuple[dict[str, str], dict[str, str]]:
    exported = render_report(example_report(), list(Section))
    pages = pdf_pages(exported.pdf)
    pdf_lines: list[str] = []
    for number, page in enumerate(pages, 1):
        body, footer = page.rsplit("\n", 1)
        assert footer == f"RedOps Command Center {number} / {len(pages)}"
        pdf_lines.extend(body.splitlines())
    return split_sections(pdf_lines), split_sections(docx_paragraphs(exported.docx))


@pytest.mark.parametrize("heading", list(SECTION_SNAPSHOTS))
def test_exported_section_snapshot(
    heading: str, exported_sections: tuple[dict[str, str], dict[str, str]],
) -> None:
    pdf, docx = exported_sections
    expected = " ".join(SECTION_SNAPSHOTS[heading])
    assert pdf[heading] == expected
    assert docx[heading] == expected


def test_exported_chain_narrative_snapshot() -> None:
    exported = render_report(example_chain_report(), [Section.ATTACK_NARRATIVES])
    expected = " ".join((
        "OPERATOR_PROVIDED · Narrative override for reviewed-chain-01",
        "The operator recorded a narrower interpretation.",
        "CHAIN_DERIVED · reviewed-chain-01",
        "Path includes findings without CONFIRMED disposition.",
        "Entry point and hop 1 · OBS-001 · Missing audit entries",
        "Status: CONFIRMED",
        "Technique: Compared archived audit records.",
        "CVSS v4.0: 10.0", VECTOR,
        f"Graph nodes: {ENTRY} → {INTERMEDIATE}",
        "CWE: CWE-778 — Insufficient Logging",
        "Evidence SHA-256 and retrieval (M7 paths)", ARTIFACT,
        "Hop 2 · OBS-002 · Retention setting reviewed",
        "Status: FALSE_POSITIVE",
        "Technique: No reviewed summary supplied.",
        "CVSS v4.0: Unscored",
        f"Graph nodes: {INTERMEDIATE} → {TERMINAL}",
        "CWE: Unmapped",
        "Evidence SHA-256 and retrieval (M7 paths)", SECOND_ARTIFACT,
        "Impact summary: The audit record is incomplete.",
        "Tier-0 reached (recorded path): true",
        "CVSS v4.0 rollup (maximum hop score): 10.0",
        "Graph path cost: 3.5",
        "OPERATOR_PROVIDED · Supplemental narratives",
        "The inventory and audit export identify the same reviewed asset.",
    ))
    pdf_body = "\n".join(page.rsplit("\n", 1)[0] for page in pdf_pages(exported.pdf))
    for body in (pdf_body, "\n".join(docx_paragraphs(exported.docx))):
        assert normalized(body.split("Attack narratives", 1)[1].split("Appendix", 1)[0]) == expected
        assert "CWE taxonomy attribution" in body
    with ZipFile(BytesIO(exported.docx)) as package:
        relations = ET.fromstring(package.read("word/_rels/document.xml.rels"))
        assert {relation.attrib["Target"] for relation in relations if relation.attrib.get("TargetMode") == "External"} == {
            ARTIFACT, SECOND_ARTIFACT,
        }
