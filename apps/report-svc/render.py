"""Render the same reviewed assessment content to PDF and Office Open XML."""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from io import BytesIO
from pathlib import Path
from typing import Literal
from uuid import UUID
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from weasyprint import HTML  # type: ignore[import-untyped]

from mappers.cwe import CWE_LICENSE_NOTICE


class Section(StrEnum):
    COVER = "cover"
    EXECUTIVE_SUMMARY = "executive_summary"
    METHODOLOGY = "methodology"
    FINDINGS = "findings"
    FINDING_DETAILS = "finding_details"
    ATTACK_NARRATIVES = "attack_narratives"
    REMEDIATION = "remediation"
    APPENDIX = "appendix"


@dataclass(frozen=True)
class ReportFinding:
    id: str
    title: str
    status: str
    cvss_vector: str | None = None
    cvss_score: float | None = None
    cwe: str | None = None
    framework_mappings: tuple[str, ...] = ()
    evidence_links: tuple[str, ...] = ()
    reproduction_steps: tuple[str, ...] = ()
    remediation: str | None = None


@dataclass(frozen=True)
class NarrativeHop:
    finding: ReportFinding
    technique_summary: str | None
    source_node: UUID
    destination_node: UUID


@dataclass(frozen=True)
class ReportChain:
    id: str
    hops: tuple[NarrativeHop, ...]
    impact_summary: str | None
    tier0_reached: bool
    path_cost: float | None = None
    operator_override: str | None = None


@dataclass(frozen=True)
class ReportData:
    engagement_id: str
    manifest_hash: str
    roe_signature_hash: str
    manifest_json: str
    ledger_excerpt_json: str
    teardown_receipt_json: str
    findings: tuple[ReportFinding, ...]
    attack_narratives: tuple[str, ...] = ()
    chains: tuple[ReportChain, ...] = ()


@dataclass(frozen=True)
class RenderedReport:
    pdf: bytes
    docx: bytes


@dataclass(frozen=True)
class Paragraph:
    text: str
    style: Literal["body", "subheading", "code", "evidence"] = "body"


@dataclass(frozen=True)
class Table:
    headers: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]


@dataclass(frozen=True)
class Chapter:
    section: Section
    title: str
    blocks: Sequence[Paragraph | Table]


def _score(finding: ReportFinding) -> str:
    return f"{finding.cvss_score:.1f}" if finding.cvss_score is not None else "Unscored"


def _evidence_paths(links: Sequence[str]) -> list[Paragraph]:
    if any(not re.fullmatch(r"/artifacts/[0-9a-f]{64}", link) for link in links):
        raise ValueError("Invalid M7 evidence path")
    return [Paragraph(link, "evidence") for link in sorted(links)]


def _details(findings: Sequence[ReportFinding]) -> list[Paragraph]:
    blocks: list[Paragraph] = []
    for finding in findings:
        blocks.extend((
            Paragraph(f"{finding.id} · {finding.title}", "subheading"),
            Paragraph(f"Status: {finding.status}"),
            Paragraph(f"CVSS v4.0: {_score(finding)}"),
        ))
        if finding.cvss_vector:
            blocks.append(Paragraph(finding.cvss_vector, "code"))
        blocks.append(Paragraph("Evidence links (M7 paths)", "subheading"))
        blocks.extend(_evidence_paths(finding.evidence_links) or [Paragraph("No evidence links supplied.")])
        blocks.append(Paragraph("Reproduction steps", "subheading"))
        blocks.extend(Paragraph(f"{i}. {step}") for i, step in enumerate(finding.reproduction_steps, 1))
        if not finding.reproduction_steps:
            blocks.append(Paragraph("No reviewed reproduction steps supplied."))
    return blocks or [Paragraph("No findings recorded.")]


def _narratives(chains: Sequence[ReportChain], operator_text: Sequence[str]) -> list[Paragraph]:
    blocks: list[Paragraph] = []
    for chain in sorted(chains, key=lambda record: record.id):
        if not chain.hops:
            raise ValueError("Narrative chains require at least one hop")
        if chain.operator_override is not None:
            blocks.extend((Paragraph(f"OPERATOR_PROVIDED · Narrative override for {chain.id}", "subheading"),
                           Paragraph(chain.operator_override)))
        blocks.append(Paragraph(f"CHAIN_DERIVED · {chain.id}", "subheading"))
        if any(hop.finding.status != "CONFIRMED" for hop in chain.hops):
            blocks.append(Paragraph("Path includes findings without CONFIRMED disposition."))
        for number, hop in enumerate(chain.hops, 1):
            finding = hop.finding
            position = "Entry point and hop 1" if number == 1 else f"Hop {number}"
            blocks.extend((
                Paragraph(f"{position} · {finding.id} · {finding.title}", "subheading"),
                Paragraph(f"Status: {finding.status}"),
                Paragraph(f"Technique: {hop.technique_summary or 'No reviewed summary supplied.'}"),
                Paragraph(f"CVSS v4.0: {_score(finding)}"),
            ))
            if finding.cvss_vector:
                blocks.append(Paragraph(finding.cvss_vector, "code"))
            if chain.path_cost is not None:
                blocks.append(Paragraph(f"Graph nodes: {hop.source_node} → {hop.destination_node}"))
            paths = _evidence_paths(finding.evidence_links)
            if not paths:
                raise ValueError("Narrative hops require M7 evidence")
            blocks.extend((Paragraph(f"CWE: {finding.cwe or 'Unmapped'}"),
                           Paragraph("Evidence SHA-256 and retrieval (M7 paths)"), *paths))
        high = max((hop.finding.cvss_score for hop in chain.hops if hop.finding.cvss_score is not None),
                   default=None)
        rollup = "Unscored" if high is None else f"{high:.1f}"
        blocks.extend((
            Paragraph(f"Impact summary: {chain.impact_summary or 'No reviewed summary supplied.'}"),
            Paragraph(f"Tier-0 reached (recorded path): {str(chain.tier0_reached).lower()}"),
            Paragraph(f"CVSS v4.0 rollup (maximum hop score): {rollup}"),
        ))
        if chain.path_cost is not None:
            blocks.append(Paragraph(f"Graph path cost: {chain.path_cost}"))
    if operator_text:
        blocks.append(Paragraph("OPERATOR_PROVIDED · Supplemental narratives", "subheading"))
        blocks.extend(Paragraph(text) for text in operator_text)
    return blocks or [Paragraph("No reviewed attack narratives supplied.")]


def _chapters(data: ReportData, sections: Sequence[Section]) -> list[Chapter]:
    wanted = set(sections or Section) | {Section.COVER, Section.APPENDIX}
    findings = sorted(data.findings, key=lambda f: f.id)
    if any(f.status not in {"CONFIRMED", "FALSE_POSITIVE"} for f in findings):
        raise ValueError("Findings require a final disposition")
    ledger = json.loads(data.ledger_excerpt_json)
    receipt = json.loads(data.teardown_receipt_json)
    if not isinstance(ledger, list) or not ledger or not isinstance(receipt, dict) or not receipt:
        raise ValueError("A ledger excerpt and workspace teardown receipt are required")

    confirmed = sorted(
        (f for f in findings if f.status == "CONFIRMED"),
        key=lambda f: (f.cvss_score is None, -(f.cvss_score or 0.0), f.id),
    )
    chapters = [Chapter(Section.COVER, "Assessment report", [
        Paragraph(f"Engagement {data.engagement_id}"),
        Paragraph("Signed RoE manifest SHA-256", "subheading"), Paragraph(data.manifest_hash, "code"),
        Paragraph("RoE signature SHA-256", "subheading"), Paragraph(data.roe_signature_hash, "code"),
    ])]
    if Section.EXECUTIVE_SUMMARY in wanted:
        total = len(findings)
        false_positives = total - len(confirmed)
        summary = [Paragraph(
            f"{total} reviewed finding{'s' if total != 1 else ''}. {len(confirmed)} confirmed. "
            f"{false_positives} false positive{'s' if false_positives != 1 else ''}."
        )]
        if confirmed and confirmed[0].cvss_score is not None:
            summary.append(Paragraph(f"Highest confirmed CVSS v4.0 score: {_score(confirmed[0])} "
                                     f"({confirmed[0].id} · {confirmed[0].title})."))
        chapters.append(Chapter(Section.EXECUTIVE_SUMMARY, "Executive summary", summary))
    if Section.METHODOLOGY in wanted:
        chapters.append(Chapter(Section.METHODOLOGY, "Methodology", [
            Paragraph("The signed rules of engagement define assessment scope. The findings register "
                      "uses the recorded disposition. Finding details identify the supporting evidence."),
            Paragraph("Methodology references", "subheading"),
            Paragraph("Penetration Testing Execution Standard (PTES) — Reporting."),
            Paragraph("NIST SP 800-115 — Technical Guide to Information Security Testing and Assessment."),
            Paragraph("OWASP Web Security Testing Guide (WSTG) — Reporting."),
            Paragraph("Severity uses FIRST CVSS v4.0 when a vector is available. Framework mappings "
                      "identify controls relevant to review. A compliance determination requires "
                      "separate assessment of the control and its operation."),
        ]))
    if Section.FINDINGS in wanted:
        rows = tuple((
            f.id, f.title, _score(f), f.cwe or "Unmapped", f.status, "\n".join(f.framework_mappings) or "Unmapped",
        ) for f in findings)
        chapters.append(Chapter(Section.FINDINGS, "Findings register", [
            Table(("ID", "Title", "CVSS v4.0", "CWE", "Status", "Framework mappings"), rows)
        ] if rows else [Paragraph("No findings recorded.")]))
    if Section.FINDING_DETAILS in wanted:
        chapters.append(Chapter(Section.FINDING_DETAILS, "Finding details", _details(findings)))
    if Section.ATTACK_NARRATIVES in wanted:
        chapters.append(Chapter(Section.ATTACK_NARRATIVES, "Attack narratives",
                                _narratives(data.chains, data.attack_narratives)))
    if Section.REMEDIATION in wanted:
        recommendations: list[Paragraph] = []
        for number, finding in enumerate(confirmed, 1):
            recommendations.extend((
                Paragraph(f"{number}. {finding.id} · {finding.title}", "subheading"),
                Paragraph(f"CVSS v4.0: {_score(finding)}"),
                Paragraph(finding.remediation or "No reviewed remediation supplied."),
            ))
        chapters.append(Chapter(Section.REMEDIATION, "Prioritized remediation",
                                recommendations or [Paragraph("No confirmed findings require remediation.")]))
    appendix = [
        Paragraph("Scope manifest", "subheading"), Paragraph(data.manifest_json, "code"),
        Paragraph("Audit-ledger excerpt", "subheading"), Paragraph(data.ledger_excerpt_json, "code"),
        Paragraph("Workspace teardown receipt", "subheading"), Paragraph(data.teardown_receipt_json, "code"),
    ]
    cwe_findings = list(findings) if Section.FINDINGS in wanted else []
    if Section.ATTACK_NARRATIVES in wanted:
        cwe_findings.extend(hop.finding for chain in data.chains for hop in chain.hops)
    if any(f.cwe and " — " in f.cwe for f in cwe_findings):
        appendix.extend((Paragraph("CWE taxonomy attribution", "subheading"), Paragraph(CWE_LICENSE_NOTICE)))
    chapters.append(Chapter(Section.APPENDIX, "Appendix", appendix))
    return chapters


# HTML and OOXML share XML 1.0's printable character repertoire. Keep otherwise
# unrepresentable evidence text visible as escapes rather than dropping bytes.
_INVALID_XML_TEXT = re.compile(r"[^\x09\x0a\x0d\x20-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]")


def _printable(value: str) -> str:
    return _INVALID_XML_TEXT.sub(lambda match: f"\\u{ord(match[0]):04x}", value)


_TEMPLATES = Environment(
    loader=FileSystemLoader(Path(__file__).with_name("templates")),
    autoescape=True, undefined=StrictUndefined, trim_blocks=True, lstrip_blocks=True,
)
_TEMPLATES.filters["printable"] = _printable


def _deny_fetch(url: str, *args: object, **kwargs: object) -> None:
    raise ValueError("External resources are disabled in reports")


def _docx(chapters: Sequence[Chapter]) -> bytes:
    # Only locally generated relationship IDs are interpolated into document.xml.
    paths = sorted({block.text for chapter in chapters for block in chapter.blocks
                    if isinstance(block, Paragraph) and block.style == "evidence"})
    links = {path: f"evidence{i}" for i, path in enumerate(paths, 1)}
    parts = {
        "[Content_Types].xml": "content-types.xml.j2",
        "_rels/.rels": "package-rels.xml.j2",
        "docProps/core.xml": "core.xml.j2",
        "word/document.xml": "document.xml.j2",
        "word/styles.xml": "styles.xml.j2",
        "word/_rels/document.xml.rels": "document-rels.xml.j2",
    }
    output = BytesIO()
    with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
        for path, template in parts.items():
            content = _TEMPLATES.get_template(template).render(chapters=chapters, links=links)
            # ZipInfo's fixed 1980 timestamp keeps repeated renders byte-identical.
            archive.writestr(ZipInfo(path), content.encode("utf-8"), compress_type=ZIP_DEFLATED)
    return output.getvalue()


def render_report(data: ReportData, sections: Sequence[Section] = ()) -> RenderedReport:
    """Render selected sections in editorial order, including cover and provenance."""
    chapters = _chapters(data, sections)
    html = _TEMPLATES.get_template("report.html.j2").render(chapters=chapters)
    # No base URL means printed, service-relative artifact paths stay portable.
    pdf = HTML(string=html, url_fetcher=_deny_fetch).write_pdf()
    if not isinstance(pdf, bytes):
        raise RuntimeError("PDF backend did not produce a document")
    return RenderedReport(pdf=pdf, docx=_docx(chapters))
