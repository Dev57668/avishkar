"""PDF rendering of a scan report (reportlab, pure Python: no browser, no system tools).

The document is built from the same report dict as the JSON and HTML renderings (`avishkar.report.build_report`), so every
number and sentence comes from persisted scan data or the static knowledge base. Text taken from the scan (paths,
evidence lines, titles) is untrusted: it is escaped before it reaches reportlab's mini-markup parser, and the base-14
fonts are used so no font file from anywhere is ever loaded. Output is deterministic for a given report
(`invariant=1`: fixed timestamps and IDs), and uncompressed so the text is greppable in tests and by auditors.
"""
from __future__ import annotations

import io
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

MAX_FINDINGS = 200
SEV_COLOR = {"critical": "#b91c1c", "high": "#c2410c", "medium": "#a16207", "low": "#1d4ed8", "informational": "#4b5563"}
SEV_ORDER = ["critical", "high", "medium", "low", "informational"]
_SUBS = {"→": "->", "←": "<-", "−": "-", "–": "-", "—": "-", "“": '"', "”": '"', "‘": "'", "’": "'", "…": "...", "≥": ">=", "≤": "<=",
         "·": "-", "×": "x", "•": "-", " ": " "}


def _t(x) -> str:
    """Latin-1-safe, markup-escaped text for a Paragraph."""
    s = "" if x is None else str(x)
    for a, b in _SUBS.items():
        s = s.replace(a, b)
    s = s.encode("latin-1", "replace").decode("latin-1")
    return escape(s)


def render_pdf(rep: dict) -> bytes:
    base = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=base["BodyText"], fontName="Helvetica", fontSize=9.5, leading=13)
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=10.5, textColor=colors.HexColor("#4b5563"))
    h1 = ParagraphStyle("h1", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=20, leading=24, spaceAfter=2)
    h2 = ParagraphStyle("h2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=13, leading=16, spaceBefore=14, spaceAfter=5)
    h3 = ParagraphStyle("h3", parent=base["Heading3"], fontName="Helvetica-Bold", fontSize=10.5, leading=13, spaceAfter=2)
    code = ParagraphStyle("code", parent=body, fontName="Courier", fontSize=8, leading=10, backColor=colors.HexColor("#f3f4f6"),
                          borderPadding=(3, 4, 3, 4), spaceBefore=3, spaceAfter=3)
    warn = ParagraphStyle("warn", parent=body, textColor=colors.HexColor("#991b1b"), backColor=colors.HexColor("#fef2f2"),
                          borderPadding=(5, 6, 5, 6), spaceBefore=6, spaceAfter=6)

    sd, scan = rep["securityDebt"], rep["scan"]
    story: list = [Paragraph("Security debt report", h1),
                   Paragraph(_t(f"{rep['repository']['name']} - generated {rep['generatedAt']} - {scan['service']} - {rep['reportVersion']}"), small)]
    if scan["status"] != "complete":
        story.append(Paragraph("<b>INCOMPLETE ANALYSIS.</b> No score was calculated. This is NOT a pass.", warn))

    story += [Paragraph("Executive summary", h2), Paragraph(_t(rep["executiveSummary"]), body)]
    idx = sd.get("normalizedIndex")
    kpis = [["Security debt index", "Gross debt units", "Open findings", "Files scanned"],
            [_t(idx if idx is not None else "n/a"), _t(sd.get("grossUnits") if sd.get("grossUnits") is not None else "n/a"),
             _t(rep["openFindings"]), _t(scan.get("filesScanned") if scan.get("filesScanned") is not None else "n/a")],
            [_t(f"{sd.get('scoreVersion') or ''} - uncalibrated"), "", "", ""]]
    t = Table(kpis, colWidths=[44 * mm] * 4)
    t.setStyle(TableStyle([("FONT", (0, 0), (-1, 0), "Helvetica", 8), ("FONT", (0, 1), (-1, 1), "Helvetica-Bold", 17),
                           ("FONT", (0, 2), (-1, 2), "Helvetica", 7.5), ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#4b5563")),
                           ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")), ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db"))]))
    story += [Spacer(1, 6), t]

    sev = rep["severityDistribution"]
    st = Table([[s.capitalize() for s in SEV_ORDER], [str(sev.get(s, 0)) for s in SEV_ORDER]], colWidths=[35 * mm] * 5)
    st.setStyle(TableStyle([("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8.5), ("FONT", (0, 1), (-1, 1), "Helvetica", 11),
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")), ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")), ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db"))]
                           + [("TEXTCOLOR", (i, 0), (i, 0), colors.HexColor(SEV_COLOR[s])) for i, s in enumerate(SEV_ORDER)]))
    story += [Paragraph("Severity distribution (open findings)", h2), st]

    meta = [("Run id", scan["runId"]), ("Status", scan["status"]), ("Commit", scan.get("commitSha") or "n/a"), ("Started", scan["startedAt"]),
            ("Score version", scan.get("scoreVersion")), ("Policy version", scan.get("policyVersion")), ("Knowledge base", scan["knowledgeBase"]),
            ("Detectors", f"{scan.get('completedDetectors')}/{scan.get('requiredDetectors')} required completed"),
            ("Policy outcome", (rep.get("decision") or {}).get("outcome"))]
    mt = Table([[Paragraph(_t(k), small), Paragraph(_t(v), body)] for k, v in meta], colWidths=[38 * mm, 130 * mm])
    mt.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")), ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
                            ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story += [Paragraph("Scan metadata", h2), mt]

    m = (rep.get("scoreExplanation") or {}).get("method")
    if m:
        story += [Paragraph("How the index is calculated", h2), Paragraph(_t(m["formula"]), code), Paragraph(_t(m["aggregation"]), body),
                  Paragraph(_t(m["normalization"]), code)] + [Paragraph("- " + _t(n), small) for n in m["notes"]]

    cmp = rep.get("comparison")
    if cmp:
        story.append(Paragraph("Before and after", h2))
        if cmp.get("comparable"):
            d = cmp["delta"]
            story.append(Paragraph(_t(f"Previous run {cmp['base']['runId']}: index {cmp['base']['normalizedIndex']} -> this run: "
                                      f"{cmp['head']['normalizedIndex']} ({d['index']:+g})."), body))
            story += [Paragraph("- " + _t(x), small) for x in cmp["explanation"]]
        else:
            story.append(Paragraph(_t(cmp.get("reason")), body))

    findings = rep["findings"]
    story.append(Paragraph(f"Findings ({len(findings)})", h2))
    for f in findings[:MAX_FINDINGS]:
        cwe = ", ".join(c["id"] for c in f["cwe"]) or "no CWE mapped"
        col = SEV_COLOR.get(f["severity"], "#4b5563")
        block = [Paragraph(f'<font color="{col}">{_t(f["severity"].upper())}</font> {_t(f["title"])}', h3),
                 Paragraph(_t(f"{f['ruleId']} | {cwe} | confidence {f['confidence']} | {f['detection']['method']}/{f['detection']['assurance']} | state {f['state']}"), small),
                 Paragraph(_t(f"{f['path']}:{f['line']}"), code)]
        if f.get("evidence"):
            block.append(Paragraph(_t(f["evidence"][:300]), code))
        block += [Paragraph("<b>Why it matters.</b> " + _t(f["why"]), body), Paragraph("<b>Impact.</b> " + _t(f["impact"]), body),
                  Paragraph("<b>Fix.</b> " + _t(f["remediation"]), body)]
        if f.get("debt"):
            dbt = f["debt"]
            block.append(Paragraph(_t(f"Debt: {dbt['impact']} x {dbt['exposure']} x {dbt['confidence']} x {dbt['age']} = {dbt['units']} units "
                                      f"({dbt['shareOfGross']}% of total)"), small))
        block.append(Spacer(1, 6))
        story.append(KeepTogether(block))
    if len(findings) > MAX_FINDINGS:
        story.append(Paragraph(_t(f"Only the first {MAX_FINDINGS} of {len(findings)} findings are listed here, ordered by severity. "
                                  "The JSON report and SARIF export contain all of them."), warn))

    story.append(Paragraph("Limitations", h2))
    story += [Paragraph("- " + _t(x), body) for x in rep["limitations"]]

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                            title=_t(f"Security debt report - {rep['repository']['name']}"), author="Second Read", pageCompression=0,
                            invariant=1)

    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#6b7280"))
        canvas.drawString(18 * mm, 9 * mm, _t(f"{rep['repository']['name']} - {scan['runId']} - uncalibrated prioritization index, not proof of safety"))
        canvas.drawRightString(A4[0] - 18 * mm, 9 * mm, f"Page {d.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
