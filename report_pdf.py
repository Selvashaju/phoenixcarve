#!/usr/bin/env python3
"""
PhoenixCarve — Phase 4: Forensic Examination Report (PDF, ReportLab)
Court-la submit panra format: evidence hashes, methodology, findings, entropy map,
recovered file table, limitations, chain of custody, examiner declaration.

Usage: python3 report_pdf.py out/ --case PC-2026-001 --examiner "Shajilin Benadict S"
"""
import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Circle, Drawing, Rect
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

from custody import CustodyLog

TOOL = "PhoenixCarve 1.0"
INK, MUTED, RULE = colors.HexColor("#1d1b1a"), colors.HexColor("#6b645d"), colors.HexColor("#d8d2c8")
EMBER, AMBER, SLATE = colors.HexColor("#b8431f"), colors.HexColor("#a87a1f"), colors.HexColor("#4d6d88")
STATUS_COL = {"valid": AMBER, "corrupt": EMBER, "unverified": SLATE}

S = {
    "title": ParagraphStyle("t", fontName="Helvetica-Bold", fontSize=22, leading=26, textColor=INK),
    "sub": ParagraphStyle("s", fontName="Helvetica", fontSize=10.5, leading=14, textColor=MUTED),
    "h": ParagraphStyle("h", fontName="Helvetica-Bold", fontSize=13, leading=17, textColor=INK,
                        spaceBefore=14, spaceAfter=6),
    "p": ParagraphStyle("p", fontName="Helvetica", fontSize=10, leading=14.5, textColor=INK, alignment=TA_LEFT),
    "bullet": ParagraphStyle("b", fontName="Helvetica", fontSize=10, leading=14.5, textColor=INK,
                             leftIndent=12, bulletIndent=2, spaceAfter=2),
    "small": ParagraphStyle("sm", fontName="Helvetica", fontSize=8.5, leading=11.5, textColor=MUTED),
    "cell": ParagraphStyle("c", fontName="Helvetica", fontSize=8.5, leading=11, textColor=INK),
    "mono": ParagraphStyle("m", fontName="Courier", fontSize=8, leading=10.5, textColor=INK),
}


def human(n):
    return f"{n} B" if n < 1024 else f"{n / 1024:.1f} KB" if n < 1 << 20 else f"{n / (1 << 20):.2f} MB"


def P(text, style="p"):
    return Paragraph(text, S[style])


def B(text):
    return Paragraph(text, S["bullet"], bulletText="\u2022")


def kv_table(rows, w0=45 * mm):
    t = Table([[P(f"<b>{k}</b>", "cell"), P(v, "mono" if len(v) > 40 and " " not in v else "cell")]
               for k, v in rows], colWidths=[w0, None])
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
                           ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    return t


def grid_table(header, rows, widths):
    data = [[P(f"<b>{h}</b>", "cell") for h in header]] + rows
    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("LINEBELOW", (0, 0), (-1, 0), 0.8, INK),
                           ("LINEBELOW", (0, 1), (-1, -1), 0.3, RULE),
                           ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                           ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3)]))
    return t


# ---------- Entropy figure ----------
STOPS = [(0, (58, 53, 50)), (2.4, (93, 126, 153)), (5, (217, 164, 65)), (7.1, (226, 85, 46)), (8, (255, 106, 61))]


def ramp(e):
    for (x1, c1), (x2, c2) in zip(STOPS, STOPS[1:]):
        if e <= x2:
            t = (e - x1) / (x2 - x1)
            return colors.Color(*[(a + (b - a) * t) / 255 for a, b in zip(c1, c2)])
    return colors.Color(*[v / 255 for v in STOPS[-1][1]])


def entropy_figure(ent, carved, width):
    ents = [b["entropy"] for b in ent["blocks"]]
    n, bs = len(ents), ent["block_size"]
    cols = max(16, min(64, int((n * 4) ** 0.5) + 1))
    cell = width / cols
    rows = -(-n // cols)
    d = Drawing(width, rows * cell)
    top = rows * cell
    for i, e in enumerate(ents):
        x, y = (i % cols) * cell, top - (i // cols + 1) * cell
        d.add(Rect(x, y, cell - 0.6, cell - 0.6, fillColor=ramp(e), strokeColor=None))
    for u in ent["unexplained_high_entropy"]:
        for i in range(u["start"] // bs, -(-u["end"] // bs)):
            x, y = (i % cols) * cell, top - (i // cols + 1) * cell
            d.add(Rect(x + 1, y + 1, cell - 2.6, cell - 2.6, fillColor=None,
                       strokeColor=colors.white, strokeWidth=0.8, strokeDashArray=[1.5, 1.5]))
    for c in carved:
        i = c["start_offset"] // bs
        d.add(Circle((i % cols) * cell + cell / 2, top - (i // cols) * cell - cell / 2, max(1.6, cell / 4.5),
                     fillColor=STATUS_COL.get(c["status"], INK), strokeColor=colors.white, strokeWidth=0.6))
    return d


# ---------- Page furniture ----------
def make_canvas(case_no):
    class Numbered(rl_canvas.Canvas):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self._pages = []

        def showPage(self):
            self._pages.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total = len(self._pages)
            for st in self._pages:
                self.__dict__.update(st)
                w, h = A4
                self.setFont("Helvetica", 7.5)
                self.setFillColor(MUTED)
                self.drawString(18 * mm, 12 * mm, f"Case {case_no}  |  {TOOL}  |  Forensic data recovery report")
                self.drawRightString(w - 18 * mm, 12 * mm, f"Page {self._pageNumber} of {total}")
                self.setStrokeColor(RULE)
                self.line(18 * mm, 15 * mm, w - 18 * mm, 15 * mm)
                super().showPage()
            super().save()
    return Numbered


# ---------- Report ----------
def build_report(out_dir, case_no, examiner, organisation="", purpose="", out_pdf=None):
    rep = json.load(open(os.path.join(out_dir, "report.json")))
    ent = json.load(open(os.path.join(out_dir, "entropy.json")))
    ev_path = os.path.join(out_dir, "evaluation.json")
    evaluation = json.load(open(ev_path)) if os.path.exists(ev_path) else None
    log = CustodyLog(os.path.join(out_dir, "custody.jsonl"))
    out_pdf = out_pdf or os.path.join(out_dir, f"PhoenixCarve_Report_{case_no}.pdf")

    ev, carved, val = rep["evidence"], rep["carved"], rep.get("validation", {})
    unexpl = ent["unexplained_high_entropy"]
    now = datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC")
    W = A4[0] - 36 * mm
    st = []

    # Title block
    st += [P("Forensic Data Recovery Report", "title"), Spacer(1, 3),
           P(f"Signature-based file carving and entropy analysis of a raw disk image. Generated {now}.", "sub"),
           Spacer(1, 10)]
    st.append(kv_table([("Case number", escape(case_no)), ("Examiner", escape(examiner)),
                        ("Organisation", escape(organisation or "-")),
                        ("Purpose", escape(purpose or "Recovery of deleted or hidden data from unallocated space")),
                        ("Tool", TOOL)]))

    # 1 Evidence
    st.append(P("1. Evidence item", "h"))
    st.append(kv_table([
        ("File", escape(os.path.basename(ev["path"]))),
        ("Size", f"{ev['size']:,} bytes ({human(ev['size'])})"),
        ("SHA-256 (acquired)", ev["sha256_before"]),
        ("SHA-256 (after analysis)", ev["sha256_after"]),
        ("MD5", ev["md5"]),
        ("Integrity", "<font color='#a87a1f'><b>Preserved.</b></font> Hashes before and after analysis match; "
                      "the image was opened read-only." if ev["integrity_preserved"] else
                      "<font color='#b8431f'><b>NOT preserved.</b></font> Hashes differ; findings must not be relied on."),
    ]))

    # 2 Method
    st.append(P("2. Method", "h"))
    for t in [
        "The image was memory-mapped read-only and searched for known file signatures (magic numbers) "
        "from a database of file types. For each hit the end of the file was located from a footer marker, "
        "a size field stored in the header, or the next known header, bounded by a maximum size per type.",
        "Every carved candidate was then checked structurally: JPEG marker walk, PNG chunk CRCs, ZIP member CRCs, "
        "PE section table, BMP and SQLite headers. Candidates whose structure failed were marked damaged; signature "
        "hits that proved to be random byte matches (for example a stray 'MZ') were rejected.",
        f"Shannon entropy was computed for every {ent['block_size']}-byte block. High-entropy areas not explained by "
        "a recovered file were reported as possible encrypted or packed data. SHA-256 and MD5 were recorded for "
        "every recovered file.",
    ]:
        st += [P(t), Spacer(1, 5)]

    # 3 Findings
    st.append(P("3. Summary of findings", "h"))
    by_type = ", ".join(f"{v} {k.upper()}" for k, v in sorted(rep["summary"].items()))
    findings = [
        f"<b>{len(carved)}</b> files were recovered ({by_type}).",
        f"<b>{val.get('valid', 0)}</b> passed structural validation; <b>{val.get('corrupt', 0)}</b> are damaged "
        f"and <b>{val.get('unverified', 0)}</b> could not be verified.",
        f"<b>{val.get('false_positives_dropped', 0)}</b> signature matches were rejected as false positives.",
        (f"<b>{len(unexpl)}</b> region(s) of high-entropy data totalling {human(sum(u['size'] for u in unexpl))} "
         "match no file signature and may be encrypted." if unexpl else
         "All high-entropy data is accounted for by recovered files."),
    ]
    zeros = [r for r in ent["regions"] if r["class"] == "zero" and r["size"] >= max(4096, 2 * ent["block_size"])]
    if zeros:
        findings.append(f"<b>{len(zeros)}</b> zero-filled region(s) totalling {human(sum(z['size'] for z in zeros))}, "
                        "consistent with deliberate wiping.")
    for f_ in findings:
        st.append(B(f_))
    st.append(Spacer(1, 10))

    fig = entropy_figure(ent, carved, W)
    st.append(KeepTogether([fig, Spacer(1, 4), P(
        "Figure 1. Entropy map, one cell per block, read left to right from offset 0. Dark is empty, blue is text, "
        "amber is binary, red is compressed or encrypted. Dots mark recovered files (amber valid, red damaged, "
        "blue unverified); dashed cells are unexplained high entropy.", "small")]))

    # 4 Recovered files
    st.append(P("4. Recovered files", "h"))
    rows = []
    for i, c in enumerate(carved, 1):
        col = STATUS_COL.get(c["status"], INK).hexval()[2:]
        rows.append([P(str(i), "cell"), P(escape(c["file"].split("/")[-1]), "mono"),
                     P(f"0x{c['start_offset']:08x}", "mono"), P(human(c["size"]), "cell"),
                     P(f"<font color='#{col}'><b>{c['status']}</b></font>", "cell"),
                     P(escape(c["reason"]), "cell")])
    st.append(grid_table(["#", "File", "Offset", "Size", "Status", "Validation detail"], rows,
                         [8 * mm, 42 * mm, 24 * mm, 16 * mm, 18 * mm, None]))

    # 5 Suspicious regions
    if unexpl or zeros:
        st.append(P("5. Suspicious regions", "h"))
        rows = [[P(f"0x{u['start']:08x} to 0x{u['end']:08x}", "mono"), P(human(u["size"]), "cell"),
                 P(f"{u['avg_entropy']}", "cell"), P("No signature; possible encrypted container or packed data", "cell")]
                for u in unexpl]
        rows += [[P(f"0x{z['start']:08x} to 0x{z['end']:08x}", "mono"), P(human(z["size"]), "cell"),
                  P("0.0", "cell"), P("Zero-filled; consistent with wiping", "cell")] for z in zeros]
        st.append(grid_table(["Range", "Size", "Entropy", "Assessment"], rows, [52 * mm, 18 * mm, 18 * mm, None]))

    # 6 Effectiveness
    if evaluation:
        st.append(P("6. Recovery effectiveness (test against known ground truth)", "h"))
        pct = lambda v: "n/a" if v is None else f"{v * 100:.1f}%"
        st.append(kv_table([
            ("Files planted / carved", f"{evaluation['ground_truth_files']} / {evaluation['carved_files']}"),
            ("Exact / partial / missed", f"{evaluation['exact_recoveries']} / {evaluation['partial_recoveries']} / {evaluation['missed']}"),
            ("False positives", str(evaluation["false_positives"])),
            ("Precision / Recall / F1", f"{pct(evaluation['precision'])} / {pct(evaluation['recall'])} / {pct(evaluation['f1_score'])}"),
            ("Byte recovery rate", pct(evaluation["byte_recovery_rate"])),
            ("Validator accuracy", pct(evaluation["validator_accuracy"])),
        ]))

    # 7 Limitations
    st.append(P("7. Limitations", "h"))
    for t in [
        "Header/footer carving assumes files are stored contiguously. Fragmented files are recovered only up to the "
        "first break and are reported as damaged rather than repaired.",
        "Files with no structural validator are reported as unverified; their content was not confirmed.",
        "High entropy indicates compressed or encrypted data but does not prove encryption. Flagged regions require "
        "further examination.",
        "File names, timestamps and directory paths are not recoverable by carving; carved files are named by type and offset.",
    ]:
        st.append(B(t))

    # 8 Custody
    log.add("report_generated", f"PDF report for case {case_no}", actor=examiner)
    ok, msg = log.verify()
    st.append(P("8. Chain of custody", "h"))
    st.append(P(f"Each entry stores the SHA-256 of the previous entry, so any later edit breaks the chain. "
                f"Verification: <b>{'intact' if ok else 'TAMPERED'}</b> ({msg})."))
    st.append(Spacer(1, 5))
    rows = [[P(str(e["seq"]), "cell"), P(e["time_utc"].replace("T", " ").replace("+00:00", ""), "cell"),
             P(escape(e["actor"]), "cell"), P(escape(e["action"]).replace("_", " "), "cell"),
             P(e["entry_hash"][:16] + "...", "mono")] for e in log.entries()]
    st.append(grid_table(["#", "Time (UTC)", "Actor", "Action", "Entry hash"], rows,
                         [8 * mm, 34 * mm, 34 * mm, None, 38 * mm]))

    # 9 Declaration
    st.append(KeepTogether([
        P("9. Examiner declaration", "h"),
        P(f"I, {escape(examiner)}, declare that the examination described in this report was carried out by me using "
          f"{TOOL} on a read-only copy of the evidence identified in section 1, that the evidence hash was unchanged by "
          "the examination, and that the findings are a true record of the results obtained."),
        Spacer(1, 26),
        Table([[P("Signature", "small"), "", P("Date", "small"), ""]],
              colWidths=[20 * mm, 70 * mm, 14 * mm, 40 * mm],
              style=[("LINEBELOW", (1, 0), (1, 0), 0.6, INK), ("LINEBELOW", (3, 0), (3, 0), 0.6, INK)]),
    ]))

    # Appendix: hashes
    st += [PageBreak(), P("Appendix A. Hashes of recovered files", "h")]
    rows = [[P(escape(c["file"].split("/")[-1]), "mono"), P(c["sha256"], "mono")] for c in carved]
    st.append(grid_table(["File", "SHA-256"], rows, [48 * mm, None]))

    doc = SimpleDocTemplate(out_pdf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=18 * mm, bottomMargin=22 * mm,
                            title=f"Forensic Data Recovery Report {case_no}", author=examiner)
    doc.build(st, canvasmaker=make_canvas(case_no))

    # Sidecar hash so the report itself can be verified later
    sha = hashlib.sha256(open(out_pdf, "rb").read()).hexdigest()
    with open(out_pdf + ".sha256", "w") as f:
        f.write(f"{sha}  {os.path.basename(out_pdf)}\n")
    log.add("report_hashed", f"SHA-256 {sha}", actor=examiner)
    return out_pdf, sha


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("out_dir", help="folder with report.json + entropy.json")
    ap.add_argument("--case", required=True)
    ap.add_argument("--examiner", required=True)
    ap.add_argument("--org", default="")
    ap.add_argument("--purpose", default="")
    a = ap.parse_args()
    pdf, sha = build_report(a.out_dir, a.case, a.examiner, a.org, a.purpose)
    print(f"[*] Report: {pdf}\n[*] SHA-256: {sha}")
