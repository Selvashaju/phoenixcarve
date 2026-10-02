#!/usr/bin/env python3
"""
PhoenixCarve — Phase 4: One-shot case pipeline
carve -> validate -> entropy -> visual map -> (evaluate) -> PDF report, all logged in the custody chain.

Usage:
  python3 pipeline.py evidence.dd --case PC-2026-001 --examiner "Shajilin Benadict S" [-o cases/PC-2026-001] [--truth ground_truth.json]
"""
import argparse
import os

from carver import HERE, carve, hash_file, load_signatures
from custody import CustodyLog
from evaluate import evaluate
from report_pdf import build_report
from visualize import build_map


def run_case(image, out_dir, case_no, examiner, org="", purpose="", truth=None, progress=lambda s: None):
    os.makedirs(out_dir, exist_ok=True)
    log = CustodyLog(os.path.join(out_dir, "custody.jsonl"))

    progress("hashing")
    sha, md5 = hash_file(image)
    log.add("evidence_received", f"{os.path.basename(image)} SHA-256 {sha}", actor=examiner,
            evidence_sha256=sha, evidence_md5=md5)

    progress("carving")
    rep = carve(image, out_dir, load_signatures(os.path.join(HERE, "signatures.json")))
    log.add("carving_completed", f"{len(rep['carved'])} files carved, integrity "
            f"{'preserved' if rep['evidence']['integrity_preserved'] else 'CHANGED'}", actor=examiner)

    progress("entropy")
    map_path, ent = build_map(image, os.path.join(out_dir, "report.json"))
    log.add("entropy_analysis", f"{len(ent['unexplained_high_entropy'])} unexplained high-entropy region(s)",
            actor=examiner)

    if truth:
        progress("evaluating")
        evaluate(os.path.join(out_dir, "report.json"), truth)
        log.add("evaluation", "compared against ground truth", actor=examiner)

    progress("reporting")
    pdf, pdf_sha = build_report(out_dir, case_no, examiner, org, purpose)
    progress("done")
    return {"report": rep, "map": map_path, "pdf": pdf, "pdf_sha256": pdf_sha}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--case", required=True)
    ap.add_argument("--examiner", required=True)
    ap.add_argument("--org", default="")
    ap.add_argument("--purpose", default="")
    ap.add_argument("--truth")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()
    res = run_case(a.image, a.out or os.path.join("cases", a.case), a.case, a.examiner, a.org, a.purpose, a.truth,
                   progress=lambda s: print(f"--- {s}"))
    print(f"\n[*] Map:    {res['map']}\n[*] Report: {res['pdf']}\n[*] Report SHA-256: {res['pdf_sha256']}")
