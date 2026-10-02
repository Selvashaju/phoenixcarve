#!/usr/bin/env python3
"""
PhoenixCarve — Phase 2: Recovery Effectiveness Evaluator
Compares report.json with ground_truth.json and computes precision, recall, F1,
byte-level accuracy and validator accuracy.

Usage: python3 evaluate.py out/report.json ground_truth.json
"""
import json
import sys

EXT = {"gif87": "gif", "sqlite": "db"}


def norm(t):
    return EXT.get(t, t)


def evaluate(report_path, truth_path):
    carved = json.load(open(report_path))["carved"]
    truth = json.load(open(truth_path))
    by_offset = {c["start_offset"]: c for c in carved}

    exact = partial = missed = 0
    status_hits = status_total = 0
    bytes_truth = bytes_ok = 0
    per_type, rows = {}, []

    for g in truth:
        t = norm(g["type"])
        pt = per_type.setdefault(t, {"expected": 0, "recovered": 0})
        pt["expected"] += 1
        bytes_truth += g["size"]
        c = by_offset.get(g["offset"])

        if not c or norm(c["type"]) != t:
            missed += 1
            verdict = "MISSED"
        elif c["size"] == g["size"]:
            exact += 1
            pt["recovered"] += 1
            bytes_ok += g["size"]
            verdict = "EXACT"
        else:
            partial += 1
            bytes_ok += min(c["size"], g["size"])
            verdict = f"PARTIAL ({c['size']} vs {g['size']} bytes)"

        if c and "expect" in g:
            status_total += 1
            status_hits += c.get("status") == g["expect"]
        rows.append((t, g["offset"], g.get("note", ""), verdict,
                     c.get("status", "-") if c else "-", g.get("expect", "-")))

    truth_offsets = {g["offset"] for g in truth}
    false_pos = [c for c in carved if c["start_offset"] not in truth_offsets]

    tp = exact
    precision = tp / (tp + partial + len(false_pos)) if carved else 0
    recall = tp / len(truth) if truth else 0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0

    print(f"\n{'TYPE':6} {'OFFSET':>10}  {'NOTE':22} {'RESULT':28} {'STATUS':10} EXPECTED")
    print("-" * 92)
    for t, off, note, v, st, ex in rows:
        mark = "" if ex == "-" or st == ex else "  <-- mismatch"
        print(f"{t:6} 0x{off:08x}  {note:22} {v:28} {st:10} {ex}{mark}")
    for c in false_pos:
        print(f"{c['type']:6} 0x{c['start_offset']:08x}  {'(not in ground truth)':22} {'FALSE POSITIVE':28} {c['status']}")

    result = {
        "ground_truth_files": len(truth),
        "carved_files": len(carved),
        "exact_recoveries": exact,
        "partial_recoveries": partial,
        "missed": missed,
        "false_positives": len(false_pos),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "byte_recovery_rate": round(bytes_ok / bytes_truth, 4) if bytes_truth else 0,
        "validator_accuracy": round(status_hits / status_total, 4) if status_total else None,
        "per_type": per_type,
    }
    print("\n=== Effectiveness ===")
    for k in ("precision", "recall", "f1_score", "byte_recovery_rate", "validator_accuracy"):
        v = result[k]
        print(f"  {k:20} {v * 100:6.1f}%" if v is not None else f"  {k:20}   n/a")
    print(f"  exact/partial/missed/FP: {exact}/{partial}/{missed}/{len(false_pos)}")

    out = report_path.replace("report.json", "evaluation.json")
    json.dump(result, open(out, "w"), indent=2)
    print(f"\n[*] Saved {out}")
    return result


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    evaluate(sys.argv[1], sys.argv[2])
