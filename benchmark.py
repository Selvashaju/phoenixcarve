#!/usr/bin/env python3
"""
PhoenixCarve — Phase 5: Benchmark vs Foremost and Scalpel
Same test images, same ground truth, same scoring for every tool.

Usage:
  python3 benchmark.py --images 10            # 10 random images (byte offsets + sector aligned)
Needs foremost / scalpel on PATH (Mac: brew install foremost scalpel). Missing tools are skipped.
"""
import argparse
import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

from carver import HERE, carve, load_signatures

TYPES = {"jpg", "png", "gif", "bmp", "pdf", "zip", "exe"}
NORM = {"gif87": "gif", "docx": "zip", "xlsx": "zip", "pptx": "zip", "jpeg": "jpg"}

SCALPEL_CONF = r"""
gif     y   5000000     \x47\x49\x46\x38\x37\x61    \x00\x3b
gif     y   5000000     \x47\x49\x46\x38\x39\x61    \x00\x3b
jpg     y   20000000    \xff\xd8\xff    \xff\xd9
png     y   20000000    \x89\x50\x4e\x47\x0d\x0a\x1a\x0a    \x49\x45\x4e\x44\xae\x42\x60\x82
bmp     y   10000000    BM??\x00\x00\x00
pdf     y   50000000    %PDF    %%EOF
zip     y   100000000   PK\x03\x04  PK\x05\x06
exe     y   10000000    MZ
"""


def norm(t):
    t = t.lower().lstrip(".")
    return NORM.get(t, t)


# ---------- tool runners: each returns list of {type, offset, size} ----------
def run_phoenix(image, work):
    with contextlib.redirect_stdout(io.StringIO()):
        rep = carve(image, os.path.join(work, "pc"), load_signatures(os.path.join(HERE, "signatures.json")))
    return [{"type": norm(c["type"]), "offset": c["start_offset"], "size": c["size"], "status": c["status"]}
            for c in rep["carved"]]


def run_foremost(image, work):
    out = os.path.join(work, "fm")
    subprocess.run(["foremost", "-i", image, "-o", out], capture_output=True, check=True)
    paths = {f: os.path.join(r, f) for r, _, fs in os.walk(out) for f in fs}
    res = []
    for line in open(os.path.join(out, "audit.txt"), errors="replace"):
        m = re.match(r"\s*\d+:\s+(\S+)\s+.*?\s(\d+)\s*\t", line)
        if m and m.group(1) in paths:
            name = m.group(1)
            res.append({"type": norm(os.path.splitext(name)[1]), "offset": int(m.group(2)),
                        "size": os.path.getsize(paths[name])})
    return res


def run_scalpel(image, work):
    out, conf = os.path.join(work, "sc"), os.path.join(work, "scalpel.conf")
    open(conf, "w").write(SCALPEL_CONF)
    subprocess.run(["scalpel", "-c", conf, "-o", out, image], capture_output=True, check=True)
    res = []
    for line in open(os.path.join(out, "audit.txt"), errors="replace"):
        m = re.match(r"\s*\d+\.(\w+)\s+(\d+)\s+(YES|NO)\s+(\d+)", line)
        if m:
            res.append({"type": norm(m.group(1)), "offset": int(m.group(2)), "size": int(m.group(4))})
    return res


TOOLS = {"PhoenixCarve": run_phoenix, "Foremost": run_foremost, "Scalpel": run_scalpel}


# ---------- scoring ----------
def score(found, truth):
    found = [f for f in found if f["type"] in TYPES]
    by_off = {}
    for f in found:
        by_off.setdefault(f["offset"], f)
    exact = partial = missed = 0
    damaged_flagged = damaged_total = 0
    for g in truth:
        f = by_off.get(g["offset"])
        if g.get("expect") == "corrupt":
            damaged_total += 1
            damaged_flagged += bool(f and f.get("status") == "corrupt")
        if not f or f["type"] != norm(g["type"]):
            missed += 1
        elif f["size"] == g["size"]:
            exact += 1
        else:
            partial += 1
    offs = {g["offset"] for g in truth}
    fp = sum(1 for f in found if f["offset"] not in offs)
    return {"exact": exact, "partial": partial, "missed": missed, "fp": fp,
            "carved": len(found), "truth": len(truth),
            "damaged_flagged": damaged_flagged, "damaged_total": damaged_total}


def summarize(rows):
    t = {k: sum(r[k] for r in rows) for k in rows[0] if k != "seconds"}
    precision = t["exact"] / t["carved"] if t["carved"] else 0
    recall = t["exact"] / t["truth"] if t["truth"] else 0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
    return {**t, "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
            "damage_detection": round(t["damaged_flagged"] / t["damaged_total"], 4) if t["damaged_total"] else None,
            "seconds": round(sum(r["seconds"] for r in rows), 3)}


def make_images(n, work):
    imgs = []
    for i in range(n):
        for align in (0, 512):
            name = os.path.join(work, f"img_s{i}_a{align}")
            subprocess.run([sys.executable, os.path.join(HERE, "make_test_image.py"), "--seed", str(100 + i),
                            "--align", str(align), "--out", name], capture_output=True, check=True)
            imgs.append((name + ".dd", json.load(open(name + "_truth.json")), align))
    return imgs


def chart(summary, path):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return None
    tools = list(summary)
    metrics = [("precision", "Precision"), ("recall", "Recall"), ("f1", "F1"), ("damage_detection", "Damage detected")]
    cols = ["#d9a441", "#5d7e99", "#9c948a"]
    fig, ax = plt.subplots(figsize=(8, 3.6), dpi=150)
    w = 0.8 / len(tools)
    for i, t in enumerate(tools):
        raw = [summary[t][k] for k, _ in metrics]
        vals = [(v or 0) * 100 for v in raw]
        bars = ax.bar([x + i * w for x in range(len(metrics))], vals, w, label=t, color=cols[i % 3])
        for b, v, r in zip(bars, vals, raw):
            ax.text(b.get_x() + b.get_width() / 2, v + 1.5, "n/a" if r is None else f"{v:.0f}",
                    ha="center", fontsize=7, color="#6b645d" if r is None else "black")
    ax.set_xticks([x + w * (len(tools) - 1) / 2 for x in range(len(metrics))], [m for _, m in metrics])
    ax.set_ylim(0, 108)
    ax.set_ylabel("%")
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(frameon=False, fontsize=8, loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=3)
    fig.tight_layout()
    fig.savefig(path)
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--images", type=int, default=10, help="random seeds (each is built unaligned and 512-aligned)")
    ap.add_argument("-o", "--out", default="benchmark")
    a = ap.parse_args()

    tools = {n: f for n, f in TOOLS.items() if n == "PhoenixCarve" or shutil.which(n.lower())}
    skipped = [n for n in TOOLS if n not in tools]
    os.makedirs(a.out, exist_ok=True)
    work = tempfile.mkdtemp(prefix="pcbench_")
    imgs = make_images(a.images, work)
    print(f"[*] {len(imgs)} test images, {sum(len(t) for _, t, _ in imgs)} planted files. Tools: {', '.join(tools)}"
          + (f" (skipped: {', '.join(skipped)})" if skipped else ""))

    per = {n: {"all": [], "unaligned": [], "aligned": []} for n in tools}
    for img, truth, align in imgs:
        for n, fn in tools.items():
            d = tempfile.mkdtemp(dir=work)
            t0 = time.time()
            s = score(fn(img, d), truth)
            s["seconds"] = time.time() - t0
            per[n]["all"].append(s)
            per[n]["aligned" if align else "unaligned"].append(s)

    summary = {n: summarize(v["all"]) for n, v in per.items()}
    split = {n: {k: summarize(v[k]) for k in ("unaligned", "aligned")} for n, v in per.items()}
    json.dump({"images": len(imgs), "summary": summary, "by_alignment": split}, open(f"{a.out}/benchmark.json", "w"), indent=2)

    pct = lambda v: "n/a" if v is None else f"{v * 100:.1f}%"
    lines = ["| Tool | Exact | Partial | Missed | False pos. | Precision | Recall | F1 | Damage detected | Time |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for n, s in summary.items():
        lines.append(f"| {n} | {s['exact']} | {s['partial']} | {s['missed']} | {s['fp']} | {pct(s['precision'])} | "
                     f"{pct(s['recall'])} | {pct(s['f1'])} | {pct(s['damage_detection']) if n == 'PhoenixCarve' else 'not supported'} | {s['seconds']}s |")
    lines += ["", "| Tool | F1 (any byte offset) | F1 (sector aligned) |", "|---|---|---|"]
    for n, s in split.items():
        lines.append(f"| {n} | {pct(s['unaligned']['f1'])} | {pct(s['aligned']['f1'])} |")
    md = "\n".join(lines)
    open(f"{a.out}/benchmark.md", "w").write(md + "\n")
    for n in summary:
        if n != "PhoenixCarve":
            summary[n]["damage_detection"] = None
    c = chart(summary, f"{a.out}/benchmark.png")
    print("\n" + md + f"\n\n[*] Saved {a.out}/benchmark.json, benchmark.md" + (", benchmark.png" if c else ""))
    shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
