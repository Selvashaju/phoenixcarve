#!/usr/bin/env python3
"""
PhoenixCarve — Phase 3: Entropy Analysis
Disk-ah fixed blocks-ah pirichu ovvoru block-kum Shannon entropy (0-8 bits/byte) calculate pannum.
  ~0     -> wiped / zero-filled
  low    -> text, logs, config
  mid    -> code, uncompressed images, mixed
  high   -> compressed (JPG/ZIP/PNG) or ENCRYPTED
Carved files cover pannaadha high-entropy region = "unexplained" = possible encrypted
container / hidden data. Idhu dhaan investigator-ku mukkiyamaana lead.

Usage: python3 entropy.py evidence.dd [-r out/report.json] [-b 4096]  (block size auto if omitted)
"""
import argparse
import json
import math
import mmap
import os

try:
    import numpy as np
except ImportError:          # works without numpy, just slower
    np = None

CLASSES = [  # (upper bound, label)
    (0.0001, "zero"),
    (1.0, "sparse"),
    (4.5, "text"),
    (7.2, "binary"),
    (8.01, "high"),
]


def shannon(block):
    n = len(block)
    if not n:
        return 0.0
    if np is not None:
        counts = np.bincount(np.frombuffer(block, dtype=np.uint8), minlength=256)
        p = counts[counts > 0] / n
        return float(-(p * np.log2(p)).sum()) + 0.0
    ent = 0.0
    for c in (block.count(bytes([i])) for i in range(256)):
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent + 0.0


def classify(e):
    for bound, label in CLASSES:
        if e < bound:
            return label
    return "high"


def block_map(data, block_size):
    out = []
    for off in range(0, len(data), block_size):
        e = shannon(data[off:off + block_size])
        out.append({"offset": off, "entropy": round(e, 3), "class": classify(e)})
    return out


def merge_regions(blocks, block_size, total):
    regions = []
    for b in blocks:
        if regions and regions[-1]["class"] == b["class"]:
            r = regions[-1]
            r["end"] = min(b["offset"] + block_size, total)
            r["_sum"] += b["entropy"]
            r["_n"] += 1
        else:
            regions.append({"start": b["offset"], "end": min(b["offset"] + block_size, total),
                            "class": b["class"], "_sum": b["entropy"], "_n": 1})
    for r in regions:
        r["avg_entropy"] = abs(round(r.pop("_sum") / r.pop("_n"), 3))
        r["size"] = r["end"] - r["start"]
    return regions


def auto_block(total):
    """~2000 blocks on the map, power of 2, at least 512 bytes."""
    b = 512
    while total / b > 2048:
        b *= 2
    return b


def refine(data, start, end, step=256, threshold=6.5):
    """Block boundary 4 KB granularity-la irukkum; 256-byte steps-la narrow panni
    encrypted data exact-ah enga start/end aagudhu-nu kandupidikkum."""
    lo = max(0, start - step * 16)
    s = start
    for o in range(lo, min(end, start + step * 16), step):
        if shannon(data[o:o + step]) >= threshold:
            s = o
            break
    e = end
    for o in range(min(len(data), end + step * 16) - step, max(s, end - step * 16), -step):
        if shannon(data[o:o + step]) >= threshold:
            e = o + step
            break
    return s, e


def find_unexplained(regions, carved, min_size):
    """High-entropy regions that no carved file explains."""
    spans = sorted((c["start_offset"], c["end_offset"]) for c in carved)
    hits = []
    for r in regions:
        if r["class"] != "high" or r["size"] < min_size:
            continue
        covered = 0
        for s, e in spans:
            lo, hi = max(s, r["start"]), min(e, r["end"])
            if hi > lo:
                covered += hi - lo
        frac = covered / r["size"]
        if frac < 0.5:
            hits.append({**r, "covered_by_carved": round(frac, 3),
                         "verdict": "possible encrypted container / hidden data"})
    return hits


def analyze(image, report_path=None, block_size=None, min_size=None):
    carved = json.load(open(report_path))["carved"] if report_path else []
    with open(image, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        total = len(data)
        block_size = block_size or auto_block(total)
        min_size = min_size or max(block_size * 2, 4096)
        blocks = block_map(data, block_size)
        regions = merge_regions(blocks, block_size, total)
        unexplained = find_unexplained(regions, carved, min_size)
        for u in unexplained:
            u["start"], u["end"] = refine(data, u["start"], u["end"])
            u["size"] = u["end"] - u["start"]

    dist = {}
    for b in blocks:
        dist[b["class"]] = dist.get(b["class"], 0) + 1
    return {
        "image": os.path.abspath(image),
        "block_size": block_size,
        "total_bytes": total,
        "class_distribution": {k: round(v / len(blocks), 4) for k, v in dist.items()},
        "blocks": blocks,
        "regions": regions,
        "unexplained_high_entropy": unexplained,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("-r", "--report", help="report.json from carver.py")
    ap.add_argument("-b", "--block", type=int, default=None, help="block size (default: auto)")
    ap.add_argument("-o", "--out", default=None)
    a = ap.parse_args()

    res = analyze(a.image, a.report, a.block)
    bs = res["block_size"]
    out = a.out or (os.path.join(os.path.dirname(a.report), "entropy.json") if a.report else "entropy.json")
    json.dump(res, open(out, "w"), indent=2)

    print(f"[*] {len(res['blocks'])} blocks of {bs} bytes")
    print(f"[*] Distribution: " + ", ".join(f"{k} {v * 100:.1f}%" for k, v in res["class_distribution"].items()))
    for r in res["regions"]:
        if r["class"] in ("zero", "high") and r["size"] >= bs * 4:
            print(f"    {r['class']:6} 0x{r['start']:08x}-0x{r['end']:08x}  {r['size']:>9} B  avg {r['avg_entropy']}")
    if res["unexplained_high_entropy"]:
        print("[!] Unexplained high-entropy regions:")
        for u in res["unexplained_high_entropy"]:
            print(f"    0x{u['start']:08x}-0x{u['end']:08x}  {u['size']} B  "
                  f"(carved coverage {u['covered_by_carved'] * 100:.0f}%) -> {u['verdict']}")
    print(f"[*] Saved {out}")


if __name__ == "__main__":
    main()
