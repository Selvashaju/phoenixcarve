#!/usr/bin/env python3
"""
PhoenixCarve — Signature-Driven Forensic Data Resurrection Engine
Phase 1: signature DB + header/footer carving + chain-of-custody hashing.
Phase 2: structural validation, size trimming, false-positive filtering.

Usage:
    python3 carver.py evidence.dd -o output_dir
    python3 carver.py evidence.dd -t jpg png pdf
"""
import argparse
import hashlib
import json
import mmap
import os
import sys
import time

from validator import validate
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))


# ---------- Chain of custody ----------
def hash_file(path, chunk=1 << 20):
    sha, md5 = hashlib.sha256(), hashlib.md5()
    with open(path, "rb") as f:
        while block := f.read(chunk):
            sha.update(block)
            md5.update(block)
    return sha.hexdigest(), md5.hexdigest()


def hash_bytes(data):
    return hashlib.sha256(data).hexdigest(), hashlib.md5(data).hexdigest()


# ---------- Signature DB ----------
def load_signatures(path, only=None):
    with open(path) as f:
        raw = json.load(f)
    sigs = {}
    for name, s in raw.items():
        if only and name not in only:
            continue
        sigs[name] = {
            "header": bytes.fromhex(s["header"]),
            "footer": bytes.fromhex(s["footer"]) if s.get("footer") else None,
            "max_size": s["max_size"],
            "footer_extra": s.get("footer_extra", 0),
            "footer_last": s.get("footer_last", False),
            "header_offset": s.get("header_offset", 0),
            "size_field": s.get("size_field"),
            "ext": s.get("ext", name),
            "drop_if_invalid": s.get("drop_if_invalid", False),
        }
    return sigs


def find_all(data, pattern):
    """Every offset where pattern occurs (like a librarian scanning every page)."""
    pos = data.find(pattern)
    while pos != -1:
        yield pos
        pos = data.find(pattern, pos + 1)


# ---------- End-of-file detection ----------
def find_end(data, start, sig, next_start):
    """Return (end_offset, method). end is exclusive."""
    limit = min(start + sig["max_size"], len(data))

    # 1) Size stored inside the header (BMP, WAV)
    sf = sig["size_field"]
    if sf:
        a = start + sf["offset"]
        if a + sf["length"] > len(data):
            return None, None
        size = int.from_bytes(data[a:a + sf["length"]], sf["endian"]) + sf.get("add", 0)
        if size <= len(sig["header"]) or size > sig["max_size"]:
            return None, None  # nonsense size -> false positive
        return min(start + size, len(data)), "size-field"

    # 2) Footer marker (JPG, PNG, PDF, ZIP)
    if sig["footer"]:
        body = start + len(sig["header"])
        if sig["footer_last"]:
            # PDFs can have several %%EOF (incremental saves); take the last
            # one before the next PDF begins.
            window_end = min(limit, next_start) if next_start else limit
            pos = data.rfind(sig["footer"], body, window_end)
        else:
            pos = data.find(sig["footer"], body, limit)
        if pos == -1:
            return None, None
        end = pos + len(sig["footer"]) + sig["footer_extra"]
        if sig["footer_extra"] and end + 2 <= len(data) and sig["ext"] == "zip":
            # ZIP EOCD: last 2 bytes of fixed part = comment length
            end += int.from_bytes(data[end - 2:end], "little")
        if sig["ext"] == "pdf":
            # %%EOF is usually followed by an end-of-line; keep it
            while end < len(data) and data[end:end + 1] in (b"\r", b"\n"):
                end += 1
        return min(end, len(data)), "footer"

    # 3) No footer: carve until the next known header or max_size
    end = min(limit, next_start) if next_start else limit
    return end, "bounded"


# ---------- Carving ----------
def carve(image, out_dir, sigs, drop_invalid=False):
    os.makedirs(out_dir, exist_ok=True)
    started = time.time()

    print(f"[*] Hashing evidence before carving...")
    sha_before, md5_before = hash_file(image)

    results = []
    with open(image, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        # Collect every header hit first, so "bounded" carves know where the next file starts
        hits = []
        for name, sig in sigs.items():
            for pos in find_all(data, sig["header"]):
                start = pos - sig["header_offset"]
                if start >= 0:
                    hits.append((start, name))
        hits.sort()
        all_starts = [h[0] for h in hits]
        print(f"[*] {len(hits)} candidate headers found")

        dropped = 0
        last_end = {}  # skip headers nested inside an already carved file of same type
        for i, (start, name) in enumerate(hits):
            sig = sigs[name]
            if start < last_end.get(name, -1):
                continue
            next_start = next((s for s in all_starts[i + 1:] if s > start), None)
            end, method = find_end(data, start, sig, next_start)
            if end is None or end <= start:
                continue

            blob = data[start:end]
            check = validate(sig["ext"], blob)

            # Structure told us the real size -> trim the over-carve
            if check["true_size"] and check["true_size"] < len(blob):
                end = start + check["true_size"]
                blob = data[start:end]
                method += "+trimmed"

            if check["status"] == "corrupt" and (drop_invalid or sig["drop_if_invalid"]):
                dropped += 1
                continue

            sha, md5 = hash_bytes(blob)
            fname = f"{name}_{start:010x}.{sig['ext']}"
            sub = os.path.join(out_dir, sig["ext"])
            os.makedirs(sub, exist_ok=True)
            with open(os.path.join(sub, fname), "wb") as o:
                o.write(blob)

            # Only a trusted carve "owns" its region. A corrupt one may have
            # swallowed the next file (fragmentation), so let that file be carved too.
            if check["status"] != "corrupt":
                last_end[name] = end
            results.append({
                "file": f"{sig['ext']}/{fname}",
                "type": name,
                "start_offset": start,
                "end_offset": end,
                "size": end - start,
                "method": method,
                "status": check["status"],
                "reason": check["reason"],
                "sha256": sha,
                "md5": md5,
            })
            tag = {"valid": "OK ", "corrupt": "BAD", "unverified": " ? "}[check["status"]]
            print(f"  [{tag}] {name:6} @ 0x{start:08x}  {end - start:>10} bytes  ({method}) - {check['reason']}")

    sha_after, _ = hash_file(image)
    integrity = sha_before == sha_after

    report = {
        "tool": "PhoenixCarve",
        "phase": 2,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "evidence": {
            "path": os.path.abspath(image),
            "size": os.path.getsize(image),
            "sha256_before": sha_before,
            "sha256_after": sha_after,
            "md5": md5_before,
            "integrity_preserved": integrity,
        },
        "duration_sec": round(time.time() - started, 3),
        "summary": {},
        "validation": {"valid": 0, "corrupt": 0, "unverified": 0, "false_positives_dropped": dropped},
        "carved": results,
    }
    for r in results:
        report["summary"][r["type"]] = report["summary"].get(r["type"], 0) + 1
        report["validation"][r["status"]] += 1

    with open(os.path.join(out_dir, "report.json"), "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[*] Carved {len(results)} files in {report['duration_sec']}s -> {out_dir}")
    print(f"[*] Summary: {report['summary']}")
    print(f"[*] Validation: {report['validation']}")
    print(f"[*] Evidence integrity: {'PRESERVED' if integrity else 'CHANGED!'} (SHA-256 {sha_before[:16]}...)")
    return report


def main():
    ap = argparse.ArgumentParser(description="PhoenixCarve - signature-based file carver")
    ap.add_argument("image", help="Raw disk image (.dd / .img / .raw)")
    ap.add_argument("-o", "--out", default="carved_output", help="Output directory")
    ap.add_argument("-s", "--sigs", default=os.path.join(HERE, "signatures.json"))
    ap.add_argument("--drop-invalid", action="store_true", help="Don't save files that fail validation")
    ap.add_argument("-t", "--types", nargs="*", help="Only carve these types (e.g. jpg png)")
    args = ap.parse_args()

    if not os.path.isfile(args.image):
        sys.exit(f"[!] Image not found: {args.image}")
    sigs = load_signatures(args.sigs, args.types)
    if not sigs:
        sys.exit("[!] No signatures loaded")
    carve(args.image, args.out, sigs, args.drop_invalid)


if __name__ == "__main__":
    main()
