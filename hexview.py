#!/usr/bin/env python3
"""
PhoenixCarve — Phase 3: Terminal Hex Viewer
Carved file region-ah colour-la highlight pannum; signature bytes bold-ah varum.

Usage:
    python3 hexview.py evidence.dd 0x1c76 256 -r out/report.json
    python3 hexview.py evidence.dd --file jpg_0000001c76.jpg -r out/report.json
"""
import argparse
import json
import sys

RESET, DIM, BOLD = "\033[0m", "\033[2m", "\033[1m"
COLORS = {"valid": "\033[38;5;214m", "corrupt": "\033[38;5;160m", "unverified": "\033[38;5;110m"}


def region_at(regions, off):
    for r in regions:
        if r["start_offset"] <= off < r["end_offset"]:
            return r
    return None


def dump(data, base, regions, sig_len=4, width=16, color=True):
    lines = []
    for row in range(0, len(data), width):
        chunk = data[row:row + width]
        hx, asc = [], []
        for i, byte in enumerate(chunk):
            off = base + row + i
            r = region_at(regions, off)
            h = f"{byte:02x}"
            ch = chr(byte) if 32 <= byte < 127 else "."
            if color:
                if r:
                    style = COLORS.get(r.get("status", "unverified"), "")
                    if off - r["start_offset"] < sig_len or r["end_offset"] - off <= 2:
                        style += BOLD           # header signature / footer bytes
                    h, ch = f"{style}{h}{RESET}", f"{style}{ch}{RESET}"
                elif byte == 0:
                    h, ch = f"{DIM}{h}{RESET}", f"{DIM}{ch}{RESET}"
            hx.append(h)
            asc.append(ch)
        pad = "   " * (width - len(chunk))
        mid = " ".join(hx[:8]) + "  " + " ".join(hx[8:])
        lines.append(f"{base + row:08x}  {mid}{pad}  |{''.join(asc)}|")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("offset", nargs="?", default="0", help="decimal or 0x hex")
    ap.add_argument("length", nargs="?", type=int, default=256)
    ap.add_argument("-r", "--report")
    ap.add_argument("--file", help="jump to a carved file by name")
    ap.add_argument("--no-color", action="store_true")
    a = ap.parse_args()

    regions = json.load(open(a.report))["carved"] if a.report else []
    off = int(a.offset, 0)
    if a.file:
        match = [r for r in regions if r["file"].endswith(a.file)]
        if not match:
            sys.exit(f"[!] {a.file} not in report")
        off = match[0]["start_offset"]
        r = match[0]
        print(f"{r['file']}  {r['size']} bytes  [{r.get('status')}] {r.get('reason', '')}")

    start = max(0, off - (off % 16))
    with open(a.image, "rb") as f:
        f.seek(start)
        data = f.read(a.length)
    print(dump(data, start, regions, color=not a.no_color and sys.stdout.isatty()))


if __name__ == "__main__":
    main()
