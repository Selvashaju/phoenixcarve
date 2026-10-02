#!/usr/bin/env python3
"""
Builds a fake 'deleted files' disk image with known files hidden inside
random junk, plus ground_truth.json so we can measure recovery accuracy.
Needs: pip3 install pillow
"""
import argparse, io, json, os, random, struct, zipfile
from PIL import Image

ap = argparse.ArgumentParser()
ap.add_argument("--seed", type=int, default=42)
ap.add_argument("--out", default="test_evidence", help="output name prefix")
ap.add_argument("--align", type=int, default=0, help="start files on N-byte boundaries (512 = sector aligned)")
ARGS = ap.parse_args()
random.seed(ARGS.seed)

def jpg(color):
    b = io.BytesIO(); Image.new("RGB", (120, 80), color).save(b, "JPEG"); return b.getvalue()

def png(color):
    b = io.BytesIO(); Image.new("RGB", (64, 64), color).save(b, "PNG"); return b.getvalue()

def bmp(color):
    b = io.BytesIO(); Image.new("RGB", (32, 32), color).save(b, "BMP"); return b.getvalue()

def gif(color):
    b = io.BytesIO(); Image.new("P", (40, 40), 3).save(b, "GIF"); return b.getvalue()

def pdf():
    return (b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Kids[]/Count 0>>endobj\n"
            b"trailer<</Root 1 0 R>>\n%%EOF\n")

def zipf():
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("secret/notes.txt", "Meet at dock 7, 2300 hrs")
    return b.getvalue()

def docx():
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document>Confidential</w:document>")
    return b.getvalue()

def pe_exe():
    """Minimal PE: DOS header -> PE header -> 1 section (raw data at 0x200, 0x200 bytes)."""
    b = bytearray(0x400)
    b[0:2] = b"MZ"
    struct.pack_into("<I", b, 0x3C, 0x80)                  # e_lfanew
    b[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", b, 0x84, 0x14C, 1)             # i386, 1 section
    struct.pack_into("<H", b, 0x94, 0xE0)                  # SizeOfOptionalHeader
    sec = 0x80 + 24 + 0xE0
    b[sec:sec + 8] = b".text\0\0\0"
    struct.pack_into("<II", b, sec + 16, 0x200, 0x200)     # SizeOfRawData, PointerToRawData
    b[0x200:0x400] = bytes(random.randrange(256) for _ in range(0x200)).replace(b"MZ", b"mz")
    return bytes(b)

def broken_png():
    d = bytearray(png((90, 90, 250)))
    d[45] ^= 0xFF                                          # flip a byte inside IDAT -> CRC fails
    return bytes(d)

WORDS = ("the user login session failed accepted update config path system file "
         "network packet error warning info service started stopped kernel driver "
         "cache temp backup admin password reset token request response").split()

def junk(n):
    # log/slack-space style text: realistic low entropy, no accidental signatures
    out = bytearray()
    while len(out) < n:
        out += (" ".join(random.choice(WORDS) for _ in range(random.randint(4, 12))) + "\n").encode()
    return bytes(out[:n])

# (type, data, expected validator status, note)
J1, J2 = jpg((200, 30, 30)), jpg((30, 30, 200))
files = [
    ("jpg", J1, "valid", "clean"),
    ("png", png((30, 200, 30)), "valid", "clean"),
    ("pdf", pdf(), "valid", "clean"),
    ("zip", zipf(), "valid", "clean"),
    ("zip", docx(), "valid", "DOCX"),
    ("bmp", bmp((120, 120, 0)), "valid", "clean"),
    ("gif", gif(0), "valid", "clean"),
    ("png", broken_png(), "corrupt", "bit-flipped IDAT"),
    ("exe", pe_exe(), "valid", "PE, no footer"),
    ("jpg", J1[: len(J1) * 6 // 10], "corrupt", "truncated (60%)"),
    ("jpg", J2, "valid", "right after truncated"),
]

img, truth = bytearray(), []
for kind, data, expect, note in files:
    pad = bytearray(junk(random.randint(2048, 8192)))
    if random.random() < 0.5:                       # stray 'MZ' = classic false positive
        p = random.randrange(100, len(pad) - 100)
        pad[p:p + 2] = b"MZ"
    img += pad
    if ARGS.align:
        img += junk(-len(img) % ARGS.align)
    truth.append({"type": kind, "offset": len(img), "size": len(data), "expect": expect, "note": note})
    img += data
# Planted anomalies for Phase 3 entropy analysis (not files, so not in ground truth)
hidden = []
img += junk(4096)
hidden.append({"kind": "wiped (zero-filled)", "offset": len(img), "size": 16384})
img += bytes(16384)
img += junk(4096)
blob = bytes(random.randrange(256) for _ in range(32768))   # looks like AES ciphertext
hidden.append({"kind": "encrypted container (no header)", "offset": len(img), "size": len(blob)})
img += blob
img += junk(4096)

with open(f"{ARGS.out}_hidden_regions.json" if ARGS.out != "test_evidence" else "hidden_regions.json", "w") as f:
    json.dump(hidden, f, indent=2)
truth_name = "ground_truth.json" if ARGS.out == "test_evidence" else f"{ARGS.out}_truth.json"
with open(f"{ARGS.out}.dd", "wb") as f:
    f.write(img)
with open(truth_name, "w") as f:
    json.dump(truth, f, indent=2)
print(f"Created {ARGS.out}.dd ({len(img)} bytes) with {len(files)} hidden files")
