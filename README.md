# PhoenixCarve

**Signature-driven forensic data resurrection engine.** PhoenixCarve recovers deleted and hidden files from raw disk images by file signature, checks that every recovered file is structurally sound, maps the whole disk by entropy to expose encrypted or wiped areas, and writes a court-style PDF report backed by a tamper-evident chain of custody.

Built as Micro Project 03 (Digital Forensics, OBCFC 2025-26, Karunya Institute of Technology and Sciences): *implement a tool that uses file signature analysis and a hex editor to carve lost data from a disk image.*

## What it does

| Stage | Module | What happens |
|---|---|---|
| Carve | `carver.py` | Finds headers from `signatures.json`, ends each file by footer, by the size stored in its header, or at the next header. Evidence is opened read-only and hashed before and after. |
| Validate | `validator.py` | Walks JPEG markers, checks PNG and ZIP CRCs, reads PE section tables, BMP and SQLite headers. Trims over-carved files to their true size and rejects random signature matches. |
| Map | `entropy.py`, `visualize.py` | Shannon entropy per block. High-entropy data that no recovered file explains is flagged as a possible encrypted container; zero-filled runs as possible wiping. Produces a single-file HTML map with a clickable hex viewer. |
| Inspect | `hexview.py` | Terminal hex dump with recovered regions coloured by validation status. |
| Report | `report_pdf.py`, `custody.py` | A4 PDF with evidence hashes, method, findings, entropy figure, file table, limitations, custody chain and examiner declaration. Every step is appended to a hash-chained custody log; editing any entry breaks the chain. |
| Serve | `server.py`, `dashboard.html` | FastAPI backend and browser dashboard: upload an image, follow progress, open the map, download the report. |
| Measure | `evaluate.py`, `benchmark.py` | Precision, recall, F1, byte recovery and damage detection against ground truth, and a head-to-head run against Foremost and Scalpel. |

Supported types: JPG, PNG, GIF, BMP, PDF, ZIP (with DOCX, XLSX, APK detection), EXE (PE), SQLite, DOC/XLS (OLE), RAR, 7z, GZ, MP3, WAV, MP4. Add a type by adding one line to `signatures.json`.

## Quick start (macOS / Linux)

```bash
pip3 install -r requirements.txt
python3 make_test_image.py                     # test_evidence.dd + ground_truth.json

# Web dashboard
uvicorn server:app --reload                    # open http://127.0.0.1:8000

# Or everything from the command line
python3 pipeline.py test_evidence.dd --case PC-2026-001 \
  --examiner "Your Name" --truth ground_truth.json
```

Individual tools:

```bash
python3 carver.py image.dd -o out              # carve + validate
python3 evaluate.py out/report.json ground_truth.json
python3 visualize.py image.dd out/report.json  # out/phoenix_map.html
python3 hexview.py image.dd --file exe -r out/report.json
python3 custody.py cases/PC-2026-001/custody.jsonl   # verify chain
python3 benchmark.py --images 10               # needs: brew install foremost scalpel
```

## Results

On 20 generated images (220 planted files, including a bit-flipped PNG, a truncated JPEG followed by an intact one, a footerless PE executable and stray `MZ` bytes), carved at byte offsets and at 512-byte sector alignment:

| Tool | Exact | Partial | Missed | False pos. | F1 | Damaged files flagged |
|---|---|---|---|---|---|---|
| PhoenixCarve | 200 | 20 | 0 | 0 | 90.9% | 100% |
| Foremost 1.5.7 | 160 | 20 | 40 | 0 | 80.0% | not supported |
| Scalpel 1.60 | 100 | 120 | 0 | 143 | 34.3% | not supported |

Read these numbers with care. The test images were built by the same author as the tool, so they favour the cases PhoenixCarve was designed for. Scalpel was run with a minimal configuration; most of its partials are ZIP files cut 18 bytes short and PDFs missing a final newline, which a tuned configuration would partly fix. Foremost's misses are the synthetic PE file and the intact JPEG that its carve of the truncated JPEG swallowed. A fair next step is the DFRWS 2006 carving challenge image.

## Limitations

Carving assumes contiguous storage; fragmented files are recovered up to the first break and reported as damaged, not repaired. File names, paths and timestamps are not recoverable by carving. High entropy suggests, but does not prove, encryption.

## Project layout

```
carver.py  validator.py  signatures.json     carving and validation
entropy.py visualize.py  hexview.py          analysis and inspection
custody.py report_pdf.py pipeline.py         chain of custody and reporting
server.py  dashboard.html                    web app
evaluate.py benchmark.py make_test_image.py  testing
```

Author: Shajilin Benadict S, B.Sc. Information Security and Digital Forensics, Karunya Institute of Technology and Sciences.
