"""
PhoenixCarve — Phase 2: Carved File Validator
Header match aana mattum podhadhu; file-oda internal structure correct-ah irukka-nu
check pannum. Each validator returns:
    {"status": "valid" | "corrupt" | "unverified", "reason": str, "true_size": int|None}
true_size = structure-la irundhu kandupidicha real file size (carve trim panna use aagum).
"""
import io
import struct
import zipfile
import zlib


def _r(status, reason, true_size=None):
    return {"status": status, "reason": reason, "true_size": true_size}


# ---------- JPEG: marker walk + entropy-data scan ----------
def v_jpg(b):
    if b[:2] != b"\xFF\xD8":
        return _r("corrupt", "missing SOI")
    i, n, scans = 2, len(b), 0
    while i < n - 1:
        if b[i] != 0xFF:
            return _r("corrupt", f"expected marker at +{i}")
        m = b[i + 1]
        if m == 0xFF:            # fill byte
            i += 1
            continue
        if m == 0xD9:
            return _r("valid" if scans else "corrupt",
                      "EOI reached" if scans else "EOI before any scan", i + 2)
        if 0xD0 <= m <= 0xD7 or m == 0x01:
            i += 2
            continue
        if m == 0xD8:
            return _r("corrupt", f"second SOI at +{i} (fragmented / truncated file)")
        if i + 4 > n:
            break
        seg_len = struct.unpack(">H", b[i + 2:i + 4])[0]
        if seg_len < 2:
            return _r("corrupt", f"bad segment length at +{i}")
        i += 2 + seg_len
        if m == 0xDA:            # Start of Scan -> entropy-coded data follows
            scans += 1
            while i < n - 1:
                if b[i] == 0xFF:
                    nx = b[i + 1]
                    if nx == 0x00 or 0xD0 <= nx <= 0xD7:
                        i += 2
                        continue
                    if nx == 0xD8:
                        return _r("corrupt", f"SOI inside scan data at +{i} (fragmented / truncated file)")
                    break        # real marker -> back to outer loop
                i += 1
    return _r("corrupt", "no EOI marker")


# ---------- PNG: chunk walk with CRC check ----------
def v_png(b):
    if b[:8] != b"\x89PNG\r\n\x1a\n":
        return _r("corrupt", "bad PNG signature")
    i, first = 8, True
    while i + 12 <= len(b):
        length = struct.unpack(">I", b[i:i + 4])[0]
        ctype = b[i + 4:i + 8]
        if first and ctype != b"IHDR":
            return _r("corrupt", "first chunk is not IHDR")
        first = False
        end = i + 12 + length
        if end > len(b):
            return _r("corrupt", f"chunk {ctype!r} runs past end")
        crc = struct.unpack(">I", b[end - 4:end])[0]
        if zlib.crc32(b[i + 4:end - 4]) & 0xFFFFFFFF != crc:
            return _r("corrupt", f"CRC mismatch in {ctype.decode(errors='replace')} chunk at +{i}")
        if ctype == b"IEND":
            return _r("valid", "all chunk CRCs OK", end)
        i = end
    return _r("corrupt", "no IEND chunk")


# ---------- GIF ----------
def v_gif(b):
    if b[:6] not in (b"GIF87a", b"GIF89a") or len(b) < 13:
        return _r("corrupt", "bad GIF header")
    w, h = struct.unpack("<HH", b[6:10])
    if not (w and h):
        return _r("corrupt", "zero width/height")
    if b[-1:] != b";":
        return _r("corrupt", "missing trailer 0x3B")
    return _r("valid", f"{w}x{h}, trailer present")


# ---------- BMP ----------
def v_bmp(b):
    if len(b) < 26 or b[:2] != b"BM":
        return _r("corrupt", "too small / bad header")
    size = struct.unpack("<I", b[2:6])[0]
    pix_off = struct.unpack("<I", b[10:14])[0]
    dib = struct.unpack("<I", b[14:18])[0]
    if dib not in (12, 40, 52, 56, 108, 124):
        return _r("corrupt", f"unknown DIB header size {dib}")
    if not (14 + dib <= pix_off < size):
        return _r("corrupt", "pixel offset out of range")
    if size > len(b):
        return _r("corrupt", f"declared size {size} > carved {len(b)} (truncated)")
    return _r("valid", f"DIB {dib}, size matches", size)


# ---------- PDF ----------
def v_pdf(b):
    if not b.startswith(b"%PDF-"):
        return _r("corrupt", "bad header")
    if b"%%EOF" not in b[-1024:]:
        return _r("corrupt", "no %%EOF near end")
    objs = b.count(b" obj")
    if not objs:
        return _r("corrupt", "no objects")
    if b"trailer" not in b and b"/XRef" not in b:
        return _r("corrupt", "no trailer / xref stream")
    return _r("valid", f"{objs} objects, trailer present")


# ---------- ZIP (also DOCX/XLSX/APK/JAR) ----------
def v_zip(b):
    try:
        with zipfile.ZipFile(io.BytesIO(b)) as z:
            bad = z.testzip()
            if bad:
                return _r("corrupt", f"CRC failure in member {bad}")
            names = z.namelist()
            kind = "DOCX" if "word/document.xml" in names else \
                   "XLSX" if "xl/workbook.xml" in names else \
                   "APK" if "AndroidManifest.xml" in names else "ZIP"
            return _r("valid", f"{kind}, {len(names)} members, CRCs OK")
    except Exception as e:
        return _r("corrupt", f"zip error: {e}")


# ---------- EXE (PE): e_lfanew -> 'PE\0\0' + section table gives real size ----------
def v_exe(b):
    if len(b) < 0x40 or b[:2] != b"MZ":
        return _r("corrupt", "no DOS header")
    pe = struct.unpack("<I", b[0x3C:0x40])[0]
    if pe < 0x40 or pe + 24 > len(b) or b[pe:pe + 4] != b"PE\0\0":
        return _r("corrupt", "no PE signature (random 'MZ' false positive)")
    nsec = struct.unpack("<H", b[pe + 6:pe + 8])[0]
    opt = struct.unpack("<H", b[pe + 20:pe + 22])[0]
    sec = pe + 24 + opt
    if not (0 < nsec <= 96) or sec + 40 * nsec > len(b):
        return _r("corrupt", "bad section table")
    end = sec + 40 * nsec
    for k in range(nsec):
        s = sec + 40 * k
        raw_size, raw_ptr = struct.unpack("<II", b[s + 16:s + 24])
        end = max(end, raw_ptr + raw_size)
    if end > len(b):
        return _r("corrupt", f"sections need {end} bytes, only {len(b)} carved")
    return _r("valid", f"PE with {nsec} sections", end)


# ---------- SQLite ----------
def v_sqlite(b):
    if len(b) < 100:
        return _r("corrupt", "header truncated")
    ps = struct.unpack(">H", b[16:18])[0]
    ps = 65536 if ps == 1 else ps
    if ps < 512 or ps & (ps - 1):
        return _r("corrupt", f"invalid page size {ps}")
    pages = struct.unpack(">I", b[28:32])[0]
    true = ps * pages if pages else None
    if true and true > len(b):
        return _r("corrupt", f"needs {true} bytes, only {len(b)} carved")
    return _r("valid", f"page size {ps}, {pages} pages", true)


VALIDATORS = {
    "jpg": v_jpg, "png": v_png, "gif": v_gif, "bmp": v_bmp, "pdf": v_pdf,
    "zip": v_zip, "exe": v_exe, "db": v_sqlite,
}


def validate(ext, blob):
    fn = VALIDATORS.get(ext)
    if not fn:
        return _r("unverified", "no structural validator for this type yet")
    try:
        return fn(bytes(blob))
    except Exception as e:
        return _r("corrupt", f"validator crashed: {e}")
