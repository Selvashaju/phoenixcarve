#!/usr/bin/env python3
"""
PhoenixCarve — Phase 4: FastAPI backend
Run:  uvicorn server:app --reload     then open http://127.0.0.1:8000
"""
import json
import os
import re
import shutil
import stat
import traceback
from datetime import datetime, timezone

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse

from carver import HERE
from custody import CustodyLog
from pipeline import run_case

CASES = os.path.join(HERE, "cases")
os.makedirs(CASES, exist_ok=True)
app = FastAPI(title="PhoenixCarve", version="1.0")
CASE_RE = re.compile(r"^[A-Za-z0-9_-]{3,40}$")


# ---------- helpers ----------
def case_dir(case_no):
    if not CASE_RE.match(case_no):
        raise HTTPException(400, "Case number can use letters, digits, - and _ (3 to 40 characters).")
    return os.path.join(CASES, case_no)


def read_status(case_no):
    p = os.path.join(case_dir(case_no), "status.json")
    if not os.path.exists(p):
        raise HTTPException(404, f"Case {case_no} not found")
    return json.load(open(p))


def write_status(cno, **kw):
    p = os.path.join(case_dir(cno), "status.json")
    st = json.load(open(p)) if os.path.exists(p) else {}
    st.update(kw, updated_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    json.dump(st, open(p, "w"), indent=2)


def safe_path(base, rel):
    full = os.path.realpath(os.path.join(base, rel))
    if not full.startswith(os.path.realpath(base) + os.sep):
        raise HTTPException(400, "Invalid path")
    if not os.path.isfile(full):
        raise HTTPException(404, "File not found")
    return full


def worker(case_no, image, meta):
    try:
        res = run_case(image, case_dir(case_no), case_no, meta["examiner"], meta["org"], meta["purpose"],
                       progress=lambda s: write_status(case_no, stage=s))
        write_status(case_no, state="done", stage="done", pdf=os.path.basename(res["pdf"]),
                     pdf_sha256=res["pdf_sha256"])
    except Exception as e:
        write_status(case_no, state="failed", stage="failed", error=str(e), trace=traceback.format_exc()[-2000:])


# ---------- routes ----------
@app.get("/", response_class=HTMLResponse)
def dashboard():
    return open(os.path.join(HERE, "dashboard.html")).read()


@app.post("/api/cases", status_code=202)
async def create_case(background: BackgroundTasks, image: UploadFile = File(...),
                      case_no: str = Form(...), examiner: str = Form(...),
                      org: str = Form(""), purpose: str = Form("")):
    d = case_dir(case_no)
    if os.path.exists(d):
        raise HTTPException(409, f"Case {case_no} already exists. Use a new case number.")
    ev_dir = os.path.join(d, "evidence")
    os.makedirs(ev_dir)
    name = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(image.filename or "evidence.dd"))
    path = os.path.join(ev_dir, name)
    with open(path, "wb") as f:
        while chunk := await image.read(1 << 20):          # stream to disk, 1 MB at a time
            f.write(chunk)
    os.chmod(path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)  # evidence is read-only from here on

    meta = {"examiner": examiner.strip(), "org": org.strip(), "purpose": purpose.strip()}
    write_status(case_no, case_no=case_no, evidence=name, size=os.path.getsize(path), state="running",
                 stage="queued", created_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"), **meta)
    background.add_task(worker, case_no, path, meta)
    return {"case_no": case_no, "state": "running"}


@app.get("/api/cases")
def list_cases():
    out = []
    for c in sorted(os.listdir(CASES)):
        p = os.path.join(CASES, c, "status.json")
        if os.path.exists(p):
            st = json.load(open(p))
            st.pop("trace", None)
            out.append(st)
    return sorted(out, key=lambda s: s.get("created_utc", ""), reverse=True)


@app.get("/api/cases/{case_no}")
def get_case(case_no: str):
    st = read_status(case_no)
    st.pop("trace", None)
    d = case_dir(case_no)
    rp, ep = os.path.join(d, "report.json"), os.path.join(d, "entropy.json")
    if os.path.exists(rp):
        rep = json.load(open(rp))
        st.update(evidence_hash=rep["evidence"], summary=rep["summary"], validation=rep.get("validation"),
                  carved=rep["carved"])
    if os.path.exists(ep):
        st["unexplained"] = json.load(open(ep))["unexplained_high_entropy"]
    return st


@app.get("/api/cases/{case_no}/custody")
def custody(case_no: str):
    read_status(case_no)
    log = CustodyLog(os.path.join(case_dir(case_no), "custody.jsonl"))
    ok, msg = log.verify()
    return {"intact": ok, "message": msg, "entries": log.entries()}


@app.get("/api/cases/{case_no}/map")
def evidence_map(case_no: str):
    return FileResponse(safe_path(case_dir(case_no), "phoenix_map.html"), media_type="text/html")


@app.get("/api/cases/{case_no}/report")
def report(case_no: str):
    st = read_status(case_no)
    if st.get("state") != "done":
        raise HTTPException(409, "Report is not ready yet")
    return FileResponse(safe_path(case_dir(case_no), st["pdf"]), media_type="application/pdf",
                        filename=st["pdf"])


@app.get("/api/cases/{case_no}/files/{rel:path}")
def carved_file(case_no: str, rel: str):
    if rel.startswith("evidence/") or rel.endswith((".json", ".jsonl")):
        raise HTTPException(403, "Only carved files can be downloaded here")
    return FileResponse(safe_path(case_dir(case_no), rel), filename=os.path.basename(rel))


@app.delete("/api/cases/{case_no}")
def delete_case(case_no: str):
    d = case_dir(case_no)
    read_status(case_no)
    for root, _, files in os.walk(d):          # evidence is read-only; make writable to delete
        for f in files:
            os.chmod(os.path.join(root, f), stat.S_IWUSR | stat.S_IRUSR)
    shutil.rmtree(d)
    return {"deleted": case_no}
