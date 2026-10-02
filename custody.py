"""
PhoenixCarve — Phase 4: Tamper-evident Chain of Custody
Ovvoru entry-um previous entry-oda hash-ah ulla vechirukkum (blockchain maadhiri chain).
Naduvula yaaravadhu oru line maathunaa, adhukku apparam ulla ella hash-um break aagum.
"""
import getpass
import hashlib
import json
import os
import platform
from datetime import datetime, timezone

GENESIS = "0" * 64


def _digest(entry):
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


class CustodyLog:
    def __init__(self, path):
        self.path = path

    def entries(self):
        if not os.path.exists(self.path):
            return []
        with open(self.path) as f:
            return [json.loads(line) for line in f if line.strip()]

    def add(self, action, detail="", actor=None, **extra):
        prev = self.entries()
        entry = {
            "seq": len(prev) + 1,
            "time_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "actor": actor or getpass.getuser(),
            "host": platform.node(),
            "action": action,
            "detail": detail,
            **extra,
            "prev_hash": prev[-1]["entry_hash"] if prev else GENESIS,
        }
        entry["entry_hash"] = _digest(entry)
        with open(self.path, "a") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def verify(self):
        """Returns (ok, message)."""
        prev = GENESIS
        for e in self.entries():
            if e["prev_hash"] != prev:
                return False, f"chain broken at entry {e['seq']} (prev_hash mismatch)"
            if _digest(e) != e["entry_hash"]:
                return False, f"entry {e['seq']} was modified after it was written"
            prev = e["entry_hash"]
        return True, "all entries intact"


if __name__ == "__main__":
    import sys
    log = CustodyLog(sys.argv[1] if len(sys.argv) > 1 else "custody.jsonl")
    ok, msg = log.verify()
    for e in log.entries():
        print(f"{e['seq']:>3}  {e['time_utc']}  {e['actor']:<10} {e['action']:<22} {e['detail']}")
    print(("[OK] " if ok else "[TAMPERED] ") + msg)
