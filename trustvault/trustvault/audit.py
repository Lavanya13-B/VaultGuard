"""Tamper-evident audit log.

Three independent layers, so no single mistake makes the record forgeable:
  1. SQLite triggers reject UPDATE and DELETE on audit_log (schema.sql).
  2. Every row stores prev_hash and hash = HMAC-SHA256(audit_key, prev_hash | row).
     Editing, deleting, inserting or re-ordering any row breaks the chain from that
     point on. The key is NOT in the database, so someone who can write to the DB file
     (but not read the key) cannot recompute the chain.
  3. head() gives (count, last hash). Copy it somewhere the app cannot write (a ticket,
     a WORM bucket, an email) and verify(expected=...) will also catch truncation of
     the tail, which a chain alone cannot see.
"""
import hashlib
import hmac
import json

from .db import now, tx

GENESIS = "0" * 64
FIELDS = ("ts", "actor_id", "actor_name", "action", "outcome", "doc_id", "target_user", "detail", "ip")


def _mac(key: bytes, prev: str, rec: dict) -> str:
    body = json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hmac.new(key, f"{prev}|{body}".encode(), hashlib.sha256).hexdigest()


def record(db, key, *, actor_id=None, actor_name=None, action, outcome="success",
           doc_id=None, target_user=None, detail=None, ip=None):
    """Append one row. If the caller already holds a transaction the row commits (or
    rolls back) atomically with the action it describes."""
    rec = {
        "ts": now(), "actor_id": actor_id, "actor_name": actor_name, "action": action,
        "outcome": outcome, "doc_id": (str(doc_id)[:64] if doc_id else None),
        "target_user": target_user,
        "detail": json.dumps(detail, sort_keys=True) if detail is not None else None,
        "ip": ip,
    }
    with tx(db):
        row = db.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev = row["hash"] if row else GENESIS
        h = _mac(key, prev, rec)
        db.execute(
            "INSERT INTO audit_log (ts,actor_id,actor_name,action,outcome,doc_id,target_user,"
            "detail,ip,prev_hash,hash) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (*[rec[f] for f in FIELDS], prev, h),
        )


def head(db):
    row = db.execute("SELECT COUNT(*) n, (SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1) h "
                     "FROM audit_log").fetchone()
    return {"count": row["n"], "hash": row["h"] or GENESIS}


def verify(db, key, expected=None):
    """Walk the whole chain. expected = {"count": n, "hash": h} from an earlier head()."""
    prev, n = GENESIS, 0
    for r in db.execute("SELECT * FROM audit_log ORDER BY id"):
        n += 1
        rec = {f: r[f] for f in FIELDS}
        if r["prev_hash"] != prev:
            return {"ok": False, "count": n, "bad_id": r["id"], "why": "chain link broken (row removed, inserted or reordered)"}
        if not hmac.compare_digest(_mac(key, prev, rec), r["hash"]):
            return {"ok": False, "count": n, "bad_id": r["id"], "why": "row content does not match its hash (edited)"}
        prev = r["hash"]
    if expected and (n < expected["count"] or (n == expected["count"] and prev != expected["hash"])):
        return {"ok": False, "count": n, "bad_id": None, "why": "log is shorter than, or differs from, the anchored head (truncated)"}
    return {"ok": True, "count": n, "hash": prev}
