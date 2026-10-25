"""The single place that decides who may touch a document.

Every route that reads, changes, deletes or shares a document goes through
access_level() (via app.need()). It reads the database on every call: there are no
cached permissions, signed links or long-lived tokens to outlive a revocation.
Admins get NO implicit access to content: they manage users and read the audit log,
but need an explicit grant like anyone else.
"""
from .db import now

LEVELS = {"read": 1, "edit": 2, "owner": 3}


def access_level(db, user, doc_id):
    if not user or not user["active"]:
        return None
    doc = db.execute("SELECT owner_id, deleted_at FROM documents WHERE id=?", (doc_id,)).fetchone()
    if doc is None or doc["deleted_at"] is not None:
        return None
    if doc["owner_id"] == user["id"]:
        return "owner"
    g = db.execute(
        "SELECT level FROM grants WHERE doc_id=? AND user_id=? AND revoked_at IS NULL "
        "AND (expires_at IS NULL OR expires_at > ?)", (doc_id, user["id"], now())).fetchone()
    return g["level"] if g else None
