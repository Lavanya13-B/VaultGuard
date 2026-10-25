import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from werkzeug.security import check_password_hash, generate_password_hash

from .db import now, tx

MIN_PASSWORD = 12
# Verified against when the username doesn't exist, so unknown users cost the same time.
_DUMMY = generate_password_hash("not-a-real-password")


def hash_password(pw):
    return generate_password_hash(pw, method="scrypt")


def check_password(user, pw):
    return check_password_hash(user["password_hash"] if user else _DUMMY, pw) and user is not None


def _h(token):
    return hashlib.sha256(token.encode()).hexdigest()


def _parse(ts):
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def create_session(db, user_id, ip):
    token = secrets.token_urlsafe(32)
    with tx(db):
        db.execute("INSERT INTO sessions VALUES (?,?,?,?,?,?)",
                   (_h(token), user_id, secrets.token_urlsafe(24), now(), now(), ip))
    return token


def load_session(db, token, idle_minutes, absolute_hours):
    row = db.execute(
        "SELECT s.*, u.id uid FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?",
        (_h(token),)).fetchone()
    if not row:
        return None
    t = datetime.now(timezone.utc)
    user = db.execute("SELECT * FROM users WHERE id=?", (row["user_id"],)).fetchone()
    if (not user["active"] or t - _parse(row["last_seen"]) > timedelta(minutes=idle_minutes)
            or t - _parse(row["created_at"]) > timedelta(hours=absolute_hours)):
        db.execute("DELETE FROM sessions WHERE token_hash=?", (row["token_hash"],))
        return None
    db.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (now(), row["token_hash"]))
    return {"user": user, "csrf": row["csrf"], "token_hash": row["token_hash"]}


def destroy_sessions(db, user_id, keep_hash=None):
    db.execute("DELETE FROM sessions WHERE user_id=? AND token_hash IS NOT ?", (user_id, keep_hash))


def destroy_session(db, token_hash):
    db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))


def create_user(db, username, display_name, role, password):
    db.execute("INSERT INTO users (username,display_name,password_hash,role,created_at) VALUES (?,?,?,?,?)",
               (username, display_name, hash_password(password), role, now()))
