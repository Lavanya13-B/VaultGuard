import hmac
import io
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_file, url_for)
from itsdangerous import BadSignature, URLSafeTimedSerializer

from . import audit as auditlib
from . import auth
from . import db as dbm
from .access import LEVELS, access_level
from .config import load_config
from .store import Store
from .validation import CATEGORIES, ValidationError, validate_upload

GROUPS = {
    "permissions": ("permission_granted", "permission_changed", "permission_revoked"),
    "documents": ("upload", "view", "download", "update_content", "update_metadata", "delete"),
}
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
USERNAME = re.compile(r"^[a-z0-9._-]{3,32}$")


def like(s):
    return "%" + s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def create_app(overrides=None):
    cfg = load_config(overrides)
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=cfg["SECRET_KEY"], MAX_CONTENT_LENGTH=cfg["MAX_UPLOAD"] + 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=cfg["COOKIE_SECURE"])
    app.tv = cfg
    dbm.init_db(cfg["DATABASE"])
    store = Store(cfg["BLOB_DIR"], cfg["MASTER_KEY"])
    login_token = URLSafeTimedSerializer(cfg["SECRET_KEY"], salt="login-form")
    app.tv_store = store

    # ---------------------------------------------------------------- plumbing
    def db():
        if "db" not in g:
            g.db = dbm.connect(cfg["DATABASE"])
        return g.db

    @app.teardown_appcontext
    def _close(_):
        d = g.pop("db", None)
        if d is not None:
            d.close()

    def log(action, outcome="success", doc_id=None, target_user=None, detail=None, actor_name=None):
        u = g.get("user")
        auditlib.record(
            db(), cfg["AUDIT_KEY"], actor_id=u["id"] if u else None,
            actor_name=(u["username"] if u else actor_name), action=action, outcome=outcome,
            doc_id=doc_id, target_user=target_user, detail=detail, ip=request.remote_addr)

    @app.before_request
    def authenticate():
        g.user, g.session, g.csrf = None, None, ""
        tok = request.cookies.get("tv_session")
        if tok:
            s = auth.load_session(db(), tok, cfg["IDLE_MINUTES"], cfg["ABSOLUTE_HOURS"])
            if s:
                g.user, g.session, g.csrf = s["user"], s, s["csrf"]
        if request.endpoint in ("login", "static"):
            return None
        if g.user is None:
            return redirect(url_for("login"))
        if request.method != "GET":
            sent = request.form.get("csrf", "")
            if not hmac.compare_digest(sent.encode(), g.csrf.encode()):
                log("csrf_rejected", "denied", detail={"endpoint": request.endpoint})
                abort(400)
        return None

    @app.after_request
    def headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; "
            "frame-ancestors 'none'; base-uri 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        if cfg["COOKIE_SECURE"]:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        return resp

    @app.context_processor
    def inject():
        return {"csrf": g.get("csrf", ""), "me": g.get("user"), "categories": CATEGORIES,
                "demo_mode": os.environ.get("TRUSTVAULT_DEMO_MODE") == "1"}

    def roles(*allowed):
        def deco(f):
            @wraps(f)
            def wrapper(*a, **k):
                if g.user["role"] not in allowed:
                    log("role_denied", "denied", detail={"endpoint": request.endpoint, "role": g.user["role"]})
                    abort(403)
                return f(*a, **k)
            return wrapper
        return deco

    def need(doc_id, level, action):
        """The gate. Unknown / deleted / not-yours -> 404 (indistinguishable, so ids can't be
        probed). Has some access but not enough -> 403. Both are written to the audit log."""
        have = access_level(db(), g.user, doc_id)
        if have is None or LEVELS[have] < LEVELS[level]:
            log(action, "denied", doc_id=doc_id, detail={"required": level, "held": have})
            abort(404 if have is None else 403)
        return db().execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone(), have

    def read_upload():
        f = request.files.get("file")
        if f is None or not f.filename:
            raise ValidationError("Choose a file to upload.")
        data = f.read(cfg["MAX_UPLOAD"] + 1)
        return validate_upload(f.filename, data, cfg["MAX_UPLOAD"]), data

    def reject_upload(err, doc_id=None):
        log("upload_rejected", "denied", doc_id=doc_id, detail={"reason": str(err)})
        flash(str(err), "error")

    # ------------------------------------------------------------ authentication
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template("login.html", form_token=login_token.dumps("x"))
        try:
            login_token.loads(request.form.get("form_token", ""), max_age=900)
        except BadSignature:
            abort(400)
        uname = request.form.get("username", "").strip()[:64]
        pw = request.form.get("password", "")
        user = db().execute("SELECT * FROM users WHERE username=?", (uname,)).fetchone()
        locked = bool(user and user["locked_until"] and user["locked_until"] > dbm.now())
        ok = auth.check_password(user, pw) and user["active"] and not locked
        if not ok:
            with dbm.tx(db()):
                if user and not locked:
                    n = user["failed_count"] + 1
                    until = (datetime.now(timezone.utc) + timedelta(minutes=cfg["LOCK_MINUTES"])
                             ).strftime("%Y-%m-%dT%H:%M:%SZ") if n >= cfg["LOCK_AFTER"] else None
                    db().execute("UPDATE users SET failed_count=?, locked_until=? WHERE id=?",
                                 (0 if until else n, until, user["id"]))
                log("login_failed", "denied", actor_name=uname,
                    detail={"reason": "locked" if locked else "bad_credentials_or_inactive"})
            flash("Wrong username or password, or the account is locked.", "error")
            return render_template("login.html", form_token=login_token.dumps("x")), 401
        with dbm.tx(db()):
            db().execute("UPDATE users SET failed_count=0, locked_until=NULL WHERE id=?", (user["id"],))
            token = auth.create_session(db(), user["id"], request.remote_addr)
            g.user = user
            log("login")
        resp = redirect(url_for("dashboard"))
        resp.set_cookie("tv_session", token, httponly=True, secure=cfg["COOKIE_SECURE"],
                        samesite="Strict", path="/")
        return resp

    @app.post("/logout")
    def logout():
        with dbm.tx(db()):
            auth.destroy_session(db(), g.session["token_hash"])
            log("logout")
        resp = redirect(url_for("login"))
        resp.delete_cookie("tv_session")
        return resp

    @app.route("/account/password", methods=["GET", "POST"])
    def password():
        if request.method == "POST":
            cur, new = request.form.get("current", ""), request.form.get("new", "")
            if not auth.check_password(g.user, cur):
                log("password_change_failed", "denied")
                flash("Current password is wrong.", "error")
            elif len(new) < auth.MIN_PASSWORD:
                flash(f"New password must be at least {auth.MIN_PASSWORD} characters.", "error")
            else:
                with dbm.tx(db()):
                    db().execute("UPDATE users SET password_hash=? WHERE id=?",
                                 (auth.hash_password(new), g.user["id"]))
                    auth.destroy_sessions(db(), g.user["id"], keep_hash=g.session["token_hash"])
                    log("password_changed")
                flash("Password changed. Other sessions were signed out.", "ok")
        return render_template("password.html")

    # ----------------------------------------------------------------- documents
    @app.get("/")
    def index():
        return redirect(url_for("dashboard"))

    @app.get("/dashboard")
    def dashboard():
        uid = g.user["id"]
        now = dbm.now()
        own_count = db().execute(
            "SELECT COUNT(*) FROM documents WHERE owner_id=? AND deleted_at IS NULL", (uid,)
        ).fetchone()[0]
        shared_count = db().execute(
            "SELECT COUNT(DISTINCT d.id) FROM documents d JOIN grants gr ON gr.doc_id=d.id "
            "WHERE gr.user_id=? AND gr.revoked_at IS NULL AND (gr.expires_at IS NULL OR gr.expires_at>?) "
            "AND d.deleted_at IS NULL AND d.owner_id<>?", (uid, now, uid)
        ).fetchone()[0]
        if g.user["role"] == "admin":
            user_count = db().execute("SELECT COUNT(*) FROM users WHERE active=1").fetchone()[0]
        else:
            user_count = None
        recent = db().execute(
            "SELECT ts, action, outcome, doc_id, target_user FROM audit_log "
            "WHERE actor_id=? ORDER BY id DESC LIMIT 8", (uid,)
        ).fetchall()
        return render_template("dashboard.html", own_count=own_count, shared_count=shared_count,
                               user_count=user_count, recent=recent)

    @app.get("/account/profile")
    def profile():
        # Only non-secret account fields are passed to the template.
        user = db().execute(
            "SELECT username, display_name, role, active, created_at FROM users WHERE id=?",
            (g.user["id"],)
        ).fetchone()
        return render_template("profile.html", profile=user)

    @app.get("/documents")
    def documents():
        a = request.args
        args = {"uid": g.user["id"], "now": dbm.now()}
        mine = "d.owner_id=:uid"
        shared = ("EXISTS(SELECT 1 FROM grants g WHERE g.doc_id=d.id AND g.user_id=:uid AND g.revoked_at IS NULL "
                  "AND (g.expires_at IS NULL OR g.expires_at>:now))")
        scope = a.get("scope", "all")
        where = ["d.deleted_at IS NULL", {"mine": mine, "shared": shared}.get(scope, f"({mine} OR {shared})")]
        if a.get("q", "").strip():
            where.append("d.name LIKE :q ESCAPE '\\'")
            args["q"] = like(a["q"].strip()[:100])
        if a.get("owner", "").strip():
            where.append("o.username LIKE :owner ESCAPE '\\'")
            args["owner"] = like(a["owner"].strip()[:64])
        if a.get("category") in CATEGORIES:
            where.append("d.category=:cat")
            args["cat"] = a["category"]
        if DATE.match(a.get("from", "")):
            where.append("d.created_at>=:dfrom")
            args["dfrom"] = a["from"] + "T00:00:00Z"
        if DATE.match(a.get("to", "")):
            where.append("d.created_at<=:dto")
            args["dto"] = a["to"] + "T23:59:59Z"
        rows = db().execute(
            "SELECT d.id,d.name,d.category,d.created_at,d.updated_at,o.username owner,"
            "CASE WHEN d.owner_id=:uid THEN 'owner' ELSE (SELECT g.level FROM grants g WHERE g.doc_id=d.id "
            "AND g.user_id=:uid AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>:now)) END my_level "
            "FROM documents d JOIN users o ON o.id=d.owner_id WHERE " + " AND ".join(where) +
            " ORDER BY d.updated_at DESC LIMIT 200", args).fetchall()
        return render_template("documents.html", docs=rows, f=a, scope=scope)

    @app.route("/documents/new", methods=["GET", "POST"])
    @roles("owner")
    def upload():
        if request.method == "POST":
            category = request.form.get("category")
            try:
                if category not in CATEGORIES:
                    raise ValidationError("Choose a category.")
                meta, data = read_upload()
            except ValidationError as e:
                reject_upload(e)
                return render_template("upload.html"), 400
            doc_id, name = uuid.uuid4().hex, (request.form.get("name", "").strip()[:120] or meta["filename"])
            blob, wrapped = store.put(doc_id, 1, data)
            try:
                with dbm.tx(db()):
                    t = dbm.now()
                    db().execute("INSERT INTO documents VALUES (?,?,?,?,?,?,1,NULL,NULL)",
                                 (doc_id, name, category, g.user["id"], t, t))
                    db().execute("INSERT INTO versions VALUES (?,?,?,?,?,?,?,?,?,?)",
                                 (doc_id, 1, blob, meta["filename"], meta["mime"], meta["size"],
                                  meta["sha256"], wrapped, g.user["id"], t))
                    log("upload", doc_id=doc_id, detail={"version": 1, "sha256": meta["sha256"],
                                                          "size": meta["size"], "category": category})
            except BaseException:
                store.remove(blob)
                raise
            return redirect(url_for("document", doc_id=doc_id))
        return render_template("upload.html")

    @app.get("/documents/<doc_id>")
    def document(doc_id):
        doc, level = need(doc_id, "read", "view")
        log("view", doc_id=doc_id)
        versions = db().execute("SELECT v.*, u.username by_user FROM versions v JOIN users u ON u.id=v.uploaded_by "
                                "WHERE doc_id=? ORDER BY version DESC", (doc_id,)).fetchall()
        owner = db().execute("SELECT username FROM users WHERE id=?", (doc["owner_id"],)).fetchone()["username"]
        grants = history = []
        if level == "owner":
            grants = db().execute(
                "SELECT g.*, u.username FROM grants g JOIN users u ON u.id=g.user_id WHERE g.doc_id=? "
                "AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>?) ORDER BY g.id",
                (doc_id, dbm.now())).fetchall()
            history = db().execute("SELECT * FROM audit_log WHERE doc_id=? ORDER BY id DESC LIMIT 100",
                                   (doc_id,)).fetchall()
        return render_template("document.html", doc=doc, level=level, versions=versions,
                               owner=owner, grants=grants, history=history)

    @app.get("/documents/<doc_id>/download")
    def download(doc_id):
        doc, _ = need(doc_id, "read", "download")
        try:
            ver = int(request.args.get("version", doc["current_version"]))
        except ValueError:
            abort(400)
        v = db().execute("SELECT * FROM versions WHERE doc_id=? AND version=?", (doc_id, ver)).fetchone()
        if v is None:
            log("download", "error", doc_id=doc_id, detail={"version": ver, "reason": "no such version"})
            abort(404)
        # Fail closed: the audit row is committed BEFORE any byte is released.
        log("download", doc_id=doc_id, detail={"version": ver, "sha256": v["sha256"]})
        try:
            data = store.get(v["blob_name"], v["wrapped_key"], doc_id, ver)
        except Exception:
            log("download", "error", doc_id=doc_id, detail={"version": ver, "reason": "content unreadable"})
            abort(500)
        return send_file(io.BytesIO(data), mimetype=v["mime"], as_attachment=True,
                         download_name=v["original_filename"])

    @app.post("/documents/<doc_id>/replace")
    def replace(doc_id):
        doc, _ = need(doc_id, "edit", "update_content")
        try:
            meta, data = read_upload()
        except ValidationError as e:
            reject_upload(e, doc_id)
            return redirect(url_for("document", doc_id=doc_id))
        new = doc["current_version"] + 1
        blob, wrapped = store.put(doc_id, new, data)
        try:
            with dbm.tx(db()):
                cur = db().execute("UPDATE documents SET current_version=?, updated_at=? WHERE id=? "
                                   "AND current_version=? AND deleted_at IS NULL",
                                   (new, dbm.now(), doc_id, doc["current_version"]))
                if cur.rowcount != 1:
                    abort(409)
                db().execute("INSERT INTO versions VALUES (?,?,?,?,?,?,?,?,?,?)",
                             (doc_id, new, blob, meta["filename"], meta["mime"], meta["size"],
                              meta["sha256"], wrapped, g.user["id"], dbm.now()))
                log("update_content", doc_id=doc_id, detail={"version": new, "sha256": meta["sha256"]})
        except BaseException:
            store.remove(blob)
            raise
        flash(f"Saved as version {new}.", "ok")
        return redirect(url_for("document", doc_id=doc_id))

    @app.post("/documents/<doc_id>/metadata")
    def metadata(doc_id):
        doc, _ = need(doc_id, "edit", "update_metadata")
        name = request.form.get("name", "").strip()[:120]
        cat = request.form.get("category")
        if not name or cat not in CATEGORIES:
            flash("Name and a valid category are required.", "error")
            return redirect(url_for("document", doc_id=doc_id))
        with dbm.tx(db()):
            db().execute("UPDATE documents SET name=?, category=?, updated_at=? WHERE id=?",
                         (name, cat, dbm.now(), doc_id))
            log("update_metadata", doc_id=doc_id,
                detail={"name": [doc["name"], name], "category": [doc["category"], cat]})
        return redirect(url_for("document", doc_id=doc_id))

    @app.post("/documents/<doc_id>/delete")
    def delete(doc_id):
        doc, _ = need(doc_id, "owner", "delete")
        if request.form.get("confirm") != "yes":
            flash("Tick the box to confirm deletion.", "error")
            return redirect(url_for("document", doc_id=doc_id))
        blobs = [r["blob_name"] for r in db().execute("SELECT blob_name FROM versions WHERE doc_id=?", (doc_id,))]
        with dbm.tx(db()):
            t = dbm.now()
            db().execute("UPDATE documents SET deleted_at=?, deleted_by=? WHERE id=?", (t, g.user["id"], doc_id))
            db().execute("UPDATE versions SET wrapped_key=x'' WHERE doc_id=?", (doc_id,))   # crypto-shred
            db().execute("UPDATE grants SET revoked_at=?, revoked_by=? WHERE doc_id=? AND revoked_at IS NULL",
                         (t, g.user["id"], doc_id))
            log("delete", doc_id=doc_id, detail={"name": doc["name"], "versions": len(blobs)})
        for b in blobs:
            store.remove(b)
        flash("Document deleted. Its contents are unrecoverable; the audit record remains.", "ok")
        return redirect(url_for("documents"))

    # --------------------------------------------------------------- permissions
    @app.post("/documents/<doc_id>/share")
    def share(doc_id):
        doc, _ = need(doc_id, "owner", "permission_granted")
        uname, level = request.form.get("username", "").strip().lower(), request.form.get("level")
        days = request.form.get("days", "").strip()
        target = db().execute("SELECT * FROM users WHERE username=? AND active=1", (uname,)).fetchone()
        expires = None
        if days:
            if not days.isdigit() or not 1 <= int(days) <= 365:
                flash("Expiry must be 1 to 365 days, or blank for none.", "error")
                return redirect(url_for("document", doc_id=doc_id))
            expires = (datetime.now(timezone.utc) + timedelta(days=int(days))).strftime("%Y-%m-%dT%H:%M:%SZ")
        if level not in ("read", "edit") or target is None or target["id"] == g.user["id"]:
            log("permission_granted", "error", doc_id=doc_id, target_user=uname[:64],
                detail={"reason": "invalid user or level"})
            flash("Pick an existing, active person (not yourself) and a level.", "error")
            return redirect(url_for("document", doc_id=doc_id))
        with dbm.tx(db()):
            old = db().execute("SELECT * FROM grants WHERE doc_id=? AND user_id=? AND revoked_at IS NULL",
                               (doc_id, target["id"])).fetchone()
            if old:
                db().execute("UPDATE grants SET level=?, expires_at=? WHERE id=?", (level, expires, old["id"]))
                log("permission_changed", doc_id=doc_id, target_user=uname,
                    detail={"from": old["level"], "to": level, "expires_at": expires})
            else:
                db().execute("INSERT INTO grants (doc_id,user_id,level,granted_by,granted_at,expires_at) "
                             "VALUES (?,?,?,?,?,?)", (doc_id, target["id"], level, g.user["id"], dbm.now(), expires))
                log("permission_granted", doc_id=doc_id, target_user=uname,
                    detail={"level": level, "expires_at": expires})
        return redirect(url_for("document", doc_id=doc_id))

    @app.post("/documents/<doc_id>/revoke")
    def revoke(doc_id):
        need(doc_id, "owner", "permission_revoked")
        gid = request.form.get("grant_id", "")
        with dbm.tx(db()):
            gr = db().execute("SELECT g.*, u.username FROM grants g JOIN users u ON u.id=g.user_id "
                              "WHERE g.id=? AND g.doc_id=? AND g.revoked_at IS NULL",
                              (gid, doc_id)).fetchone()
            if gr is None:
                abort(404)
            db().execute("UPDATE grants SET revoked_at=?, revoked_by=? WHERE id=?",
                         (dbm.now(), g.user["id"], gr["id"]))
            log("permission_revoked", doc_id=doc_id, target_user=gr["username"], detail={"level": gr["level"]})
        return redirect(url_for("document", doc_id=doc_id))

    # --------------------------------------------------------------------- admin
    @app.route("/admin/users", methods=["GET", "POST"])
    @roles("admin")
    def admin_users():
        if request.method == "POST":
            f = request.form
            uname, role, pw = f.get("username", "").strip().lower(), f.get("role"), f.get("password", "")
            if not USERNAME.match(uname) or role not in ("admin", "owner", "viewer") or len(pw) < auth.MIN_PASSWORD \
                    or not f.get("display_name", "").strip():
                flash(f"Username 3-32 chars (a-z 0-9 . _ -), a name, a role, and a {auth.MIN_PASSWORD}+ char password.", "error")
            else:
                try:
                    with dbm.tx(db()):
                        auth.create_user(db(), uname, f["display_name"].strip()[:80], role, pw)
                        log("user_created", target_user=uname, detail={"role": role})
                    flash(f"Created {uname}.", "ok")
                except Exception as e:
                    if "UNIQUE" not in str(e):
                        raise
                    flash("That username is taken.", "error")
        users = db().execute("SELECT id,username,display_name,role,active,locked_until FROM users ORDER BY username").fetchall()
        return render_template("admin_users.html", users=users)

    @app.post("/admin/users/<int:uid>/<state>")
    @roles("admin")
    def admin_user_state(uid, state):
        if state not in ("deactivate", "activate"):
            abort(404)
        u = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if u is None:
            abort(404)
        if u["id"] == g.user["id"]:
            flash("You can't deactivate your own account.", "error")
            return redirect(url_for("admin_users"))
        with dbm.tx(db()):
            db().execute("UPDATE users SET active=? WHERE id=?", (1 if state == "activate" else 0, uid))
            if state == "deactivate":
                auth.destroy_sessions(db(), uid)         # signed out immediately
            log(f"user_{state}d", target_user=u["username"])
        return redirect(url_for("admin_users"))

    @app.get("/admin/activity")
    @roles("admin")
    def admin_activity():
        a, where, args = request.args, [], {}
        if a.get("group") in GROUPS:
            marks = ",".join(f":g{i}" for i in range(len(GROUPS[a["group"]])))
            where.append(f"action IN ({marks})")
            args.update({f"g{i}": x for i, x in enumerate(GROUPS[a["group"]])})
        if a.get("outcome") in ("success", "denied", "error"):
            where.append("outcome=:outcome")
            args["outcome"] = a["outcome"]
        if a.get("actor", "").strip():
            where.append("(actor_name LIKE :actor ESCAPE '\\' OR target_user LIKE :actor ESCAPE '\\')")
            args["actor"] = like(a["actor"].strip()[:64])
        if a.get("doc", "").strip():
            where.append("doc_id=:doc")
            args["doc"] = a["doc"].strip()[:64]
        if DATE.match(a.get("from", "")):
            where.append("ts>=:dfrom")
            args["dfrom"] = a["from"] + "T00:00:00Z"
        if DATE.match(a.get("to", "")):
            where.append("ts<=:dto")
            args["dto"] = a["to"] + "T23:59:59Z"
        page = max(int(a.get("page", 1)) if a.get("page", "1").isdigit() else 1, 1)
        args.update(lim=100, off=(page - 1) * 100)
        log("admin_view_activity", detail={"filters": {k: v for k, v in a.items() if v}})
        rows = db().execute("SELECT a.*, d.name doc_name FROM audit_log a LEFT JOIN documents d ON d.id=a.doc_id" +
                            (" WHERE " + " AND ".join("a." + w for w in where) if where else "") +
                            " ORDER BY a.id DESC LIMIT :lim OFFSET :off", args).fetchall()
        return render_template("admin_activity.html", rows=rows, f=a, page=page,
                               base={k: v for k, v in a.items() if v and k != "page"})

    @app.get("/admin/audit/verify")
    @roles("admin")
    def admin_verify():
        exp = None
        if request.args.get("count", "").isdigit() and request.args.get("hash"):
            exp = {"count": int(request.args["count"]), "hash": request.args["hash"].strip()}
        result = auditlib.verify(db(), cfg["AUDIT_KEY"], exp)
        log("audit_verified", detail={"ok": result["ok"], "entries": result["count"]})
        return render_template("admin_verify.html", result=result, head=auditlib.head(db()))

    # ------------------------------------------------------------------- errors
    for code, msg in {400: "Bad request.", 403: "You don't have permission to do that.",
                      404: "Not found.", 409: "That changed while you were working. Reload and retry.",
                      413: "File too large.", 500: "Something went wrong."}.items():
        app.register_error_handler(code, lambda e, c=code, m=msg: (render_template("error.html", code=c, msg=m), c))

    return app
