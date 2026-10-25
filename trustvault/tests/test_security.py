"""Security tests for VaultGuard. Run:  python -m unittest -v
Each class maps to one of the three non-negotiable standards plus the supporting controls."""
import hashlib
import io
import os
import re
import sqlite3
import tempfile
import unittest
import zipfile
from unittest import mock

from trustvault import audit, auth, create_app
from trustvault import db as dbm

PW = "correct-horse-battery"
PDF = b"%PDF-1.4\nTOP-SECRET-SALARY-4200000\n%%EOF"
PDF_B = b"%PDF-1.4\nCONTRACT-B-CONFIDENTIAL\n%%EOF"
AUDIT_KEY = b"a" * 32
USERS = [("admin", "admin"), ("alice", "owner"), ("bob", "owner"),
         ("carol", "viewer"), ("dave", "viewer"), ("erin", "viewer")]


class Browser:
    """One cookie jar = one person's browser."""

    def __init__(self, app):
        self.c, self._csrf = app.test_client(), None

    def login(self, username, pw=PW):
        page = self.c.get("/login").text
        tok = re.search(r'name="form_token" value="([^"]+)"', page).group(1)
        r = self.c.post("/login", data={"username": username, "password": pw, "form_token": tok})
        if r.status_code == 302:
            self._csrf = re.search(r'name="csrf" value="([^"]+)"', self.c.get("/account/password").text).group(1)
        return r

    def get(self, url, **kw):
        return self.c.get(url, **kw)

    def post(self, url, **data):
        data.setdefault("csrf", self._csrf)
        return self.c.post(url, data=data)

    def upload(self, url, content=PDF, filename="salary.pdf", **fields):
        fields.setdefault("csrf", self._csrf)
        fields["file"] = (io.BytesIO(content), filename)
        return self.c.post(url, data=fields, content_type="multipart/form-data")


class Base(unittest.TestCase):
    max_upload = 10 * 1024 * 1024

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = create_app({"HOME": self.tmp.name, "MASTER_KEY": b"m" * 32, "AUDIT_KEY": AUDIT_KEY,
                               "SECRET_KEY": b"s" * 32, "COOKIE_SECURE": False, "MAX_UPLOAD": self.max_upload})
        db = self.raw()
        for name, role in USERS:
            auth.create_user(db, name, name.title(), role, PW)
        db.close()
        self.b = {n: Browser(self.app) for n, _ in USERS}
        for n, _ in USERS:
            self.assertEqual(self.b[n].login(n).status_code, 302)

    def tearDown(self):
        self.tmp.cleanup()

    def raw(self):
        d = sqlite3.connect(self.app.tv["DATABASE"], isolation_level=None)
        d.row_factory = sqlite3.Row
        return d

    def new_doc(self, who="alice", content=PDF, name="Salary letter", category="HR", filename="salary.pdf"):
        r = self.b[who].upload("/documents/new", content=content, filename=filename, name=name, category=category)
        self.assertEqual(r.status_code, 302, r.text[:300])
        return r.headers["Location"].rsplit("/", 1)[-1]

    def audit_rows(self, **where):
        q = " AND ".join(f"{k}=?" for k in where) or "1"
        return self.raw().execute(f"SELECT * FROM audit_log WHERE {q} ORDER BY id", tuple(where.values())).fetchall()

    def grant(self, doc, user, level="read", owner="alice", **extra):
        r = self.b[owner].post(f"/documents/{doc}/share", username=user, level=level, **extra)
        self.assertEqual(r.status_code, 302)


# ---------------------------------------------------------------------------------------
class TestStandard1_OnlyGrantedPeopleReachDocuments(Base):
    def test_strangers_are_refused_on_every_action_and_nothing_changes(self):
        doc = self.new_doc()
        for who in ("carol", "bob", "admin"):          # a viewer, another owner, and the administrator
            b = self.b[who]
            attempts = {
                "view": b.get(f"/documents/{doc}"),
                "download": b.get(f"/documents/{doc}/download"),
                "replace": b.upload(f"/documents/{doc}/replace", content=PDF_B),
                "metadata": b.post(f"/documents/{doc}/metadata", name="pwned", category="Other"),
                "delete": b.post(f"/documents/{doc}/delete", confirm="yes"),
                "share": b.post(f"/documents/{doc}/share", username=who, level="edit"),
                "revoke": b.post(f"/documents/{doc}/revoke", grant_id="1"),
            }
            for name, r in attempts.items():
                self.assertEqual(r.status_code, 404, f"{who} {name}")
                self.assertNotIn(b"TOP-SECRET", r.data)
        db = self.raw()
        d = db.execute("SELECT * FROM documents WHERE id=?", (doc,)).fetchone()
        self.assertEqual((d["name"], d["current_version"], d["deleted_at"]), ("Salary letter", 1, None))
        self.assertEqual(db.execute("SELECT COUNT(*) FROM grants").fetchone()[0], 0)
        # ...and every refusal is on the record, attributed to the person who tried
        denied = self.audit_rows(outcome="denied", doc_id=doc)
        self.assertEqual({r["actor_name"] for r in denied}, {"carol", "bob", "admin"})
        self.assertEqual(len(denied), 21)

    def test_every_route_that_takes_a_document_id_is_guarded(self):
        """Walks the URL map, so a route added later without a check fails this test."""
        doc = self.new_doc()
        rules = [r for r in self.app.url_map.iter_rules() if "<doc_id>" in r.rule]
        self.assertGreaterEqual(len(rules), 7)
        for rule in rules:
            for method in rule.methods - {"HEAD", "OPTIONS"}:
                for who in ("carol", "bob", "admin"):
                    r = self.b[who].c.open(rule.rule.replace("<doc_id>", doc), method=method,
                                           data={"csrf": self.b[who]._csrf})
                    self.assertIn(r.status_code, (403, 404), f"{who} {method} {rule.rule}")
                anon = self.app.test_client().open(rule.rule.replace("<doc_id>", doc), method=method)
                self.assertEqual((anon.status_code, anon.headers["Location"].endswith("/login")), (302, True))

    def test_unauthorised_and_nonexistent_look_identical(self):
        doc = self.new_doc()
        a = self.b["carol"].get(f"/documents/{doc}")
        b = self.b["carol"].get("/documents/" + "0" * 32)
        self.assertEqual((a.status_code, a.data), (b.status_code, b.data))

    def test_search_and_listings_never_leak_other_peoples_documents(self):
        self.new_doc(name="Salary letter")
        for params in ("q=Salary", "owner=alice", "category=HR", "scope=all", "scope=mine", "q=%25", "from=2000-01-01"):
            for who in ("carol", "bob"):
                r = self.b[who].get("/documents?" + params)
                self.assertEqual(r.status_code, 200)
                self.assertNotIn(b"Salary letter", r.data, f"{who} {params}")
        inj = self.b["carol"].get("/documents?q=%27+OR+1%3D1+--&owner=%27+OR+%271%27%3D%271")
        self.assertEqual(inj.status_code, 200)
        self.assertNotIn(b"Salary letter", inj.data)

    def test_admin_role_does_not_confer_document_access(self):
        doc = self.new_doc()
        self.assertEqual(self.b["admin"].get(f"/documents/{doc}/download").status_code, 404)

    def test_read_grant_allows_reading_only(self):
        doc = self.new_doc()
        self.grant(doc, "carol", "read")
        c = self.b["carol"]
        r = c.get(f"/documents/{doc}/download")
        self.assertEqual((r.status_code, r.data), (200, PDF))
        self.assertEqual(c.upload(f"/documents/{doc}/replace", content=PDF_B).status_code, 403)
        self.assertEqual(c.post(f"/documents/{doc}/metadata", name="x", category="HR").status_code, 403)
        self.assertEqual(c.post(f"/documents/{doc}/delete", confirm="yes").status_code, 403)
        self.assertEqual(c.post(f"/documents/{doc}/share", username="dave", level="read").status_code, 403)
        self.assertEqual(self.b["dave"].get(f"/documents/{doc}").status_code, 404)    # no re-sharing happened
        self.assertEqual(self.raw().execute("SELECT current_version FROM documents").fetchone()[0], 1)

    def test_edit_grant_can_change_but_not_delete_or_share(self):
        doc = self.new_doc()
        self.grant(doc, "dave", "edit")
        d = self.b["dave"]
        self.assertEqual(d.upload(f"/documents/{doc}/replace", content=PDF_B).status_code, 302)
        self.assertEqual(self.b["alice"].get(f"/documents/{doc}/download?version=1").data, PDF)   # history kept
        self.assertEqual(d.get(f"/documents/{doc}/download").data, PDF_B)
        self.assertEqual(d.post(f"/documents/{doc}/delete", confirm="yes").status_code, 403)
        self.assertEqual(d.post(f"/documents/{doc}/share", username="erin", level="read").status_code, 403)

    def test_expired_grant_stops_working(self):
        doc = self.new_doc()
        self.grant(doc, "carol", "read", days="1")
        self.assertEqual(self.b["carol"].get(f"/documents/{doc}/download").status_code, 200)
        db = self.raw()
        db.execute("UPDATE grants SET expires_at='2000-01-01T00:00:00Z'")
        self.assertEqual(self.b["carol"].get(f"/documents/{doc}/download").status_code, 404)

    def test_viewers_cannot_upload_and_non_admins_cannot_reach_admin_pages(self):
        self.assertEqual(self.b["carol"].upload("/documents/new", category="HR").status_code, 403)
        for who in ("carol", "alice"):
            for url in ("/admin/users", "/admin/activity", "/admin/audit/verify"):
                self.assertEqual(self.b[who].get(url).status_code, 403)

    def test_files_are_encrypted_at_rest_and_blobs_cannot_be_swapped(self):
        a, b = self.new_doc(name="A"), self.new_doc(name="B", content=PDF_B)
        blobs = []
        for root, _, files in os.walk(self.app.tv["BLOB_DIR"]):
            for f in files:
                data = open(os.path.join(root, f), "rb").read()
                self.assertNotIn(b"TOP-SECRET", data)
                self.assertNotIn(b"CONTRACT-B", data)
                blobs.append(os.path.join(root, f))
        self.assertEqual(len(blobs), 2)
        x, y = (open(p, "rb").read() for p in blobs)
        open(blobs[0], "wb").write(y)
        open(blobs[1], "wb").write(x)                                   # attacker swaps the ciphertexts
        for doc in (a, b):
            r = self.b["alice"].get(f"/documents/{doc}/download")
            self.assertEqual(r.status_code, 500)
            self.assertNotIn(b"CONTRACT-B", r.data)
            self.assertNotIn(b"TOP-SECRET", r.data)


# ---------------------------------------------------------------------------------------
class TestStandard2_YouCanProveWhoReachedIt(Base):
    def test_full_lifecycle_is_recorded_with_who_and_what(self):
        doc = self.new_doc()
        self.grant(doc, "carol", "read")
        self.b["carol"].get(f"/documents/{doc}/download")
        self.b["alice"].post(f"/documents/{doc}/metadata", name="Renamed", category="Finance")
        self.b["alice"].upload(f"/documents/{doc}/replace", content=PDF_B)
        self.b["alice"].post(f"/documents/{doc}/share", username="carol", level="edit")
        gid = self.raw().execute("SELECT id FROM grants").fetchone()[0]
        self.b["alice"].post(f"/documents/{doc}/revoke", grant_id=gid)
        self.b["alice"].post(f"/documents/{doc}/delete", confirm="yes")
        seen = [(r["actor_name"], r["action"], r["outcome"]) for r in self.audit_rows(doc_id=doc)]
        for expected in [("alice", "upload", "success"), ("alice", "permission_granted", "success"),
                         ("carol", "download", "success"), ("alice", "update_metadata", "success"),
                         ("alice", "update_content", "success"), ("alice", "permission_changed", "success"),
                         ("alice", "permission_revoked", "success"), ("alice", "delete", "success")]:
            self.assertIn(expected, seen)
        dl = self.audit_rows(doc_id=doc, action="download")[0]
        self.assertIn(hashlib.sha256(PDF).hexdigest(), dl["detail"])      # which exact bytes were released

    def test_refused_attempts_and_failed_logins_are_recorded(self):
        doc = self.new_doc()
        self.b["carol"].get(f"/documents/{doc}/download")
        r = self.audit_rows(action="download", outcome="denied")
        self.assertEqual((len(r), r[0]["actor_name"], r[0]["doc_id"]), (1, "carol", doc))
        Browser(self.app).login("carol", "wrong-password-here")
        Browser(self.app).login("nobody", "wrong-password-here")
        self.assertEqual({x["actor_name"] for x in self.audit_rows(action="login_failed")}, {"carol", "nobody"})

    def test_download_is_logged_before_bytes_are_released(self):
        doc = self.new_doc()
        real = audit.record

        def failing(db, key, **kw):
            if kw.get("action") == "download":
                raise RuntimeError("audit store unavailable")
            return real(db, key, **kw)
        with mock.patch.object(audit, "record", side_effect=failing):
            r = self.b["alice"].get(f"/documents/{doc}/download")
        self.assertEqual(r.status_code, 500)
        self.assertNotIn(b"TOP-SECRET", r.data)                           # no audit row -> no file

    def test_database_refuses_to_edit_or_delete_audit_rows(self):
        self.new_doc()
        db = self.raw()
        with self.assertRaises(sqlite3.DatabaseError):
            db.execute("UPDATE audit_log SET actor_name='mallory' WHERE id=1")
        with self.assertRaises(sqlite3.DatabaseError):
            db.execute("DELETE FROM audit_log WHERE id=1")

    def _disarm(self):
        db = self.raw()
        db.executescript("DROP TRIGGER audit_no_update; DROP TRIGGER audit_no_delete;")   # attacker has the DB file
        return db

    def test_edited_row_is_detected_even_if_attacker_recomputes_the_hash_without_the_key(self):
        self.new_doc()
        db = self._disarm()
        self.assertTrue(audit.verify(db, AUDIT_KEY)["ok"])
        row = db.execute("SELECT * FROM audit_log WHERE action='upload'").fetchone()
        db.execute("UPDATE audit_log SET actor_name='bob' WHERE id=?", (row["id"],))
        res = audit.verify(db, AUDIT_KEY)
        self.assertEqual((res["ok"], res["bad_id"]), (False, row["id"]))
        rec = {f: (("bob" if f == "actor_name" else row[f])) for f in audit.FIELDS}
        forged = audit._mac(b"x" * 32, row["prev_hash"], rec)             # wrong key: they don't have the real one
        db.execute("UPDATE audit_log SET hash=? WHERE id=?", (forged, row["id"]))
        self.assertFalse(audit.verify(db, AUDIT_KEY)["ok"])

    def test_deleted_or_inserted_rows_break_the_chain(self):
        self.new_doc()
        self.b["carol"].get("/documents/" + "0" * 32)
        db = self._disarm()
        mid = db.execute("SELECT id FROM audit_log WHERE action='upload'").fetchone()[0]
        db.execute("DELETE FROM audit_log WHERE id=?", (mid,))
        self.assertFalse(audit.verify(db, AUDIT_KEY)["ok"])

    def test_truncation_is_caught_by_an_anchored_head(self):
        self.new_doc()
        self.new_doc(name="second")
        anchor = audit.head(self.raw())                                    # copied somewhere the app can't write
        db = self._disarm()
        db.execute("DELETE FROM audit_log WHERE id=(SELECT MAX(id) FROM audit_log)")
        self.assertTrue(audit.verify(db, AUDIT_KEY)["ok"])                 # a bare chain cannot see this...
        self.assertFalse(audit.verify(db, AUDIT_KEY, anchor)["ok"])        # ...the anchor can

    def test_admin_page_reports_tampering(self):
        self.new_doc()
        self.assertIn(b"Chain intact", self.b["admin"].get("/admin/audit/verify").data)
        db = self._disarm()
        db.execute("UPDATE audit_log SET ip='6.6.6.6' WHERE id=1")
        self.assertIn(b"TAMPERING DETECTED", self.b["admin"].get("/admin/audit/verify").data)

    def test_admin_activity_view_filters_and_is_itself_audited(self):
        doc = self.new_doc()
        self.grant(doc, "carol")
        self.b["bob"].get(f"/documents/{doc}")
        r = self.b["admin"].get("/admin/activity?group=permissions")
        self.assertIn(b"permission_granted", r.data)
        self.assertNotIn(b"download", r.data.replace(b"Document activity", b""))
        self.assertIn(b"denied", self.b["admin"].get("/admin/activity?outcome=denied").data)
        self.assertTrue(self.audit_rows(action="admin_view_activity", actor_name="admin"))

    def test_hostile_text_in_the_log_is_escaped(self):
        self.b["carol"].get("/documents/<script>alert(1)</script>")
        self.b["carol"].c.post("/login", data={"username": "<img src=x onerror=alert(1)>", "password": "x"})
        page = self.b["admin"].get("/admin/activity").data
        self.assertNotIn(b"<script>alert(1)", page)
        self.assertNotIn(b"<img src=x", page)


# ---------------------------------------------------------------------------------------
class TestStandard3_RevocationIsImmediate(Base):
    def test_revoked_user_loses_access_on_the_very_next_request_with_the_same_session(self):
        doc = self.new_doc()
        self.grant(doc, "carol", "read")
        carol = self.b["carol"]
        self.assertEqual(carol.get(f"/documents/{doc}/download").status_code, 200)
        self.assertIn(b"Salary letter", carol.get("/documents").data)
        gid = self.raw().execute("SELECT id FROM grants WHERE revoked_at IS NULL").fetchone()[0]
        self.assertEqual(self.b["alice"].post(f"/documents/{doc}/revoke", grant_id=gid).status_code, 302)
        self.assertEqual(carol.get(f"/documents/{doc}/download").status_code, 404)
        self.assertEqual(carol.get(f"/documents/{doc}").status_code, 404)
        self.assertEqual(carol.get(f"/documents/{doc}/download?version=1").status_code, 404)
        self.assertNotIn(b"Salary letter", carol.get("/documents").data)
        self.assertEqual(self.audit_rows(actor_name="carol", action="download", outcome="denied")[-1]["doc_id"], doc)

    def test_edit_rights_are_cut_immediately_too(self):
        doc = self.new_doc()
        self.grant(doc, "dave", "edit")
        gid = self.raw().execute("SELECT id FROM grants").fetchone()[0]
        self.b["alice"].post(f"/documents/{doc}/revoke", grant_id=gid)
        self.assertEqual(self.b["dave"].upload(f"/documents/{doc}/replace", content=PDF_B).status_code, 404)
        self.assertEqual(self.raw().execute("SELECT current_version FROM documents").fetchone()[0], 1)

    def test_downgrading_read_edit_to_read_takes_effect_immediately(self):
        doc = self.new_doc()
        self.grant(doc, "dave", "edit")
        self.grant(doc, "dave", "read")
        self.assertEqual(self.b["dave"].upload(f"/documents/{doc}/replace", content=PDF_B).status_code, 403)

    def test_deactivated_person_is_signed_out_at_once_and_cannot_return(self):
        doc = self.new_doc()
        self.grant(doc, "carol", "read")
        carol_id = self.raw().execute("SELECT id FROM users WHERE username='carol'").fetchone()[0]
        self.assertEqual(self.b["carol"].get(f"/documents/{doc}/download").status_code, 200)
        self.assertEqual(self.b["admin"].post(f"/admin/users/{carol_id}/deactivate").status_code, 302)
        r = self.b["carol"].get(f"/documents/{doc}/download")
        self.assertEqual((r.status_code, r.headers["Location"].endswith("/login")), (302, True))
        self.assertEqual(Browser(self.app).login("carol").status_code, 401)

    def test_deleting_a_document_ends_every_grant_and_destroys_the_contents(self):
        doc = self.new_doc()
        self.grant(doc, "carol", "read")
        self.b["alice"].post(f"/documents/{doc}/delete", confirm="yes")
        for who in ("alice", "carol"):
            self.assertEqual(self.b[who].get(f"/documents/{doc}/download").status_code, 404)
        self.assertEqual(self.raw().execute("SELECT wrapped_key FROM versions").fetchone()[0], b"")
        self.assertEqual(sum(len(f) for _, _, f in os.walk(self.app.tv["BLOB_DIR"])), 0)
        self.assertTrue(self.audit_rows(doc_id=doc, action="delete"))      # the record outlives the file

    def test_changing_password_signs_out_other_sessions(self):
        other = Browser(self.app)
        other.login("carol")
        self.b["carol"].post("/account/password", current=PW, new="a-brand-new-passphrase")
        r = other.get("/documents")
        self.assertEqual((r.status_code, r.headers["Location"].endswith("/login")), (302, True))
        self.assertEqual(self.b["carol"].get("/documents").status_code, 200)    # the session that changed it survives


# ---------------------------------------------------------------------------------------
class TestUploadValidation(Base):
    max_upload = 2000

    def rejected(self, **kw):
        before = len(self.audit_rows(action="upload_rejected"))
        r = self.b["alice"].upload("/documents/new", category="HR", **kw)
        self.assertEqual(r.status_code, 400, kw.get("filename"))
        self.assertEqual(self.raw().execute("SELECT COUNT(*) FROM documents").fetchone()[0], 0)
        self.assertEqual(len(self.audit_rows(action="upload_rejected")), before + 1)

    def test_bad_uploads_are_refused_and_logged(self):
        self.rejected(content=b"MZ\x90\x00 evil", filename="invoice.pdf")           # exe pretending to be a pdf
        self.rejected(content=b"MZ\x90\x00 evil", filename="setup.exe")              # type not allowed
        self.rejected(content=b"<script>x</script>", filename="page.html")
        self.rejected(content=b"", filename="empty.pdf")
        self.rejected(content=PDF + b"A" * 3000, filename="big.pdf")                # over the limit
        self.rejected(content=b"PK\x03\x04junk", filename="fake.docx")
        self.rejected(content=b"bin\x00ary", filename="notes.txt")
        self.rejected(content=PDF, filename="noextension")

    def test_missing_category_is_refused(self):
        r = self.b["alice"].upload("/documents/new", category="Nonsense")
        self.assertEqual(r.status_code, 400)

    def test_valid_files_and_hostile_filenames(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml", "<x/>")
            z.writestr("word/document.xml", "<x/>")
        self.new_doc(content=buf.getvalue(), name="real docx", filename="real.docx")
        doc = self.new_doc(content=PDF)
        r = self.b["alice"].upload("/documents/new", filename="../../etc/pass wd<>.pdf", category="HR")
        self.assertEqual(r.status_code, 302)
        stored = self.raw().execute("SELECT original_filename FROM versions ORDER BY rowid DESC").fetchone()[0]
        self.assertNotIn("/", stored)
        self.assertNotIn("<", stored)
        self.assertTrue(stored.endswith(".pdf"))
        dl = self.b["alice"].get(f"/documents/{doc}/download")
        self.assertIn("attachment", dl.headers["Content-Disposition"])
        self.assertEqual(dl.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(dl.mimetype, "application/pdf")

    def test_stored_html_in_a_text_file_is_never_rendered(self):
        r = self.b["alice"].upload("/documents/new", content=b"<script>alert(1)</script>", filename="n.txt", category="Other")
        d = r.headers["Location"].rsplit("/", 1)[-1]
        dl = self.b["alice"].get(f"/documents/{d}/download")
        self.assertEqual((dl.mimetype, "attachment" in dl.headers["Content-Disposition"]), ("text/plain", True))


# ---------------------------------------------------------------------------------------
class TestSessionsAndRequestIntegrity(Base):
    def test_state_changing_posts_without_a_valid_csrf_token_do_nothing(self):
        doc = self.new_doc()
        for bad in (None, "", "forged"):
            data = {"confirm": "yes"} if bad is None else {"confirm": "yes", "csrf": bad}
            r = self.b["alice"].c.post(f"/documents/{doc}/delete", data=data)
            self.assertEqual(r.status_code, 400)
        self.assertIsNone(self.raw().execute("SELECT deleted_at FROM documents").fetchone()[0])
        self.assertTrue(self.audit_rows(action="csrf_rejected"))

    def test_login_locks_after_repeated_failures_even_for_the_right_password(self):
        for _ in range(5):
            self.assertEqual(Browser(self.app).login("erin", "wrong-guess-123").status_code, 401)
        self.assertEqual(Browser(self.app).login("erin").status_code, 401)

    def test_login_does_not_reveal_which_usernames_exist(self):
        a = Browser(self.app).login("erin", "wrong-guess-123")
        b = Browser(self.app).login("no-such-user", "wrong-guess-123")
        self.assertEqual((a.status_code, a.data.count(b"Wrong username")), (b.status_code, b.data.count(b"Wrong username")))

    def test_cookie_flags_headers_and_hashed_session_storage(self):
        br = Browser(self.app)
        page = br.c.get("/login").text
        tok = re.search(r'name="form_token" value="([^"]+)"', page).group(1)
        r = br.c.post("/login", data={"username": "erin", "password": PW, "form_token": tok})
        cookie = r.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        raw_token = re.search(r"tv_session=([^;]+)", cookie).group(1)
        stored = [x[0] for x in self.raw().execute("SELECT token_hash FROM sessions")]
        self.assertNotIn(raw_token, stored)
        h = br.c.get("/documents").headers
        self.assertIn("default-src 'none'", h["Content-Security-Policy"])
        self.assertEqual((h["X-Frame-Options"], h["Cache-Control"]), ("DENY", "no-store"))

    def test_idle_sessions_expire(self):
        self.raw().execute("UPDATE sessions SET last_seen='2000-01-01T00:00:00Z'")
        self.assertEqual(self.b["carol"].get("/documents").status_code, 302)

    def test_forged_session_cookie_is_rejected(self):
        c = self.app.test_client()
        c.set_cookie("tv_session", "A" * 43)
        self.assertEqual(c.get("/documents").status_code, 302)


if __name__ == "__main__":
    unittest.main()
