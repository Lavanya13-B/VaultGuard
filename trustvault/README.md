# VaultGuard — secure document sharing with a real audit trail

Flask + SQLite + AES-256-GCM. Server-rendered, no JavaScript, so there is no client-side
logic that could be mistaken for a security control.

```
pip install -r requirements.txt
python manage.py seed-demo                 # dev only: admin, alice, bob (owners), carol, dave (viewers)
Windows PowerShell: set `$env:TRUSTVAULT_INSECURE_COOKIES="1"` and `$env:TRUSTVAULT_DEMO_MODE="1"`, then run `python run.py`.
macOS/Linux: `TRUSTVAULT_INSECURE_COOKIES=1 TRUSTVAULT_DEMO_MODE=1 python run.py`  # http://127.0.0.1:5000
python -m unittest -v                      # 36 security tests
```

## Evaluator demo access (local/demo use only)
Run `python manage.py seed-demo`, then set `TRUSTVAULT_INSECURE_COOKIES=1` and `TRUSTVAULT_DEMO_MODE=1` in your environment before starting the app. In Windows PowerShell, use `$env:TRUSTVAULT_INSECURE_COOKIES="1"` and `$env:TRUSTVAULT_DEMO_MODE="1"`. The login page will show quick sign-in buttons for these demo accounts:

| Role | Username | Password |
|---|---|---|
| Admin | `admin` | `Demo-Passw0rd!x` |
| Owner | `alice` | `Demo-Passw0rd!x` |
| Viewer | `carol` | `Demo-Passw0rd!x` |

The quick sign-in buttons are hidden unless `TRUSTVAULT_DEMO_MODE=1` is set. This mode exposes demo credentials
and must only be used for a local evaluation/demo instance, never for a public production deployment.

Real users: `python manage.py create-user <name> <admin|owner|viewer>`. Production: run behind TLS,
set `TRUSTVAULT_MASTER_KEY`, `TRUSTVAULT_AUDIT_KEY`, `TRUSTVAULT_SECRET_KEY` (64 hex chars each) from a
secret manager, **not** on the same host/volume as the database.

## Roles (written down, enforced on the server)

| | Administrator | Owner | Viewer |
|---|---|---|---|
| Create / deactivate users | yes | – | – |
| Read the audit log, verify its integrity | yes | own documents' history only | – |
| Upload documents | – | yes | – |
| Read a document | only if granted | own + granted | only if granted |
| Edit (new version, rename, recategorise) | only if granted `edit` | own + granted `edit` | only if granted `edit` |
| Delete a document | – | own only | – |
| Grant / change / revoke access | – | own documents only | – |

Deliberate choice: **an administrator can see that a document exists (name, owner, who touched it) but cannot read its
contents without being granted it like anyone else.** Admin power is over people and the record, not over the files.
Grantees with `edit` cannot re-share or delete; only the owner can.

## How the three standards are met

**1. Reachable only by someone who was granted it.**
- One function, `access.access_level()`, decides. Every route taking a document id calls it through `need()`; there is
  no other path to a document or its bytes (no public links, no static file serving, blobs have random names).
- It queries the database on every request. Nothing cached, nothing signed, no tokens that carry permission.
- No grant → **404**, identical to "does not exist" (ids can't be probed). Some access but not enough → 403.
- Search and listings are filtered *in SQL* by ownership/grant, so results can't leak a name.
- Defence in depth: files are encrypted at rest with a per-version key; blobs are bound to their document id, so a
  swapped file fails to decrypt rather than serving the wrong document.
- `test_every_route_that_takes_a_document_id_is_guarded` walks the Flask URL map, so a route added later without a
  guard fails the build.

**2. You can prove who reached it — including refused attempts.**
- Logged: login/failed login, upload (and rejected uploads), view, download (with version + SHA-256 of the bytes
  released), content/metadata changes, delete, every grant/change/revoke, refused access of any kind, CSRF rejections,
  user creation/deactivation, and admins viewing the log itself.
- A download writes its audit row **before** a byte is released. If the log can't be written, the file isn't served.
- **What stops the log being quietly altered?** Three layers: (1) database triggers reject UPDATE/DELETE on the table;
  (2) each row carries `HMAC-SHA256(audit_key, previous_hash | row)`, so editing, deleting, inserting or reordering any
  row breaks the chain from that point, and someone with only the DB file can't recompute it because the key isn't in
  the DB; (3) the admin page shows the current head (count + hash) to copy somewhere the app cannot write; verifying
  against that anchor also catches deletion of the *newest* rows, which a chain alone cannot. Tests drop the triggers
  and tamper to prove each case is detected.
- Honest limit: someone who holds **both** the database and the audit key can rewrite history. Mitigation is
  operational: keep the key off the DB host and anchor the head externally on a schedule.

**3. Taking access away works immediately.**
- Revoking sets `revoked_at`; the very next request from that person fails, on the same session, for downloads, edits,
  version history, listings and search. There is nothing issued earlier that can outlive it (no share links, no
  bearer tokens, no cached permissions).
- Deactivating a user deletes their sessions at once; inactive users fail the access check even with live grants.
- Deleting a document revokes all grants and erases the encryption keys, so remaining ciphertext (backups) is
  unreadable. The audit record of it stays.
- Grants can carry an expiry; changing a password signs out all other sessions.

## Other controls
Scrypt password hashing, 12+ char minimum, lockout after 5 failures (15 min), constant-time dummy hash for unknown
users, hashed server-side session tokens with idle (30 min) and absolute (8 h) expiry, HttpOnly + SameSite=Strict
cookies, per-session CSRF tokens on every POST, strict CSP (`default-src 'none'`, no inline script), nosniff,
`Cache-Control: no-store`, downloads always `attachment`, allow-listed upload types verified by content (magic bytes /
zip structure / UTF-8), size cap, sanitised filenames, parameterised SQL, escaped output.

## Deliberately left out (and why)
- **Share links / external-recipient URLs:** they are exactly how access outlives a revocation.
- **Self-registration, SSO:** accounts are admin-created. SSO + MFA is the first thing to add for production.
- **Admin override to read content or "break glass":** would undermine standard 1; would need dual control + audit.
- **Previews/inline rendering:** a stored-XSS and sniffing surface; everything downloads as an attachment.
- **Antivirus scan, rate limiting beyond login, multi-node:** noted as next steps; SQLite is single-node.
- **Ownership transfer when an owner leaves:** deactivation protects their documents but they stay orphaned.
- **Trust in `X-Forwarded-For`:** IPs recorded are the socket peer; configure your proxy before trusting more.
