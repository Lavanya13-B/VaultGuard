CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','owner','viewer')),
  active INTEGER NOT NULL DEFAULT 1,
  failed_count INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT,
  created_at TEXT NOT NULL
);

-- Server-side sessions: nothing the client holds is trusted on its own.
-- Only a hash of the cookie token is stored, so a DB leak is not a session leak.
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  csrf TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  ip TEXT
);

CREATE TABLE IF NOT EXISTS documents (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  owner_id INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  current_version INTEGER NOT NULL,
  deleted_at TEXT,
  deleted_by INTEGER REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS versions (
  doc_id TEXT NOT NULL REFERENCES documents(id),
  version INTEGER NOT NULL,
  blob_name TEXT NOT NULL,
  original_filename TEXT NOT NULL,
  mime TEXT NOT NULL,
  size INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  wrapped_key BLOB NOT NULL,          -- emptied on delete (crypto-shredding)
  uploaded_by INTEGER NOT NULL REFERENCES users(id),
  uploaded_at TEXT NOT NULL,
  PRIMARY KEY (doc_id, version)
);

-- Grants are never deleted, only revoked, so "who could read this, and when"
-- stays answerable.
CREATE TABLE IF NOT EXISTS grants (
  id INTEGER PRIMARY KEY,
  doc_id TEXT NOT NULL REFERENCES documents(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  level TEXT NOT NULL CHECK (level IN ('read','edit')),
  granted_by INTEGER NOT NULL REFERENCES users(id),
  granted_at TEXT NOT NULL,
  expires_at TEXT,
  revoked_at TEXT,
  revoked_by INTEGER REFERENCES users(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_grant
  ON grants(doc_id, user_id) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  actor_id INTEGER,
  actor_name TEXT,
  action TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('success','denied','error')),
  doc_id TEXT,
  target_user TEXT,
  detail TEXT,
  ip TEXT,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_doc ON audit_log(doc_id);

-- Layer 1 of tamper resistance: the database itself refuses edits and deletes.
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
