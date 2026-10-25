"""CLI: python manage.py <command>
  create-user <username> <admin|owner|viewer>   prompts for a password
  seed-demo                                      demo users (password: Demo-Passw0rd!x) - DEV ONLY
  verify-audit                                   walk the hash chain, print the head to anchor
"""
import getpass
import sys

from trustvault import audit, auth
from trustvault import db as dbm
from trustvault.config import load_config

cfg = load_config()
dbm.init_db(cfg["DATABASE"])
db = dbm.connect(cfg["DATABASE"])


def add(username, name, role, pw):
    with dbm.tx(db):
        auth.create_user(db, username, name, role, pw)
        audit.record(db, cfg["AUDIT_KEY"], actor_name="cli", action="user_created",
                     target_user=username, detail={"role": role})


cmd = sys.argv[1] if len(sys.argv) > 1 else ""
if cmd == "create-user" and len(sys.argv) == 4:
    pw = getpass.getpass("Password (12+ chars): ")
    if len(pw) < auth.MIN_PASSWORD:
        sys.exit("Password too short.")
    add(sys.argv[2].lower(), sys.argv[2], sys.argv[3], pw)
    print("created")
elif cmd == "seed-demo":
    for u, n, r in [("admin", "Ada Admin", "admin"), ("alice", "Alice (HR owner)", "owner"),
                    ("bob", "Bob (Legal owner)", "owner"), ("carol", "Carol (viewer)", "viewer"),
                    ("dave", "Dave (viewer)", "viewer")]:
        try:
            add(u, n, r, "Demo-Passw0rd!x")
        except Exception as e:
            print(f"skip {u}: {e}")
    print("Demo users: admin, alice, bob, carol, dave  /  password: Demo-Passw0rd!x")
elif cmd == "verify-audit":
    print(audit.verify(db, cfg["AUDIT_KEY"]))
    print("anchor this:", audit.head(db))
else:
    print(__doc__)
