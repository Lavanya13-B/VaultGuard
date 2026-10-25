import json
import os
import secrets
from pathlib import Path


def _keys(home: Path) -> dict:
    """Env vars win (production). Otherwise generate once into instance/keys.json (0600).
    The audit key and the master key should live OUTSIDE the database host in production."""
    names = ("MASTER_KEY", "AUDIT_KEY", "SECRET_KEY")
    env = {n: os.environ.get(f"TRUSTVAULT_{n}") for n in names}
    if all(env.values()):
        return {n: bytes.fromhex(v) for n, v in env.items()}
    path = home / "keys.json"
    if not path.exists():
        home.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({n: secrets.token_hex(32) for n in names}))
        os.chmod(path, 0o600)
    stored = json.loads(path.read_text())
    return {n: bytes.fromhex(env[n] or stored[n]) for n in names}


def load_config(overrides=None) -> dict:
    overrides = dict(overrides or {})
    home = Path(overrides.get("HOME") or os.environ.get("TRUSTVAULT_HOME", "instance")).resolve()
    cfg = {
        "HOME": home,
        "DATABASE": str(home / "trustvault.db"),
        "BLOB_DIR": str(home / "blobs"),
        "MAX_UPLOAD": 10 * 1024 * 1024,
        "COOKIE_SECURE": os.environ.get("TRUSTVAULT_INSECURE_COOKIES") != "1",
        "IDLE_MINUTES": 30,
        "ABSOLUTE_HOURS": 8,
        "LOCK_AFTER": 5,
        "LOCK_MINUTES": 15,
    }
    cfg.update(overrides)
    if not all(k in cfg for k in ("MASTER_KEY", "AUDIT_KEY", "SECRET_KEY")):
        cfg.update({k: v for k, v in _keys(home).items() if k not in cfg})
    return cfg
