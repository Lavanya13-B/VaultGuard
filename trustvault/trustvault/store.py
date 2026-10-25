"""Encrypted blob storage. Files never touch disk in plaintext.

Each file version gets its own random 256-bit data key. The data key is wrapped with the
master key and kept in the DB; the ciphertext lives in a randomly named file. AES-GCM
binds each blob to (doc_id, version) via associated data, so swapping two blobs on disk
makes decryption fail instead of silently serving the wrong document. Deleting a document
destroys its wrapped keys, which makes any leftover ciphertext (backups included)
unreadable.
"""
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class Store:
    def __init__(self, root, master_key: bytes):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.master = AESGCM(master_key)

    @staticmethod
    def _aad(doc_id, version):
        return f"{doc_id}:{version}".encode()

    def _path(self, blob_name):
        if not (len(blob_name) == 32 and all(c in "0123456789abcdef" for c in blob_name)):
            raise ValueError("bad blob name")
        return self.root / blob_name[:2] / blob_name

    def put(self, doc_id, version, data: bytes):
        key = AESGCM.generate_key(bit_length=256)
        nonce = secrets.token_bytes(12)
        ct = AESGCM(key).encrypt(nonce, data, self._aad(doc_id, version))
        wnonce = secrets.token_bytes(12)
        wrapped = wnonce + self.master.encrypt(wnonce, key, self._aad(doc_id, version))
        name = secrets.token_hex(16)
        path = self._path(name)
        path.parent.mkdir(exist_ok=True)
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(nonce + ct)
        os.replace(tmp, path)
        return name, wrapped

    def get(self, blob_name, wrapped: bytes, doc_id, version) -> bytes:
        if not wrapped:
            raise FileNotFoundError("document content has been destroyed")
        key = self.master.decrypt(wrapped[:12], wrapped[12:], self._aad(doc_id, version))
        raw = self._path(blob_name).read_bytes()
        return AESGCM(key).decrypt(raw[:12], raw[12:], self._aad(doc_id, version))

    def remove(self, blob_name):
        try:
            self._path(blob_name).unlink()
        except FileNotFoundError:
            pass
