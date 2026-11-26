"""Content encryption keys (ADR 0002, P3): a keyring, so the key can be rotated without losing content.

Each stored body records the id of the key that encrypted it. The first key of the ring encrypts;
every key in the ring decrypts. Sources, first match wins:

    CONTENT_ENCRYPTION_KEYS="2026-11:<fernet key>,default:<old fernet key>"
    CONTENT_ENCRYPTION_KEYS_FILE=/run/secrets/tether-content-keys   one "id:key" per line, '#' comments
    CONTENT_ENCRYPTION_KEY=<fernet key>                             a single key with the id "default"

The file form suits keys delivered by a secret manager (Vault Agent, Kubernetes secret, systemd
credentials), so the key need not live in the compose .env file.

Rotation: put a new key first, keep the old ones after it, run `python -m app.rekey` (or
POST /v1/admin/audit/content/rekey) until nothing is left on the old ids, then remove them.
GET /v1/admin/audit/content/keys shows which ids are still in use. Key material is never returned.
"""
import os
import re
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

LEGACY_ID = "default"  # rows written before keyrings (migration 0012) carry this id
KEY_ID = re.compile(r"^[A-Za-z0-9._-]{1,32}$")


class KeyringError(ValueError):
    """The configured keys are malformed. Raised at startup so a bad key never reaches a write."""


class MissingKey(LookupError):
    """A row was encrypted with a key id that is not in the ring."""

    def __init__(self, key_id):
        super().__init__(f"content key {key_id!r} is not configured")
        self.key_id = key_id


class Keyring:
    def __init__(self, entries):
        if not entries:
            raise KeyringError("no content encryption key")
        self.ids, self._f = [], {}
        for key_id, key in entries:
            if not KEY_ID.match(key_id):
                raise KeyringError(f"invalid content key id {key_id!r} (letters, digits, '.', '_', '-'; at most 32)")
            if key_id in self._f:
                raise KeyringError(f"content key id {key_id!r} appears twice")
            try:
                self._f[key_id] = Fernet(key.strip())
            except (ValueError, TypeError):
                raise KeyringError(f"content key {key_id!r} is not a valid Fernet key") from None
            self.ids.append(key_id)

    @property
    def active(self):
        return self.ids[0]

    def encrypt(self, raw: bytes):
        """(key id, ciphertext) with the active key."""
        return self.active, self._f[self.active].encrypt(raw)

    def decrypt(self, key_id, token: bytes) -> bytes:
        """Raises MissingKey for an unknown id and InvalidToken for a wrong key or tampered data."""
        f = self._f.get(key_id or LEGACY_ID)
        if f is None:
            raise MissingKey(key_id)
        return f.decrypt(token)


def parse(text):
    entries = []
    for part in re.split(r"[,\n]", text):
        part = part.strip()
        if not part or part.startswith("#"):
            continue
        key_id, sep, key = part.partition(":")
        if not sep:
            raise KeyringError("each content key must be written as id:key")
        entries.append((key_id.strip(), key.strip()))
    return entries


def load():
    """The ring from the environment. None when no source is set; KeyringError when one is malformed."""
    if os.environ.get("CONTENT_ENCRYPTION_KEYS", "").strip():
        return Keyring(parse(os.environ["CONTENT_ENCRYPTION_KEYS"]))
    path = os.environ.get("CONTENT_ENCRYPTION_KEYS_FILE", "").strip()
    if path:
        try:
            text = Path(path).read_text()
        except OSError as e:
            raise KeyringError(f"cannot read CONTENT_ENCRYPTION_KEYS_FILE: {e.strerror}") from None
        return Keyring(parse(text))
    if os.environ.get("CONTENT_ENCRYPTION_KEY", "").strip():
        return Keyring([(LEGACY_ID, os.environ["CONTENT_ENCRYPTION_KEY"])])
    return None


__all__ = ["Keyring", "KeyringError", "MissingKey", "InvalidToken", "LEGACY_ID", "load", "parse"]
