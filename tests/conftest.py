"""tests/conftest.py — shared fixtures."""
from __future__ import annotations

from pathlib import Path

import pytest

# Fake secrets for every test — never hits os.environ; no .env file needed.
_ENV_OVERRIDES = {
    "EMAIL_ADDRESS": "agent@example.com",
    "EMAIL_PASSWORD": "fake-app-password",
    "GPG_KEY_ID": "AAAA" * 10,
    "GPG_PASSPHRASE": "fake-passphrase",
    "IMAP_HOST": "imap.gmail.com",
    "SMTP_HOST": "smtp.gmail.com",
}


@pytest.fixture(autouse=True)
def _env_secrets(monkeypatch):
    """Seed fake secrets so Config fails noisily in every test."""
    for k, v in _ENV_OVERRIDES.items():
        monkeypatch.setenv(k, v)


@pytest.fixture
def tmp_project(tmp_path: Path):
    """
    Return a pair (project_root, env_dict) that simulates a self-contained
    project tree with contacts, archive, logs, and exported_keys dirs.
    """
    root = tmp_path
    contacts = root / "data" / "contacts.json"
    contacts.parent.mkdir(parents=True)
    contacts.write_text("{}", encoding="utf-8")

    env = {
        "CONTACTS_PATH": str(contacts),
        "ARCHIVE_PATH": str(root / "data" / "archive.emails.jsonl"),
        "LOGS_DIR": str(root / "logs"),
        "PUBKEY_EXPORT_DIR": str(root / "exported_keys"),
        "SECRET_BACKEND": "env",
    }
    return root, env
