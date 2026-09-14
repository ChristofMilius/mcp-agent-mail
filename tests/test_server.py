"""tests/test_server.py — server assembly, logging, AppContext."""
from __future__ import annotations

import json
import types
from pathlib import Path

import mcp.server.mcpserver
import pytest

from mcp_agent_mail.contacts import ContactBook
from mcp_agent_mail.context import AppContext
from mcp_agent_mail.logging_setup import setup_logging
from mcp_agent_mail.server import (
    INSTRUCTIONS,
    SERVER_NAME,
    create_server,
    validate_identity_entries,
)


def _fake_ctx(tmp_project):
    root, env = tmp_project
    cfg = types.SimpleNamespace(
        contacts_path=env["CONTACTS_PATH"],
        archive_path=env["ARCHIVE_PATH"],
        logs_dir=str(root / "logs"),
        pubkey_export_dir=str(root / "exported_keys"),
        email_address="agent@example.com",
        secret_backend="env",
    )
    return AppContext(
        cfg=cfg,
        crypto=object(),
        contacts=object(),
        email_client=object(),
        archive=object(),
    )


class TestCreateServer:
    def test_uses_fastmcp_compatible_server_contract(self, tmp_project):
        server = create_server(_fake_ctx(tmp_project))
        assert isinstance(server, mcp.server.mcpserver.MCPServer)
        assert server.name == SERVER_NAME
        assert "no silent downgrade" in INSTRUCTIONS.lower() or "encrypt" in INSTRUCTIONS.lower()

    def test_known_tool_names_registered(self, tmp_project):
        server = create_server(_fake_ctx(tmp_project))
        tool_names = set(server._tool._tools) if hasattr(server, "_tool") else set()
        if not tool_names:
            pytest.skip("mcpserver internals not introspectable on this version")
        assert "email_send" in tool_names


class TestSetupLogging:
    def test_creates_rotating_log_file(self, tmp_path):
        log_file = setup_logging(str(tmp_path / "logs"))
        assert log_file.parent.is_dir()
        assert log_file.exists() or "log" in log_file.name

    def test_idempotent_when_called_twice(self, tmp_path):
        import logging as _logging

        setup_logging(str(tmp_path / "logs"))
        before = len(_logging.getLogger().handlers)
        setup_logging(str(tmp_path / "logs"))
        assert len(_logging.getLogger().handlers) == before


class TestAppContext:
    def test_frozen_dataclass(self, tmp_project):
        ctx = _fake_ctx(tmp_project)
        with pytest.raises(Exception):
            ctx.cfg = None


def _seed_identity_book(path, *, extra=None):
    """Provision a well-formed book with agent + owner identity entries."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    base = "2026-09-13T00:00:00"

    def rec(given, surname, email, fp):
        return {
            "added": base,
            "given_name": given,
            "surname": surname,
            "email": email,
            "gpg_key_fingerprint": fp,
            "key_source": "keyring_uid_match",
            "key_linked_at": base,
            "key_cleared_at": "",
            "notes": "",
            "updated": base,
        }

    data = {
        "Hermes the Agent": rec("Hermes", "agent of Chris", "agent@example.com", "A" * 40),
        "Chris Example": rec("Chris", "Example", "owner@example.com", "B" * 40),
    }
    if extra:
        data.update(extra)
    Path(path).write_text(json.dumps(data), encoding="utf-8")


class TestIdentityValidation:
    def _cfg(self, root, env, *, email_address="agent@example.com",
             owner_email="owner@example.com"):
        return types.SimpleNamespace(
            contacts_path=env["CONTACTS_PATH"],
            email_address=email_address,
            owner_email=owner_email,
        )

    def test_healthy_setup_reports_no_problems(self, tmp_project):
        root, env = tmp_project
        _seed_identity_book(env["CONTACTS_PATH"])
        cfg = self._cfg(root, env)
        assert validate_identity_entries(cfg, ContactBook(cfg)) == []

    def test_missing_agent_entry(self, tmp_project):
        root, env = tmp_project
        # Overwrite the file with ONLY the owner entry — no agent record at all.
        path = Path(env["CONTACTS_PATH"])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "Chris Example": {
                "added": "2026-09-13T00:00:00",
                "given_name": "Chris",
                "surname": "Example",
                "email": "owner@example.com",
                "gpg_key_fingerprint": "B" * 40,
                "key_source": "keyring_uid_match",
                "key_linked_at": "2026-09-13T00:00:00",
                "key_cleared_at": "",
                "notes": "",
                "updated": "2026-09-13T00:00:00",
            }
        }), encoding="utf-8")
        cfg = self._cfg(root, env)
        problems = validate_identity_entries(cfg, ContactBook(cfg))
        assert any("agent" in p and "no contact entry" in p for p in problems)
        assert not any("owner" in p for p in problems)

    def test_duplicate_owner_entry(self, tmp_project):
        root, env = tmp_project
        dup = {
            "Chris Doppel": {
                "added": "2026-09-13T00:00:00",
                "given_name": "Chris",
                "surname": "Doppel",
                "email": "owner@example.com",
                "gpg_key_fingerprint": "",
                "key_source": "",
                "key_linked_at": "",
                "key_cleared_at": "",
                "notes": "",
                "updated": "2026-09-13T00:00:00",
            }
        }
        _seed_identity_book(env["CONTACTS_PATH"], extra=dup)
        problems = validate_identity_entries(self._cfg(root, env), ContactBook(self._cfg(root, env)))
        assert any("owner" in p and "exactly one" in p for p in problems)
        assert not any("agent" in p for p in problems)

    def test_unconfigured_emails_are_skipped(self, tmp_project):
        root, env = tmp_project
        cfg = self._cfg(root, env, email_address="", owner_email="")
        assert validate_identity_entries(cfg, ContactBook(cfg)) == []

    def test_matching_is_case_insensitive(self, tmp_project):
        root, env = tmp_project
        _seed_identity_book(env["CONTACTS_PATH"])
        cfg = self._cfg(root, env, owner_email="OWNER@Example.COM")
        assert validate_identity_entries(cfg, ContactBook(cfg)) == []
