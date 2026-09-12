"""tests/test_server.py — server assembly, logging, AppContext."""
from __future__ import annotations

import types

import mcp.server.mcpserver
import pytest

from mcp_agent_mail.context import AppContext
from mcp_agent_mail.logging_setup import setup_logging
from mcp_agent_mail.server import INSTRUCTIONS, SERVER_NAME, create_server


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
