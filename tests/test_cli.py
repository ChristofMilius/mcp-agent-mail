"""tests/test_cli.py — CLI parser and main() wiring."""
from __future__ import annotations

import pytest

from mcp_agent_mail.cli import build_parser, main


class TestParser:
    def test_subcommands_exist(self):
        p = build_parser()
        for cmd in ["serve", "setup", "doctor", "keys", "archive"]:
            args = p.parse_args([cmd])
            assert hasattr(args, "func"), f"subcommand {cmd!r} not wired"

    def test_default_command_serves_stdio(self, monkeypatch):
        """No subcommand → serve with stdio transport."""
        called = {}

        def fake_run(**kwargs):
            called.update(kwargs)

        import mcp_agent_mail.server
        monkeypatch.setattr(mcp_agent_mail.server, "run", fake_run)
        main([])
        assert called == {"transport": "stdio", "host": "127.0.0.1", "port": 8000}

    def test_serve_http_flag(self, monkeypatch):
        called = {}

        def fake_run(**kwargs):
            called.update(kwargs)

        import mcp_agent_mail.server
        monkeypatch.setattr(mcp_agent_mail.server, "run", fake_run)
        main(["serve", "--http", "--port", "9000"])
        assert called == {"transport": "streamable-http", "host": "127.0.0.1", "port": 9000}

    def test_version_exits_zero(self, capsys):
        with pytest.raises(SystemExit) as e:
            main(["--version"])
        assert e.value.code == 0
        assert "0.1.0" in capsys.readouterr().out

    def test_unknown_command_exits_nonzero(self):
        with pytest.raises(SystemExit) as e:
            main(["nonexistent-command"])
        assert e.value.code == 2
