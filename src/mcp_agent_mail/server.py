"""
server.py — MCP server assembly
===============================
Wires Config → logging → crypto → contacts → archive → email_client into
an AppContext, builds an MCPServer, and registers the tool surface.

Uses mcp 2.x (`mcp.server.mcpserver.MCPServer`). See MILESTONE.md for the
FastMCP → MCPServer migration note.

Startup is fail-fast: Config(require_secrets=True) aborts if any required
secret is missing. The server will not run half-configured.
"""

from __future__ import annotations

import logging

from mcp.server.mcpserver import MCPServer

from mcp_agent_mail import __version__
from mcp_agent_mail.archive import EmailArchive
from mcp_agent_mail.config import Config, ConfigError
from mcp_agent_mail.contacts import ContactBook
from mcp_agent_mail.context import AppContext
from mcp_agent_mail.crypto import GPGCrypto
from mcp_agent_mail.email_client import EmailClient
from mcp_agent_mail.logging_setup import setup_logging
from mcp_agent_mail.tool_surface import register_all

logger = logging.getLogger(__name__)

SERVER_NAME = "mcp-agent-mail"

INSTRUCTIONS = """
Email + PGP agent mail. Read, send, and reply to encrypted email; manage a
contact book with GPG key provenance; archive and search read mail.

Security model:
  - Sending encrypts by default and REFUSES to downgrade to plaintext
    silently. If no key is on file for the recipient, either obtain their
    public key (they can email you their PGP public key block — it is
    intercepted and linked automatically) or re-send explicitly with
    encrypt=False.
  - Inbound PGP public keys are imported and linked automatically; key
    blocks never appear in email bodies returned to you.
  - Private keys and passphrases are never exposed by any tool.
  - email_read caps bodies at 2000 chars; retrieve full text via archive_get.
""".strip()


def validate_identity_entries(cfg, contacts) -> list[str]:
    """
    Check the identity setup: the agent (EMAIL_ADDRESS) and the owner
    (OWNER_EMAIL) each need exactly one contact entry holding their email.
    Returns a list of human-readable problems (empty = healthy).
    """
    problems: list[str] = []
    for email, label in ((cfg.email_address, "agent"), (cfg.owner_email, "owner")):
        if not email:
            continue
        wanted = email.strip().lower()
        holders = [
            c["name"]
            for c in contacts.list_all()
            if c.get("email", "").strip().lower() == wanted
        ]
        if not holders:
            problems.append(
                f"identity '{label}' ({email}) has no contact entry — "
                f"it must be provisioned during setup"
            )
        elif len(holders) > 1:
            problems.append(
                f"identity '{label}' ({email}) has {len(holders)} entries "
                f"({', '.join(sorted(holders))}) — exactly one is required"
            )
    return problems


def build_context(require_secrets: bool = True) -> AppContext:
    """
    Construct the full application object graph.

    Args:
        require_secrets: When True (server mode) missing secrets abort startup.
                         CLI diagnostics pass False to inspect partial config.
    """
    cfg = Config(require_secrets=require_secrets)
    setup_logging(cfg.logs_dir)

    crypto = GPGCrypto(cfg)
    contacts = ContactBook(cfg)
    archive = EmailArchive(cfg)
    email_client = EmailClient(cfg, crypto, contacts, archive=archive)

    if require_secrets:
        identity_problems = validate_identity_entries(cfg, contacts)
        if identity_problems:
            raise ConfigError(
                "Identity setup incomplete — the server will not run half-configured:\n"
                "  - " + "\n  - ".join(identity_problems) + "\n"
                "Identity is a setup step: the agent (EMAIL_ADDRESS) and the owner "
                "(OWNER_EMAIL) each need exactly one contact entry. See README "
                "'Identity & setup'."
            )

    return AppContext(
        cfg=cfg,
        crypto=crypto,
        contacts=contacts,
        email_client=email_client,
        archive=archive,
    )


def create_server(ctx: AppContext | None = None) -> MCPServer:
    """Build an MCPServer with the full tool surface registered."""
    if ctx is None:
        ctx = build_context(require_secrets=True)

    server = MCPServer(name=SERVER_NAME, instructions=INSTRUCTIONS)
    register_all(server, ctx)

    logger.info(
        "[server] %s v%s ready (backend=%s, account=%s)",
        SERVER_NAME, __version__, ctx.cfg.secret_backend, ctx.cfg.email_address,
    )
    return server


def run(transport: str = "stdio", host: str = "127.0.0.1", port: int = 8000) -> None:
    """Build and run the server.

    transport: "stdio" (default), "sse", or "streamable-http".
    """
    server = create_server()
    if transport == "stdio":
        server.run(transport="stdio")
    else:
        server.run(transport=transport, host=host, port=port)


__all__ = ["SERVER_NAME", "build_context", "create_server", "run", "validate_identity_entries"]
