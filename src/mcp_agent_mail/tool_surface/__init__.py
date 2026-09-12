"""
tool_surface — MCP tool registration
====================================
Each module owns one domain and exposes a register(server, ctx) function
that attaches its tools to the MCPServer via closures over the AppContext.

Splitting by domain keeps each file small and testable. server.py composes
them; nothing here reads module globals or constructs its own dependencies.

Every tool:
  - returns a JSON string (json.dumps) — the model always gets structured data
  - routes unexpected exceptions through errors.tool_error() so tracebacks
    stay server-side
  - never returns key material, secrets, or file paths
"""

from mcp_agent_mail.tool_surface import (
    archive_tools,
    contacts_tools,
    crypto_tools,
    email_tools,
    misc_tools,
)


def register_all(server, ctx) -> None:
    """Register every domain's tools on the given MCPServer."""
    misc_tools.register(server, ctx)
    email_tools.register(server, ctx)
    contacts_tools.register(server, ctx)
    crypto_tools.register(server, ctx)
    archive_tools.register(server, ctx)


__all__ = ["register_all"]
