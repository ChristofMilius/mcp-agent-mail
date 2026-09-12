"""
mcp_agent_mail — standalone MCP email client with GPG cryptography.

Security invariant (same as the source project, kept intact):
raw cryptographic material never passes through the model's context window
as a tool argument. All crypto operations are handled in code against the
local GPG keyring; tools accept human-meaningful identifiers only.
"""

from __future__ import annotations

__version__ = "0.1.0"


def main() -> int:
    """Console entry point (`mcp-agent-mail`). Dispatches to the CLI."""
    from mcp_agent_mail.cli import main as _cli_main

    return _cli_main()


__all__ = ["__version__", "main"]
