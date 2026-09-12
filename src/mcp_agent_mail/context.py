"""
context.py — application object graph
=====================================
A single container holding the live instances the tool surface needs.
Tools receive this context at registration time (via closures) instead of
reading module globals — this keeps the tool surface testable without a
full .env bootstrap and makes the wiring explicit.

No secrets live on this object (Config keeps them, masked).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp_agent_mail.archive import EmailArchive
    from mcp_agent_mail.config import Config
    from mcp_agent_mail.contacts import ContactBook
    from mcp_agent_mail.crypto import GPGCrypto
    from mcp_agent_mail.email_client import EmailClient


@dataclass(frozen=True)
class AppContext:
    cfg: Config
    crypto: GPGCrypto
    contacts: ContactBook
    email_client: EmailClient
    archive: EmailArchive


__all__ = ["AppContext"]
