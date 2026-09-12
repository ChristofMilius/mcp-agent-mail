"""
base.py — SecretProvider protocol
=================================
A provider resolves a named secret to a SecretString. It never exposes the
raw value as a plain str to callers; SecretString is the opaque carrier.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from mcp_agent_mail.secrets import SecretString


class MissingSecretError(Exception):
    """Raised when a required secret cannot be resolved by any backend."""


@runtime_checkable
class SecretProvider(Protocol):
    """
    A provider resolves a named secret to an opaque SecretString.

    Implementations must:
      - return SecretString(raw) — never a plain str
      - return None when the secret is absent (not raise, unless a real
        failure occurred that must abort resolution)
      - never fabricate or fall back to a known value
      - not log/print/repr the value (guaranteed by SecretString)
    """

    name: str

    def get(self, secret_name: str) -> SecretString | None: ...


# Re-exported for convenience — SecretValue IS SecretString in M1.
# The alias documents intent at call sites (what is being passed around).
SecretValue = SecretString

__all__ = ["MissingSecretError", "SecretProvider", "SecretValue"]
