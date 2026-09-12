"""
secrets.py — Sensitive value wrapper
======================================
Prevents accidental exposure of secrets (passphrases, tokens) via:
  - repr() / str()         → always returns "***"
  - logging                → repr never prints the value
  - JSON serialization     → raises TypeError (must be explicit)
  - Traceback locals       → shows SecretString(***), not the value
  - Attribute mutation     → immutable after construction (__slots__)

Usage:
    from mcp_agent_mail.secrets import SecretString

    passphrase = SecretString(raw_value)
    passphrase.expose_secret()          # Only way to get the real value
    bool(passphrase)                    # True if non-empty
    passphrase == SecretString("x")     # Constant-time comparison
"""

from __future__ import annotations

import hmac


class SecretString:
    """
    Immutable, opaque wrapper for sensitive string values.

    The only way to access the wrapped value is via .expose_secret().
    All other operations — repr, str, logging, equality — are safe.

    Design choices:
      __slots__   : prevents __dict__ creation (no accidental serialization)
      object.__setattr__ : bypasses our own __setattr__ guard during __init__
      hmac.compare_digest: constant-time equality (prevents timing attacks
                           on passphrase comparison)
    """

    __slots__ = ("_value",)

    def __init__(self, value: str):
        if not isinstance(value, str):
            raise TypeError(f"SecretString requires str, got {type(value).__name__}")
        object.__setattr__(self, "_value", value)

    def expose_secret(self) -> str:
        """
        Explicit, named accessor — the ONLY path to the raw value.
        The name is intentionally verbose. Every call site is a conscious
        decision to handle sensitive material and is easy to grep for.
        """
        return object.__getattribute__(self, "_value")

    def __repr__(self) -> str:
        return "SecretString(***)"

    def __str__(self) -> str:
        return "***"

    def __bool__(self) -> bool:
        return bool(object.__getattribute__(self, "_value"))

    def __len__(self) -> int:
        # Allow len() check without exposing value
        return len(object.__getattribute__(self, "_value"))

    def __eq__(self, other: object) -> bool:
        """
        Constant-time comparison to prevent timing side-channels.
        Two SecretStrings are equal iff their values are identical.
        Comparing to any non-SecretString always returns False.
        """
        if not isinstance(other, SecretString):
            return False
        return hmac.compare_digest(
            self.expose_secret(),
            other.expose_secret(),
        )

    def __hash__(self):
        raise TypeError(
            "SecretString is not hashable — "
            "it must not be used as a dict key or in a set."
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("SecretString is immutable after construction.")

    def __reduce__(self):
        raise TypeError(
            "SecretString cannot be pickled — "
            "do not serialize sensitive values."
        )


__all__ = ["SecretString"]
