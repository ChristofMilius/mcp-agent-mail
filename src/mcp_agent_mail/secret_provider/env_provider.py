"""
env_provider.py — environment-backed secret provider (M1 default)
================================================================
Resolves secrets from process environment variables or a `.env` file that
has already been loaded via python-dotenv (config.py does the loading).

This is the development baseline and the simplest backend. It stores secrets
in plaintext on disk (`.env`), so SECURITY.md recommends switching to a
credential-store backend (M2) for production use.
"""

from __future__ import annotations

import os

from mcp_agent_mail.secrets import SecretString


class EnvSecretProvider:
    """Reads secrets from os.environ (already seeded from .env by config)."""

    name = "env"

    def get(self, secret_name: str) -> SecretString | None:
        raw = os.environ.get(secret_name)
        if raw is None or raw == "":
            return None
        return SecretString(raw)


__all__ = ["EnvSecretProvider"]
