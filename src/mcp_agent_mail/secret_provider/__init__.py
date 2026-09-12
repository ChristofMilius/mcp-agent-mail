"""
secret_provider — pluggable secret resolution
==============================================
Abstraction seam for securely providing key material (email app password,
GPG passphrase) to the agent. M1 ships the `env` backend (reads process
environment / `.env`). Follow-up milestones add backends for:

  - Windows Credential Manager (DPAPI, via the `keyring` package)
  - KeePassXC (keepassxc-cli)
  - gpg-agent pinentry cache (the tool then never holds the GPG passphrase)
  - Linux / WSL SecretService (gnome-keyring) and cross-host interop

Contract for every backend:

  - get(name) returns a SecretString (never a plain str) or None.
  - The value never appears in repr/str/logging/tracebacks — handled by
    SecretString itself.
  - A backend must never fall back to a hardcoded value. Missing secret
    means None; the caller decides whether that is fatal.
"""

from mcp_agent_mail.secret_provider.base import (
    MissingSecretError,
    SecretProvider,
    SecretValue,
)
from mcp_agent_mail.secret_provider.env_provider import EnvSecretProvider
from mcp_agent_mail.secret_provider.registry import (
    DEFAULT_SECRET_BACKEND,
    get_provider,
    known_backends,
)

__all__ = [
    "DEFAULT_SECRET_BACKEND",
    "EnvSecretProvider",
    "MissingSecretError",
    "SecretProvider",
    "SecretValue",
    "get_provider",
    "known_backends",
]
