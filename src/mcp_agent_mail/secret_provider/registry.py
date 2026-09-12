"""
registry.py — secret backend selection
======================================
`SECRET_BACKEND` selects the provider. M1 registers only `env`.

Backends beyond `env` (Windows Credential Manager, KeePassXC, gpg-agent
pinentry cache, Linux/WSL SecretService) are planned but not yet
implemented — selecting one raises a clear error instead of silently
falling back to the env provider. No silent downgrade, in the same spirit
as the outbound encryption gate.
"""

from __future__ import annotations

from mcp_agent_mail.secret_provider.base import SecretProvider
from mcp_agent_mail.secret_provider.env_provider import EnvSecretProvider

# Default backend when SECRET_BACKEND is unset / empty.
DEFAULT_SECRET_BACKEND = "env"

# Backends that are implemented and selectable today.
_IMPLEMENTED: dict[str, type[SecretProvider]] = {
    EnvSecretProvider.name: EnvSecretProvider,
}

# Backends on the roadmap (M2) — selected but unimplemented → explicit error.
_ROADMAP_BACKENDS = frozenset(
    {
        "wincred",      # Windows Credential Manager (DPAPI via `keyring`)
        "keepassxc",    # KeePassXC database via keepassxc-cli
        "pinentry",     # gpg-agent pinentry cache — tool never holds passphrase
        "secretservice",  # Linux/WSL GNOME Keyring (SecretService)
    }
)


def known_backends() -> list[str]:
    """Return the sorted list of implemented backend names."""
    return sorted(_IMPLEMENTED)


def get_provider(backend: str | None) -> SecretProvider:
    """
    Instantiate the secret provider for the given backend name.

    Raises:
        ValueError: if the backend is unknown, or known but not yet
                    implemented (roadmap backend).
    """
    name = (backend or DEFAULT_SECRET_BACKEND).strip().lower()
    if not name:
        name = DEFAULT_SECRET_BACKEND

    cls = _IMPLEMENTED.get(name)
    if cls is not None:
        return cls()

    if name in _ROADMAP_BACKENDS:
        raise ValueError(
            f"[secrets] backend '{name}' is on the roadmap (M2) but not yet "
            f"implemented. Implemented backends: {sorted(_IMPLEMENTED)}."
        )
    raise ValueError(
        f"[secrets] unknown secret backend '{name}'. "
        f"Implemented backends: {sorted(_IMPLEMENTED)}."
    )


__all__ = ["DEFAULT_SECRET_BACKEND", "get_provider", "known_backends"]
