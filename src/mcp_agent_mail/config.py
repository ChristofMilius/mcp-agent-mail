"""
config.py — All configuration in one place
==========================================
Loads from environment variables / .env file. Never hardcode credentials.

Security:
  - gpg_passphrase and email_password are wrapped in SecretString — never
    appear in repr(), str(), logging, or tracebacks.
  - __repr__ and __str__ are overridden to mask all sensitive fields.
  - FAIL-FAST: when require_secrets=True (server mode), any of the required
    secrets being absent aborts construction instead of printing a warning.
    There is no fallback value for any secret anywhere in the codebase.

Secret resolution:
  - Secrets are resolved via the configured SecretProvider (SECRET_BACKEND,
    default "env"). Providers return SecretString or None. Config never
    holds the raw value as a plain str.

Path resolution:
  - All path fields are resolved to absolute paths at construction time.
  - Relative values in .env (e.g. CONTACTS_PATH=./contacts/contacts.json)
    are resolved relative to the project root (the directory containing the
    package), NOT relative to the process CWD. Agent harnesses set an
    unpredictable CWD when spawning MCP server subprocesses.

  Windows .env note: always use forward slashes in .env path values.
  Backslashes are not reliably handled by python-dotenv.
"""

from __future__ import annotations

import os
from pathlib import Path

from mcp_agent_mail.secret_provider import SecretProvider, get_provider
from mcp_agent_mail.secrets import SecretString

# Load .env file if python-dotenv is available (optional but recommended).
try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover — python-dotenv is a hard dependency
    load_dotenv = None  # type: ignore[assignment]

# Project root — the directory containing the package (src/mcp_agent_mail).
# All relative path env vars are resolved against this, never against CWD.
_BASE = Path(__file__).resolve().parent.parent.parent

if load_dotenv is not None:
    load_dotenv(_BASE / ".env")

# Required secrets. When require_secrets=True every one of these must resolve
# to a non-empty value or construction aborts.
REQUIRED_SECRETS = (
    "EMAIL_ADDRESS",      # account email — the To:/From: identity
    "EMAIL_PASSWORD",     # IMAP/SMTP app password
    "GPG_KEY_ID",         # agent key, used for signing + decryption
    "GPG_PASSPHRASE",     # passphrase for the agent secret key
)


class ConfigError(Exception):
    """Fatal configuration problem — the server must not start."""


def _resolve_path(raw: str) -> str:
    """
    Resolve a path string to an absolute path.

    If the value from the environment is already absolute, return it
    normalized. If relative, resolve relative to the project root (_BASE),
    not the process CWD.
    """
    p = Path(raw)
    if p.is_absolute():
        return str(p)
    return str((_BASE / p).resolve())


class Config:
    def __init__(
        self,
        *,
        require_secrets: bool = True,
        secret_provider: SecretProvider | None = None,
    ):
        # ------------------------------------------------------------------
        # Paths — all resolved to absolute via _resolve_path()
        # ------------------------------------------------------------------
        self.contacts_path: str = _resolve_path(
            os.getenv("CONTACTS_PATH", "data/contacts.json")
        )
        self.logs_dir: str = _resolve_path(os.getenv("LOGS_DIR", "logs"))
        self.pubkey_export_dir: str = _resolve_path(
            os.getenv("PUBKEY_EXPORT_DIR", "exported_keys")
        )
        self.archive_path: str = _resolve_path(
            os.getenv("ARCHIVE_PATH", "data/archive.emails.jsonl")
        )

        # ------------------------------------------------------------------
        # Email — IMAP (receiving)
        # ------------------------------------------------------------------
        self.imap_host: str = os.getenv("IMAP_HOST", "imap.gmail.com")
        self.imap_port: int = int(os.getenv("IMAP_PORT", "993"))

        # ------------------------------------------------------------------
        # Email — SMTP (sending)
        # ------------------------------------------------------------------
        self.smtp_host: str = os.getenv("SMTP_HOST", "smtp.gmail.com")
        self.smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_use_ssl: bool = os.getenv("SMTP_USE_SSL", "false").lower() == "true"

        # ------------------------------------------------------------------
        # Email — Account identity
        # ------------------------------------------------------------------
        self.email_address: str = os.getenv("EMAIL_ADDRESS", "")
        self.email_display_name: str = os.getenv("EMAIL_DISPLAY_NAME", "AI Agent")

        # ------------------------------------------------------------------
        # Secrets — resolved through the configured provider
        # ------------------------------------------------------------------
        backend = os.getenv("SECRET_BACKEND", "")
        self.secret_backend: str = backend or "env"
        try:
            provider = secret_provider or get_provider(backend)
        except ValueError as e:
            raise ConfigError(str(e)) from e
        self._provider = provider

        self.email_password: SecretString = SecretString("")
        self.gpg_passphrase: SecretString = SecretString("")

        # GPG_KEY_ID is not a *secret* (fingerprints are public), but it is a
        # required identity value. It is read from env, not the provider.
        self.gpg_key_id = os.getenv("GPG_KEY_ID", "").strip()

        self.gpg_home: str = os.getenv("GPG_HOME", "")
        # GPG_HOME is intentionally NOT passed through _resolve_path().
        # It must be blank (use system default) or an explicit absolute path.
        # The gpg-agent socket path has a ~104-char Windows limit.

        # The two provider-resolved secrets.
        self.email_password = self._resolve_secret("EMAIL_PASSWORD")
        self.gpg_passphrase = self._resolve_secret("GPG_PASSPHRASE")

        if require_secrets:
            self._ensure_required()

    # ------------------------------------------------------------------
    # Secret resolution
    # ------------------------------------------------------------------

    def _resolve_secret(self, name: str) -> SecretString:
        """Resolve one secret through the provider. Never falls back."""
        value = self._provider.get(name)
        if value is None:
            return SecretString("")
        return value

    def secret_status(self) -> list[str]:
        """Return human-readable resolution status for each required secret."""
        status = []
        for name in REQUIRED_SECRETS:
            if name == "EMAIL_ADDRESS":
                ok = bool(self.email_address)
            elif name == "GPG_KEY_ID":
                ok = bool(self.gpg_key_id)
            elif name == "EMAIL_PASSWORD":
                ok = bool(self.email_password)
            else:  # GPG_PASSPHRASE
                ok = bool(self.gpg_passphrase)
            status.append(f"{name}: {'set' if ok else 'MISSING'}")
        return status

    def _ensure_required(self) -> None:
        """Fail fast: abort construction when any required secret is missing."""
        missing = [s for s in self.secret_status() if s.endswith("MISSING")]
        if missing:
            raise ConfigError(
                "[config] refusing to start — missing required secrets via "
                f"SECRET_BACKEND={self.secret_backend!r}:\n"
                + "\n".join("  ! " + m for m in missing)
                + "\n  Set them in .env (or the selected credential store) "
                  "and restart. There is no fallback default."
            )

    # ------------------------------------------------------------------
    # Never expose sensitive fields in repr or str.
    # Without this, logging a Config object dumps credentials in plaintext.
    # ------------------------------------------------------------------
    def __repr__(self) -> str:
        return (
            f"Config("
            f"email_address={self.email_address!r}, "
            f"email_password=***, "
            f"imap_host={self.imap_host!r}, "
            f"smtp_host={self.smtp_host!r}, "
            f"gpg_key_id={self.gpg_key_id!r}, "
            f"gpg_passphrase=***, "
            f"secret_backend={self.secret_backend!r}, "
            f"contacts_path={self.contacts_path!r}, "
            f"archive_path={self.archive_path!r}, "
            f"logs_dir={self.logs_dir!r}, "
            f"pubkey_export_dir={self.pubkey_export_dir!r}, "
            f")"
        )

    def __str__(self) -> str:
        return self.__repr__()


__all__ = ["Config", "ConfigError", "REQUIRED_SECRETS"]
