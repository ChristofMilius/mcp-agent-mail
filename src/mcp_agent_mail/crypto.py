"""
crypto.py — GPG encryption/decryption/signing via python-gnupg
==============================================================
Wraps the python-gnupg library, itself a wrapper around the system
`gpg` / `gpg2` binary.

Security fixes carried over from the source project, intact:
  - Passphrase is SecretString throughout — never stored as plain str,
    never appears in repr/logging/traceback.
  - gnupg error messages sanitized before raising — stderr from gpg may
    contain key IDs, paths, and internal state. Logged internally, a
    sanitized exception is raised to callers.
  - export_secret_key() REMOVED — unnecessary attack surface. Private key
    export has no legitimate path in this agent's operation.
  - import_key() validates structural markers before passing to gnupg.
  - Key ID / fingerprint arguments validated before use.

GPG_HOME notes:
  - Leave blank to use the system default (~/.gnupg).
  - Must be absolute if set (Windows socket path limit).
  - --no-autostart, --batch, --pinentry-mode loopback for non-interactive use.

GPG agent startup:
  - _ensure_gpg_agent() is called from __init__ every time GPGCrypto is
    instantiated. It kills any stale agent, relaunches gpg-agent, then
    launches keyboxd. Without keyboxd, GnuPG >= 2.3 cannot locate keys even
    if the agent is running — the root cause of post-boot decryption failure.
  - Failures are logged but never raised: a missing gpgconf binary must not
    prevent the server from starting.
"""

from __future__ import annotations

import logging
import re
import stat
import subprocess
from pathlib import Path

import gnupg

from mcp_agent_mail.secrets import SecretString

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Valid fingerprint: 40 hex chars (FPRv4) — 16-char key IDs are ambiguous
# and vulnerable to collision. We accept only full fingerprints.
_FINGERPRINT_RE = re.compile(r"^[0-9A-Fa-f]{40}$")

# Structural markers that must appear in a key block before we send it to gnupg.
_PUBKEY_MARKER = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
_PRIVKEY_MARKER_PATTERNS = [
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "-----BEGIN PGP SECRET KEY BLOCK-----",
]


# ---------------------------------------------------------------------------
# GPG agent startup
# ---------------------------------------------------------------------------

def _ensure_gpg_agent() -> None:
    """
    Kill any stale gpg-agent and relaunch the full daemon stack.

    Why three commands:
      gpgconf --kill gpg-agent   — flush stale socket/lock files
      gpgconf --launch gpg-agent — start the passphrase-caching daemon
      gpgconf --launch keyboxd   — start the key-box database daemon

    GnuPG >= 2.3 separates the key-box into its own daemon (keyboxd).
    If keyboxd is not running, key lookups silently return "no secret key"
    even though the agent itself is alive. This is the observed post-boot
    decryption failure mode.

    Security: no key material or configuration is passed to these commands.
    Stderr is captured and discarded — it may contain socket paths and
    internal state. Only a single sanitized status line is logged.

    Failures are non-fatal: if gpgconf is absent we log a warning and
    continue; gpg itself surfaces the real error at the point of use.
    """
    sequence = [
        ["gpgconf", "--kill", "gpg-agent"],
        ["gpgconf", "--launch", "gpg-agent"],
        ["gpgconf", "--launch", "keyboxd"],
    ]
    for cmd in sequence:
        try:
            result = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                timeout=15,
            )
            if result.returncode != 0:
                logger.warning(
                    "[crypto] gpgconf %s %s exited with code %d",
                    cmd[1], cmd[2], result.returncode,
                )
        except FileNotFoundError:
            logger.warning(
                "[crypto] gpgconf not found — skipping GPG agent init. "
                "Install Gpg4win (Windows) or gnupg2 (Linux/macOS)."
            )
            return
        except subprocess.TimeoutExpired:
            logger.warning("[crypto] gpgconf %s %s timed out", cmd[1], cmd[2])
        except Exception:
            logger.warning("[crypto] gpgconf %s %s failed unexpectedly", cmd[1], cmd[2])

    logger.info("[crypto] GPG agent stack initialised (agent + keyboxd).")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_gpg(gnupghome: str | None) -> gnupg.GPG:
    """
    Construct a GPG instance for non-interactive background use.
    --no-autostart : don't hang waiting for gpg-agent
    --batch        : never prompt
    --pinentry-mode loopback : feed passphrase via stdin
    """
    options = [
        "--no-autostart",
        "--batch",
        "--pinentry-mode", "loopback",
    ]
    kwargs: dict = {"options": options}

    if gnupghome:
        home = Path(gnupghome)
        if not home.is_absolute():
            raise ValueError(
                f"[crypto] GPG_HOME must be an absolute path, got: '{gnupghome}'\n"
                "  Relative paths cause gpg-agent socket path to exceed Windows limits.\n"
                "  Use an absolute path or leave GPG_HOME blank."
            )
        home.mkdir(parents=True, exist_ok=True)
        home.chmod(0o700)  # GPG refuses a group-/world-readable home
        kwargs["gnupghome"] = str(home)

    gpg = gnupg.GPG(**kwargs)
    gpg.encoding = "utf-8"
    return gpg


def _validate_fingerprint(fp: str) -> str:
    """
    Validate and normalise a GPG fingerprint.
    Rejects short key IDs (ambiguous, vulnerable to Evil32 collision attack).
    Returns the upper-cased fingerprint.
    """
    fp = fp.strip().upper()
    fp = fp.replace(" ", "")  # accept gpg-style space-separated output
    if not _FINGERPRINT_RE.match(fp):
        raise ValueError(
            "[crypto] Invalid fingerprint — expected 40 hex chars (FPRv4), "
            f"got {len(fp)} chars. Short key IDs are rejected: they are ambiguous and "
            "vulnerable to key-collision attacks."
        )
    return fp


# Known-safe gnupg status strings. Anything else defaults to "operation failed".
_SAFE_STATUS_VALUES = frozenset({
    "no secret key",
    "bad passphrase",
    "need passphrase",
    "key expired",
    "key revoked",
    "key not found",
    "encryption ok",
    "decryption ok",
    "signature valid",
    "signature bad",
    "signature error",
    "unknown signature",
    "operation failed",
    "no data",
    "invalid armor",
    "decryption failed",
    "encryption failed",
})


def _sanitize_gpg_error(operation: str, result) -> str:
    """
    Return a sanitized error string suitable for logging and raising.

    Security:
      - result.status is whitelisted — only known-safe strings pass. Anything
        not on the whitelist becomes "operation failed", preventing gnupg
        internal state strings (which may contain key IDs, paths) from
        reaching callers.
      - result.stderr is NEVER included in the return value. It is logged
        server-side at DEBUG level only.
      - The operation name is included for diagnosability.
    """
    stderr = getattr(result, "stderr", None) or ""
    if stderr.strip():
        logger.debug("[crypto] %s stderr: %s", operation, stderr)

    status = (getattr(result, "status", None) or "").strip().lower()
    safe_status = status if status in _SAFE_STATUS_VALUES else "operation failed"

    return f"[crypto] {operation} failed: {safe_status}"


def _validate_key_block_structure(key_material: str) -> None:
    """
    Structural pre-validation of PGP key material before passing to gnupg.

    Runs entirely in Python — no subprocess, no gnupg binary. Rejects
    obviously invalid or malicious input early.

    Checks (in order):
      1. Empty / whitespace-only input
      2. Private or secret key markers — never acceptable
      3. Not a public key block at all (missing BEGIN marker)
      4. Missing END marker (truncated block)
      5. Implausibly short (< 200 bytes)
    """
    if not key_material or not key_material.strip():
        raise ValueError("[crypto] Key material is empty or whitespace-only.")

    for marker in _PRIVKEY_MARKER_PATTERNS:
        if marker in key_material:
            raise ValueError(
                "[crypto] Private key material rejected. "
                "Only public keys may be imported or validated."
            )

    if _PUBKEY_MARKER not in key_material:
        raise ValueError(
            "[crypto] Key material does not contain a PGP public key block header. "
            "Expected: '-----BEGIN PGP PUBLIC KEY BLOCK-----'"
        )

    if "-----END PGP PUBLIC KEY BLOCK-----" not in key_material:
        raise ValueError(
            "[crypto] Key block is missing its footer — the block may be truncated. "
            "Expected: '-----END PGP PUBLIC KEY BLOCK-----'"
        )

    if len(key_material.strip()) < 200:
        raise ValueError(
            f"[crypto] Key block is implausibly short ({len(key_material.strip())} bytes). "
            "Real public keys are at minimum several hundred bytes."
        )


# ---------------------------------------------------------------------------
# GPGCrypto
# ---------------------------------------------------------------------------

class GPGCrypto:
    """
    Thin, security-hardened wrapper around python-gnupg.

    Initialisation starts the GPG agent stack so that decryption is
    available immediately — including after a cold system boot before
    the user has run any other GPG operation.
    """

    def __init__(self, cfg):
        self._key_id: str = cfg.gpg_key_id
        self._passphrase: SecretString = cfg.gpg_passphrase
        self._gnupghome: str = cfg.gpg_home

        _ensure_gpg_agent()

        self._gpg = _build_gpg(self._gnupghome if self._gnupghome else None)

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def encrypt(self, plaintext: str, recipient_fingerprint: str) -> str:
        """
        Encrypt plaintext for recipient identified by full 40-char fingerprint.
        Always signs with the agent key. Returns ASCII-armored ciphertext.
        """
        fp = _validate_fingerprint(recipient_fingerprint)
        result = self._gpg.encrypt(
            plaintext,
            recipients=[fp],
            sign=self._key_id,
            passphrase=self._passphrase.expose_secret(),
            always_trust=True,
        )
        if not result.ok:
            _sanitize_gpg_error("encrypt", result)
            raise RuntimeError("Encryption failed. Check server logs.")
        return str(result)

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt ASCII-armored PGP message. Raises RuntimeError on failure."""
        result = self._gpg.decrypt(
            ciphertext,
            passphrase=self._passphrase.expose_secret(),
            always_trust=True,
        )
        if not result.ok:
            _sanitize_gpg_error("decrypt", result)
            raise RuntimeError("Decryption failed. Check server logs.")
        return str(result)

    def sign(self, plaintext: str, clearsign: bool = True) -> str:
        """
        Sign plaintext with the agent key (clear-signed PGP message).

        The clearsign parameter is accepted for API compatibility and has no
        effect — python-gnupg always produces a clear-signed message.
        """
        result = self._gpg.sign(
            plaintext,
            keyid=self._key_id,
            passphrase=self._passphrase.expose_secret(),
        )
        if not result.fingerprint:
            _sanitize_gpg_error("sign", result)
            raise RuntimeError("Signing failed. Check server logs.")
        return str(result)

    def verify(self, signed_message: str) -> dict:
        """
        Verify a PGP-signed message.
        Returns a dict with: valid (bool), fingerprint, username, timestamp.
        """
        result = self._gpg.verify(signed_message)
        return {
            "valid": bool(result),
            "fingerprint": result.fingerprint or "",
            "username": result.username or "",
            "timestamp": result.timestamp or "",
            "status": result.status or "",
        }

    def import_key(self, key_material: str) -> dict:
        """
        Import a public key into the local keyring.
        Validates structural PGP markers before passing to gnupg.

        Private key markers are rejected unconditionally.
        """
        _validate_key_block_structure(key_material)

        result = self._gpg.import_keys(key_material)
        imported = result.imported if hasattr(result, "imported") else 0
        fingerprints = list(result.fingerprints) if hasattr(result, "fingerprints") else []
        return {
            "imported": imported,
            "fingerprints": fingerprints,
        }

    def export_public_key(self, key_id: str) -> str:
        """
        Export a public key from the local keyring as ASCII-armored text.
        Safe to share. Does not expose private key material.
        """
        armor = self._gpg.export_keys(key_id)
        if not armor:
            raise RuntimeError(
                "Public key export failed — key may not be in the keyring. "
                "Check server logs."
            )
        return armor

    def export_public_key_to_file(self, key_id: str, export_dir: str) -> Path:
        """
        Export the agent's public key to a .asc file on disk.

        This is the ONLY correct path for the gpg_export_own_pubkey tool.
        Key material is written to disk and never returned to the caller —
        callers receive only the Path object, preventing key material from
        entering the model's context window.

        File permissions: 0o644 — owner rw, group r, world r.
        A public key is meant to be shared; world-readable is correct.
        """
        armor = self._gpg.export_keys(key_id)
        if not armor:
            raise RuntimeError(
                "Public key export failed — key may not be in the keyring. "
                "Check server logs."
            )

        out_dir = Path(export_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        suffix = key_id[-8:].upper() if len(key_id) >= 8 else key_id.upper()
        filename = f"agent_pubkey_{suffix}.asc"
        out_path = out_dir / filename

        out_path.write_text(armor, encoding="utf-8")

        try:
            os_chmod(out_path)
        except (AttributeError, NotImplementedError, OSError):
            pass  # Windows: skip chmod, rely on NTFS ACLs

        return out_path  # the Path — never the key material

    # export_secret_key() is intentionally absent.
    # No legitimate operational path requires exporting the private key.
    # Re-adding it would be an attack surface expansion. Do not add it back.

    def list_keys(self, secret: bool = False) -> list:
        """List keys in the keyring. secret=True lists private keys."""
        keys = self._gpg.list_keys(secret=secret)
        safe = []
        for k in keys:
            safe.append({
                "fingerprint": k.get("fingerprint", ""),
                "uids": k.get("uids", []),
                "expires": k.get("expires", ""),
                "length": k.get("length", ""),
                "algo": k.get("algo", ""),
            })
        return safe


def os_chmod(path: Path) -> None:
    """Apply 0o644 permissions (owner rw, group r, world r) to a public key file."""
    import os as _os

    _os.chmod(
        path,
        stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH,  # 0o644
    )


__all__ = [
    "GPGCrypto",
    "_ensure_gpg_agent",
    "_sanitize_gpg_error",
    "_validate_fingerprint",
    "_validate_key_block_structure",
]
