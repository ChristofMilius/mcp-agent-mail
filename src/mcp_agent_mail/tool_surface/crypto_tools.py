"""
crypto_tools — GPG key and crypto operations
============================================
list_keys / encrypt / verify / export_own_pubkey / own_status.

gpg_export_own_pubkey writes to disk and returns metadata only — key
material never enters the model context. There is no decrypt tool and no
secret-key export tool; neither has a legitimate path in this design.
"""

from __future__ import annotations

import json

from mcp_agent_mail.crypto import GPGCrypto
from mcp_agent_mail.errors import tool_error


def register(server, ctx) -> None:
    crypto: GPGCrypto = ctx.crypto
    cfg = ctx.cfg

    @server.tool()
    def gpg_list_keys(secret: bool = False) -> str:
        """List keys in the agent's keyring (fingerprints, uids, algorithm).

        Args:
            secret: If true, list private keys instead of public keys.
        """
        try:
            keys = crypto.list_keys(secret=secret)
            return json.dumps(
                {"count": len(keys), "secret": secret, "keys": keys},
                indent=2, ensure_ascii=False,
            )
        except Exception as e:
            return tool_error("gpg_list_keys", e)

    @server.tool()
    def gpg_encrypt(plaintext: str, recipient_fingerprint: str) -> str:
        """Encrypt text to a recipient's PUBLIC key (full 40-char fingerprint).

        Returns ASCII-armored ciphertext. Ciphertext is not a secret — it is
        safe to return. For email, prefer email_send(encrypt=True), which
        resolves the key from the contact book automatically.

        Args:
            plaintext: Text to encrypt.
            recipient_fingerprint: Full 40-character hex fingerprint of the recipient.
        """
        try:
            ciphertext = crypto.encrypt(plaintext, recipient_fingerprint)
            return json.dumps(
                {"status": "encrypted", "ciphertext": ciphertext},
                indent=2, ensure_ascii=False,
            )
        except Exception as e:
            return tool_error("gpg_encrypt", e)

    @server.tool()
    def gpg_verify(signed_message: str) -> str:
        """Verify a clear-signed PGP message. Returns validity and signer identity.

        Args:
            signed_message: The full ASCII-armored signed message.
        """
        try:
            result = crypto.verify(signed_message)
            return json.dumps(result, indent=2, ensure_ascii=False)
        except Exception as e:
            return tool_error("gpg_verify", e)

    @server.tool()
    def gpg_export_own_pubkey() -> str:
        """Export the agent's PUBLIC key to a file in PUBKEY_EXPORT_DIR.

        The key is written to disk; only the file path, fingerprint, and byte
        size are returned. Key material is never returned to the model.
        """
        try:
            path = crypto.export_public_key_to_file(
                cfg.gpg_key_id, cfg.pubkey_export_dir
            )
            return json.dumps(
                {
                    "status": "exported",
                    "fingerprint": cfg.gpg_key_id,
                    "file": str(path),
                    "note": "Share this .asc file with correspondents out of band.",
                },
                indent=2, ensure_ascii=False,
            )
        except Exception as e:
            return tool_error("gpg_export_own_pubkey", e)

    @server.tool()
    def gpg_own_status() -> str:
        """Report the agent's own GPG identity and configuration (no secrets)."""
        try:
            status = {
                "email_address": cfg.email_address,
                "gpg_key_id": cfg.gpg_key_id,
                "gpg_home": cfg.gpg_home or "(system default)",
                "secret_backend": cfg.secret_backend,
                "passphrase_configured": bool(cfg.gpg_passphrase),
                "secret_status": cfg.secret_status(),
            }
            return json.dumps(status, indent=2, ensure_ascii=False)
        except Exception as e:
            return tool_error("gpg_own_status", e)


__all__ = ["register"]
