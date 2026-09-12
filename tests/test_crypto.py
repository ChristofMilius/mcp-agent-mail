"""tests/test_crypto.py — fingerprint/key-block validation and sanitizers."""
from __future__ import annotations

import pytest

from mcp_agent_mail.crypto import (
    _PUBKEY_MARKER,
    _sanitize_gpg_error,
    _validate_fingerprint,
    _validate_key_block_structure,
)

FPR = "AABBCCDDEEFF00112233445566778899AABBCCDD"


class TestValidateFingerprint:
    def test_accepts_40_hex_chars(self):
        assert _validate_fingerprint(FPR) == FPR.upper()

    def test_normalizes_lowercase_and_spaces(self):
        assert _validate_fingerprint(" aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ".upper()) == (
            FPR.upper()
        )

    def test_rejects_short_keyid(self):
        with pytest.raises(ValueError, match="40 hex"):
            _validate_fingerprint(FPR[-16:])

    def test_rejects_non_hex(self):
        with pytest.raises(ValueError, match="40 hex"):
            _validate_fingerprint("G" + FPR[1:])

    def test_rejects_garbage(self):
        with pytest.raises(ValueError, match="40 hex"):
            _validate_fingerprint("not a fingerprint at all")


PUBLIC_KEY_BLOCK = f"""{_PUBKEY_MARKER}
{("A" * 64 + "\n") * 30}
-----END PGP PUBLIC KEY BLOCK-----
"""


class TestValidateKeyBlockStructure:
    def test_accepts_valid_public_block(self):
        _validate_key_block_structure(PUBLIC_KEY_BLOCK)

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="empty or whitespace"):
            _validate_key_block_structure("   \n  ")

    def test_rejects_private_key_marker(self):
        private = PUBLIC_KEY_BLOCK.replace(
            _PUBKEY_MARKER, "-----BEGIN PGP PRIVATE KEY BLOCK-----"
        )
        with pytest.raises(ValueError, match="Private key material rejected"):
            _validate_key_block_structure(private)

    def test_rejects_secret_key_marker(self):
        weird = PUBLIC_KEY_BLOCK.replace(
            _PUBKEY_MARKER, "-----BEGIN PGP SECRET KEY BLOCK-----"
        )
        with pytest.raises(ValueError, match="Private key material rejected"):
            _validate_key_block_structure(weird)

    def test_rejects_missing_begin(self):
        with pytest.raises(ValueError, match="does not contain"):
            _validate_key_block_structure("-----END PGP PUBLIC KEY BLOCK-----")

    def test_rejects_missing_end(self):
        head = _PUBKEY_MARKER + "\nAAAAAAAA\n"
        with pytest.raises(ValueError, match="truncated"):
            _validate_key_block_structure(head)

    def test_rejects_implausibly_short(self):
        short = _PUBKEY_MARKER + "\nA\n" + "-----END PGP PUBLIC KEY BLOCK-----\n"
        with pytest.raises(ValueError, match="implausibly short"):
            _validate_key_block_structure(short)


class _Result:
    """Minimal stand-in for a gnupg result object."""


class TestSanitizeGpgError:
    def test_safe_status_passed_through(self):
        r = _Result()
        r.status = "no secret key"
        r.stderr = ""
        out = _sanitize_gpg_error("decrypt", r)
        assert "decrypt failed: no secret key" in out

    def test_unknown_status_becomes_operation_failed(self):
        r = _Result()
        r.status = "erasable_entire_secret={'whatever': 'leaky'}"
        r.stderr = ""
        out = _sanitize_gpg_error("encrypt", r)
        assert "operation failed" in out
        assert "leaky" not in out

    def test_stderr_never_in_return_value(self):
        r = _Result()
        r.status = "decryption failed"
        r.stderr = "/home/user/.gnupg/foo.gpg: internal key: leaked-value"
        out = _sanitize_gpg_error("decrypt", r)
        assert "leaked-value" not in out

    def test_empty_status_becomes_operation_failed(self):
        r = _Result()
        r.status = ""
        r.stderr = ""
        out = _sanitize_gpg_error("sign", r)
        assert "operation failed" in out
