"""tests/test_contacts.py — contact book, key provenance, fingerprint rules."""
from __future__ import annotations

import pytest

from mcp_agent_mail.contacts import (
    SOURCE_CLEARED,
    SOURCE_KEYRING_MATCH,
    SOURCE_MANUAL,
    ContactBook,
    _uid_email,
)

FPR40 = "AABBCCDDEEFF00112233445566778899AABBCCDD"


def make_book(tmp_project):
    root, env = tmp_project
    import types

    cfg = types.SimpleNamespace(contacts_path=env["CONTACTS_PATH"])
    return ContactBook(cfg)


class TestUidEmail:
    def test_extracts_email_from_named_uid(self):
        assert _uid_email("Alice Example <alice@corp.example>") == "alice@corp.example"

    def test_lowercases(self):
        assert _uid_email("Bob <Bob@Example.COM>") == "bob@example.com"

    def test_returns_full_uid_without_angle_brackets(self):
        assert _uid_email("justanaddress") == "justanaddress"


class TestContactBook:
    def test_add_and_get(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice Example", "alice@example.com")
        c = book.get("Alice Example")
        assert c["email"] == "alice@example.com"
        assert c["has_gpg_key"] is False

    def test_add_includes_explicit_key_note(self, tmp_project):
        book = make_book(tmp_project)
        r = book.add("Alice Example", "alice@example.com")
        assert "contact_link_key()" in r["note"]
        assert r["has_gpg_key"] is False

    def test_get_by_prefix(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice Example", "alice@example.com")
        assert book.get("Alice")["email"] == "alice@example.com"

    def test_get_by_email(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice Example", "alice@example.com")
        assert book.get("alice@example.com")["name"] == "Alice Example"

    def test_email_change_clears_stale_fingerprint(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice Example", "alice@old.example")
        book.set_fingerprint("Alice Example", FPR40)
        assert book.get("Alice Example")["has_gpg_key"] is True
        book.add("Alice Example", "alice@new.example")
        c = book.get("Alice Example")
        assert c["has_gpg_key"] is False
        assert c["key_source"] == SOURCE_CLEARED

    def test_remove(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice Example", "alice@example.com")
        book.remove("Alice Example")
        assert book.get("Alice Example") is None

    def test_remove_unknown_raises(self, tmp_project):
        book = make_book(tmp_project)
        with pytest.raises(ValueError, match="not found"):
            book.remove("Ghost Person")

    def test_persistence(self, tmp_project):
        root, env = tmp_project
        book = make_book(tmp_project)
        book.add("Alice Example", "alice@example.com")
        book2 = ContactBook(type("Cfg", (), {"contacts_path": env["CONTACTS_PATH"]})())
        assert book2.get("Alice Example")["email"] == "alice@example.com"


class TestSetFingerprint:
    def test_accepts_full_fingerprint(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice Example", "alice@example.com")
        r = book.set_fingerprint("Alice Example", FPR40)
        assert r["fingerprint"] == FPR40
        assert r["key_source"] == SOURCE_MANUAL
        assert r["key_linked_at"]

    def test_normalizes_spaces_and_case(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice Example", "alice@example.com")
        spaced = "aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd".upper()
        r = book.set_fingerprint("Alice Example", spaced)
        assert r["fingerprint"] == FPR40

    def test_rejects_short_keyid(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice Example", "alice@example.com")
        with pytest.raises(ValueError, match="40 hex"):
            book.set_fingerprint("Alice Example", FPR40[-16:])

    def test_rejects_garbage(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice Example", "alice@example.com")
        with pytest.raises(ValueError, match="40 hex"):
            book.set_fingerprint("Alice Example", "A" * 5)


class _FakeCrypto:
    def __init__(self, keys):
        self._keys = keys

    def list_keys(self, secret=False):
        return self._keys


class TestFindAndLinkKey:
    def test_links_exact_uid_match(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice Example", "alice@example.com")
        crypto = _FakeCrypto([
            {"fingerprint": FPR40, "uids": ["Alice Example <alice@example.com>"], "keyid": "AABBCCDD"},
        ])
        r = book.find_and_link_key("Alice Example", crypto)
        assert r["status"] == "linked"
        assert r["fingerprint"] == FPR40
        assert r["key_source"] == SOURCE_KEYRING_MATCH
        assert book.get("Alice Example")["has_gpg_key"] is True

    def test_no_match_raises(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice Example", "alice@example.com")
        crypto = _FakeCrypto([])
        with pytest.raises(ValueError, match="No key in keyring"):
            book.find_and_link_key("Alice Example", crypto)

    def test_ambiguous_match_raises(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice Example", "alice@example.com")
        crypto = _FakeCrypto(
            [
                {"fingerprint": "A" * 40, "uids": ["Alice <alice@example.com>"], "keyid": "AAA"},
                {"fingerprint": "B" * 40, "uids": ["Alice <alice@example.com>"], "keyid": "BBB"},
            ]
        )
        with pytest.raises(ValueError, match="[Aa]mbiguous"):
            book.find_and_link_key("Alice Example", crypto)
