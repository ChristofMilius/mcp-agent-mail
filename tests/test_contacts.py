"""tests/test_contacts.py — contact book, key provenance, fingerprint rules."""
from __future__ import annotations

import json
import types

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
        book.add("Alice", "Example", "alice@example.com")
        c = book.get("Alice Example")
        assert c["name"] == "Alice Example"
        assert c["given_name"] == "Alice"
        assert c["surname"] == "Example"
        assert c["email"] == "alice@example.com"
        assert c["has_gpg_key"] is False

    def test_add_derives_record_key(self, tmp_project):
        book = make_book(tmp_project)
        r = book.add("Alice", "Example", "alice@example.com")
        assert r["name"] == "Alice Example"
        assert book.get("alice@example.com")["name"] == "Alice Example"

    def test_add_requires_both_names(self, tmp_project):
        book = make_book(tmp_project)
        with pytest.raises(ValueError, match="given_name and surname"):
            book.add("Alice", "", "alice@example.com")

    def test_add_includes_explicit_key_note(self, tmp_project):
        book = make_book(tmp_project)
        r = book.add("Alice", "Example", "alice@example.com")
        assert "contact_link_key()" in r["note"]
        assert r["has_gpg_key"] is False

    def test_get_by_prefix(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice", "Example", "alice@example.com")
        assert book.get("Alice")["email"] == "alice@example.com"

    def test_get_by_email(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice", "Example", "alice@example.com")
        assert book.get("alice@example.com")["name"] == "Alice Example"

    def test_email_change_clears_stale_fingerprint(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice", "Example", "alice@old.example")
        book.set_fingerprint("Alice Example", FPR40)
        assert book.get("Alice Example")["has_gpg_key"] is True
        book.add("Alice", "Example", "alice@new.example")
        c = book.get("Alice Example")
        assert c["has_gpg_key"] is False
        assert c["key_source"] == SOURCE_CLEARED
        assert c["key_cleared_at"]

    def test_remove(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice", "Example", "alice@example.com")
        book.remove("Alice Example")
        assert book.get("Alice Example") is None

    def test_remove_unknown_raises(self, tmp_project):
        book = make_book(tmp_project)
        with pytest.raises(ValueError, match="not found"):
            book.remove("Ghost Person")

    def test_persistence(self, tmp_project):
        root, env = tmp_project
        book = make_book(tmp_project)
        book.add("Alice", "Example", "alice@example.com")
        book2 = ContactBook(type("Cfg", (), {"contacts_path": env["CONTACTS_PATH"]})())
        assert book2.get("Alice Example")["email"] == "alice@example.com"


class TestMigration:
    def _write_legacy(self, path, records):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(records), encoding="utf-8")

    def test_upgrades_legacy_record(self, tmp_path):
        contacts = tmp_path / "data" / "contacts.json"
        self._write_legacy(contacts, {
            "SelfMailbox": {
                "added": "2026-09-12T19:57:26",
                "email": "agent@example.com",
                "notes": "",
                "updated": "2026-09-12T19:57:26",
                "gpg_fingerprint": FPR40,
                "key_source": "keyring_uid_match",
                "key_linked_at": "2026-09-12T19:57:26",
            }
        })
        cfg = types.SimpleNamespace(contacts_path=str(contacts))
        book = ContactBook(cfg)
        c = book.get("SelfMailbox")
        assert c["given_name"] == "SelfMailbox"
        assert c["surname"] == ""
        assert c["gpg_key_fingerprint"] == FPR40
        assert c["key_cleared_at"] == ""
        raw = json.loads(contacts.read_text(encoding="utf-8"))
        assert "gpg_key_fingerprint" in raw["SelfMailbox"]
        assert "gpg_fingerprint" not in raw["SelfMailbox"]

    def test_upgrades_keyless_legacy_record(self, tmp_path):
        contacts = tmp_path / "data" / "contacts.json"
        self._write_legacy(contacts, {
            "Jane Miller": {
                "added": "2026-09-13T17:53:23",
                "email": "jane@example.de",
                "notes": "",
                "updated": "2026-09-13T17:53:23",
            }
        })
        cfg = types.SimpleNamespace(contacts_path=str(contacts))
        book = ContactBook(cfg)
        c = book.get("Jane Miller")
        assert c["given_name"] == "Jane Miller"
        assert c["surname"] == ""
        assert c["gpg_key_fingerprint"] == ""
        assert c["has_gpg_key"] is False

    def test_current_schema_untouched(self, tmp_project):
        root, env = tmp_project
        book = make_book(tmp_project)
        book.add("Alice", "Example", "alice@example.com")
        before = (root / "data" / "contacts.json").read_bytes()
        ContactBook(type("Cfg", (), {"contacts_path": env["CONTACTS_PATH"]})())
        after = (root / "data" / "contacts.json").read_bytes()
        assert before == after


class TestSetFingerprint:
    def test_accepts_full_fingerprint(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice", "Example", "alice@example.com")
        r = book.set_fingerprint("Alice Example", FPR40)
        assert r["fingerprint"] == FPR40
        assert r["key_source"] == SOURCE_MANUAL
        assert r["key_linked_at"]
        assert book.get("Alice Example")["gpg_key_fingerprint"] == FPR40

    def test_normalizes_spaces_and_case(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice", "Example", "alice@example.com")
        spaced = "aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd".upper()
        r = book.set_fingerprint("Alice Example", spaced)
        assert r["fingerprint"] == FPR40

    def test_rejects_short_keyid(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice", "Example", "alice@example.com")
        with pytest.raises(ValueError, match="40 hex"):
            book.set_fingerprint("Alice Example", FPR40[-16:])

    def test_rejects_garbage(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice", "Example", "alice@example.com")
        with pytest.raises(ValueError, match="40 hex"):
            book.set_fingerprint("Alice Example", "A" * 5)

    def test_relink_resets_cleared_at(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice", "Example", "alice@example.com")
        book.set_fingerprint("Alice Example", FPR40)
        book.clear_key("Alice Example", FPR40)
        assert book.get("Alice Example")["key_cleared_at"]
        book.set_fingerprint("Alice Example", FPR40)
        assert book.get("Alice Example")["key_cleared_at"] == ""


class _FakeCrypto:
    def __init__(self, keys):
        self._keys = keys

    def list_keys(self, secret=False):
        return self._keys


class TestFindAndLinkKey:
    def test_links_exact_uid_match(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice", "Example", "alice@example.com")
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
        book.add("Alice", "Example", "alice@example.com")
        crypto = _FakeCrypto([])
        with pytest.raises(ValueError, match="No key in keyring"):
            book.find_and_link_key("Alice Example", crypto)

    def test_ambiguous_match_raises(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice", "Example", "alice@example.com")
        crypto = _FakeCrypto(
            [
                {"fingerprint": "A" * 40, "uids": ["Alice <alice@example.com>"], "keyid": "AAA"},
                {"fingerprint": "B" * 40, "uids": ["Alice <alice@example.com>"], "keyid": "BBB"},
            ]
        )
        with pytest.raises(ValueError, match="[Aa]mbiguous"):
            book.find_and_link_key("Alice Example", crypto)


class TestClearKey:
    def test_clears_and_records_provenance(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice", "Example", "alice@example.com")
        book.set_fingerprint("Alice Example", FPR40)
        linked_at = book.get("Alice Example")["key_linked_at"]
        r = book.clear_key("Alice Example", FPR40)
        assert r["status"] == "cleared"
        assert r["cleared_fingerprint"] == FPR40
        assert r["key_source"] == SOURCE_CLEARED
        assert r["key_cleared_at"]
        c = book.get("Alice Example")
        assert c["has_gpg_key"] is False
        assert c["key_source"] == SOURCE_CLEARED
        # key_linked_at is history and must survive the clear.
        assert c["key_linked_at"] == linked_at

    def test_normalizes_spaces_and_case(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice", "Example", "alice@example.com")
        book.set_fingerprint("Alice Example", FPR40)
        spaced = "aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd".upper()
        r = book.clear_key("Alice Example", spaced)
        assert r["status"] == "cleared"
        assert r["cleared_fingerprint"] == FPR40

    def test_mismatch_is_refused(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice", "Example", "alice@example.com")
        book.set_fingerprint("Alice Example", FPR40)
        other = "00" * 20
        with pytest.raises(ValueError, match="does not match"):
            book.clear_key("Alice Example", other)

    def test_no_key_is_noop_not_error(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice", "Example", "alice@example.com")
        r = book.clear_key("Alice Example", FPR40)
        assert r["status"] == "no_key"
        assert r["has_gpg_key"] is False

    def test_rejects_garbage_fingerprint(self, tmp_project):
        book = make_book(tmp_project)
        book.add("Alice", "Example", "alice@example.com")
        with pytest.raises(ValueError, match="40 hex"):
            book.clear_key("Alice Example", "AABB")

    def test_refuses_clearing_own_key(self, tmp_project):
        root, env = tmp_project
        cfg = types.SimpleNamespace(
            contacts_path=env["CONTACTS_PATH"], gpg_key_id=FPR40
        )
        book = ContactBook(cfg)
        book.add("Hermes", "the Agent", "agent@example.com")
        book.set_fingerprint("Hermes the Agent", FPR40)
        with pytest.raises(ValueError, match="own configured key"):
            book.clear_key("Hermes the Agent", FPR40)
        # Guard must not block clearing contacts with OTHER keys.
        book.add("Alice", "Example", "alice@example.com")
        other = "00" * 20
        book.set_fingerprint("Alice Example", other)
        assert book.clear_key("Alice Example", other)["status"] == "cleared"

    def test_unknown_contact_raises(self, tmp_project):
        book = make_book(tmp_project)
        with pytest.raises(ValueError, match="not found"):
            book.clear_key("Ghost Person", "A" * 40)
