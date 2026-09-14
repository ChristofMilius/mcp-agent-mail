"""tests/test_tools.py — tool surface end-to-end through a fake MCPServer."""
from __future__ import annotations

import json
import types

from mcp_agent_mail.archive import EmailArchive
from mcp_agent_mail.contacts import ContactBook
from mcp_agent_mail.secrets import SecretString
from mcp_agent_mail.tool_surface import register_all

FPR40 = "AABBCCDDEEFF00112233445566778899AABBCCDD"


class FakeServer:
    """Collects tools registered via @server.tool() so we can call them."""

    def __init__(self):
        self.tools = {}

    def tool(self):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn

        return deco


def make_ctx(tmp_project, contact_ops=None, seed_json=None):
    root, env = tmp_project

    cfg = types.SimpleNamespace(
        contacts_path=env["CONTACTS_PATH"],
        archive_path=env["ARCHIVE_PATH"],
        logs_dir=str(root / "logs"),
        pubkey_export_dir=str(root / "exported_keys"),
        email_address="agent@example.com",
        email_display_name="Agent",
        email_password=SecretString("pw"),
        gpg_passphrase=SecretString("pp"),
        gpg_key_id=FPR40,
        gpg_home="",
        secret_backend="env",
    )
    cfg.secret_status = lambda: [
        "EMAIL_ADDRESS: set",
        "EMAIL_PASSWORD: set",
        "GPG_KEY_ID: set",
        "GPG_PASSPHRASE: set",
    ]

    class FakeCrypto:
        def list_keys(self, secret=False):
            return [{"fingerprint": FPR40, "uids": ["Agent <agent@example.com>"], "expires": "", "length": "3072", "algo": "rsa3072"}]

        def export_public_key_to_file(self, key_id, export_dir):
            from pathlib import Path
            p = Path(export_dir) / "agent_pubkey_TEST.asc"
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("-----BEGIN PGP PUBLIC KEY BLOCK-----", encoding="utf-8")
            return p

        def encrypt(self, plaintext, fingerprint):
            return f"ENCRYPTED:{fingerprint}"

        def verify(self, signed_message):
            return {"valid": True, "fingerprint": FPR40, "username": "x", "timestamp": "", "status": "signature valid"}

    contacts = ContactBook(cfg)
    if seed_json:
        from pathlib import Path

        Path(env["CONTACTS_PATH"]).write_text(
            json.dumps(seed_json), encoding="utf-8"
        )
        contacts = ContactBook(cfg)
    if contact_ops:
        contact_ops(contacts)
    archive = EmailArchive(cfg)

    class FakeEmailClient:
        def __init__(self, contacts):
            self.contacts = contacts

        def check_inbox(self, limit=10, folder="INBOX", unread_only=False):
            return [{"uid": "7", "folder": folder, "from": "a@x.com", "to": "agent@example.com", "subject": "Hi", "date": "today"}]

        def read_email(self, uid, folder="INBOX"):
            return {"uid": uid, "folder": folder, "from": "a@x.com", "to": "agent@example.com", "subject": "Hi", "date": "today", "body": "hello", "truncated": False, "gpg_status": "not_encrypted", "attachment_count": 0, "attachments": []}

        def send_email(self, to, subject, body, encrypt=True, sign=True, cc=""):
            if encrypt:
                raise ValueError("Refusing to send encrypted mail: no PGP key on file.")
            raise RuntimeError("no reach" if False else ValueError("Refusing"))

        def reply(self, uid, body, encrypt=True, sign=True, folder="INBOX", reply_all=False):
            return self.read_email(uid, folder)

    ctx = types.SimpleNamespace(
        cfg=cfg,
        crypto=FakeCrypto(),
        contacts=contacts,
        archive=archive,
        email_client=FakeEmailClient(contacts),
    )
    return ctx


class _Result:
    pass


class TestEmailTools:
    def test_check_inbox_returns_json(self, tmp_project):
        server = FakeServer()
        register_all(server, make_ctx(tmp_project))
        out = server.tools["email_check_inbox"](limit=2)
        assert '"uid": "7"' in out

    def test_send_refusal_is_a_readable_string_not_crash(self, tmp_project):
        server = FakeServer()
        register_all(server, make_ctx(tmp_project))
        out = server.tools["email_send"](to="alice@example.com", subject="s", body="b", encrypt=True)
        assert "Error in email_send" in out
        assert "Refusing" not in out  # message is sanitized

    def test_read_returns_json(self, tmp_project):
        server = FakeServer()
        register_all(server, make_ctx(tmp_project))
        out = server.tools["email_read"]("9")
        assert '"body": "hello"' in out


class TestContactTools:
    def test_add_list_roundtrip(self, tmp_project):
        server = FakeServer()
        ctx = make_ctx(tmp_project)
        register_all(server, ctx)
        server.tools["contact_add"](given_name="Alice", surname="Example", email="alice@example.com")
        out = server.tools["contact_list"]()
        assert "Alice Example" in out

    def test_set_fingerprint_rejects_short(self, tmp_project):
        server = FakeServer()
        ctx = make_ctx(tmp_project)
        register_all(server, ctx)
        server.tools["contact_add"](given_name="Alice", surname="Example", email="alice@example.com")
        out = server.tools["contact_set_fingerprint"]("Alice Example", "AABB")
        assert "Error in contact_set_fingerprint" in out

    def test_clear_key_roundtrip(self, tmp_project):
        server = FakeServer()
        ctx = make_ctx(tmp_project)
        register_all(server, ctx)
        other = "00" * 20
        server.tools["contact_add"](given_name="Alice", surname="Example", email="alice@example.com")
        server.tools["contact_set_fingerprint"]("Alice Example", other)
        out = server.tools["contact_clear_key"]("Alice Example", other)
        assert '"status": "cleared"' in out
        listed = server.tools["contact_list"]()
        assert '"gpg_key_fingerprint": ""' in listed

    def test_clear_key_mismatch_is_no_match_json(self, tmp_project):
        server = FakeServer()
        ctx = make_ctx(tmp_project)
        register_all(server, ctx)
        other = "00" * 20
        server.tools["contact_add"](given_name="Alice", surname="Example", email="alice@example.com")
        server.tools["contact_set_fingerprint"]("Alice Example", other)
        out = server.tools["contact_clear_key"]("Alice Example", "11" * 20)
        assert '"status": "no_match"' in out
        assert "could not find a matching pair" in out
        assert '"gpg_key_fingerprint": "' + other + '"' in server.tools["contact_list"]()

    def test_unknown_contact_clear_key_is_no_match_json(self, tmp_project):
        server = FakeServer()
        ctx = make_ctx(tmp_project)
        register_all(server, ctx)
        out = server.tools["contact_clear_key"]("Ghost Person", "A" * 40)
        assert '"status": "no_match"' in out
        assert "Ghost Person" in out

    def test_clear_key_protects_identity_entry(self, tmp_project):
        server = FakeServer()
        agent = {
            "added": "2026-09-13T00:00:00",
            "given_name": "Hermes",
            "surname": "agent of Chris",
            "email": "agent@example.com",
            "gpg_key_fingerprint": FPR40,
            "key_source": "keyring_uid_match",
            "key_linked_at": "2026-09-13T00:00:00",
            "key_cleared_at": "",
            "notes": "",
            "updated": "2026-09-13T00:00:00",
        }
        register_all(server, make_ctx(tmp_project, seed_json={"Hermes the Agent": agent}))
        out = server.tools["contact_clear_key"]("Hermes the Agent", FPR40)
        assert '"status": "protected"' in out
        assert '"identity": "agent"' in out
        assert '"gpg_key_fingerprint": "' + FPR40 + '"' in server.tools["contact_list"]()

    def test_remove_protects_identity_entry(self, tmp_project):
        server = FakeServer()
        agent = {
            "added": "2026-09-13T00:00:00",
            "given_name": "Hermes",
            "surname": "agent of Chris",
            "email": "agent@example.com",
            "gpg_key_fingerprint": FPR40,
            "key_source": "keyring_uid_match",
            "key_linked_at": "2026-09-13T00:00:00",
            "key_cleared_at": "",
            "notes": "",
            "updated": "2026-09-13T00:00:00",
        }
        register_all(server, make_ctx(tmp_project, seed_json={"Hermes the Agent": agent}))
        out = server.tools["contact_remove"]("Hermes the Agent")
        assert '"status": "protected"' in out
        assert '"identity": "agent"' in out
        assert "Hermes the Agent" in server.tools["contact_list"]()

    def test_set_fingerprint_protects_identity_entry(self, tmp_project):
        server = FakeServer()
        agent = {
            "added": "2026-09-13T00:00:00",
            "given_name": "Hermes",
            "surname": "agent of Chris",
            "email": "agent@example.com",
            "gpg_key_fingerprint": FPR40,
            "key_source": "keyring_uid_match",
            "key_linked_at": "2026-09-13T00:00:00",
            "key_cleared_at": "",
            "notes": "",
            "updated": "2026-09-13T00:00:00",
        }
        register_all(server, make_ctx(tmp_project, seed_json={"Hermes the Agent": agent}))
        out = server.tools["contact_set_fingerprint"]("Hermes the Agent", "11" * 20)
        assert '"status": "protected"' in out
        assert '"gpg_key_fingerprint": "' + FPR40 + '"' in server.tools["contact_list"]()


class TestCryptoTools:
    def test_list_keys(self, tmp_project):
        server = FakeServer()
        register_all(server, make_ctx(tmp_project))
        out = server.tools["gpg_list_keys"]()
        assert FPR40 in out

    def test_own_status_masks_secrets(self, tmp_project):
        server = FakeServer()
        register_all(server, make_ctx(tmp_project))
        out = server.tools["gpg_own_status"]()
        assert '"passphrase_configured": true' in out
        assert "pw" not in out

    def test_export_pubkey_returns_path_not_material(self, tmp_project):
        server = FakeServer()
        register_all(server, make_ctx(tmp_project))
        out = server.tools["gpg_export_own_pubkey"]()
        assert "exported" in out
        assert "agent_pubkey_TEST.asc" in out
        assert "-----BEGIN PGP" not in out


class TestArchiveTools:
    def test_get_not_found_is_json_not_error(self, tmp_project):
        server = FakeServer()
        register_all(server, make_ctx(tmp_project))
        out = server.tools["archive_get"]("nope")
        assert '"status": "not_found"' in out

    def test_search(self, tmp_project):
        server = FakeServer()
        ctx = make_ctx(tmp_project)
        ctx.archive.record({
            "uid": "1", "folder": "INBOX", "sender": "a@x.com", "to": "agent@example.com",
            "subject": "Secret Project", "date": "today", "body": "hello there", "attachments": [],
            "decrypt_failed": False,
        })
        register_all(server, ctx)
        out = server.tools["archive_search"]("project")
        assert '"count": 1' in out


class TestMiscTools:
    def test_datetime(self, tmp_project):
        server = FakeServer()
        register_all(server, make_ctx(tmp_project))
        out = server.tools["get_current_datetime"]()
        assert "utc" in out


class TestToolAuditing:
    def test_tool_call_is_logged_with_args_and_result(self, tmp_project, caplog):
        import logging

        server = FakeServer()
        register_all(server, make_ctx(tmp_project))
        caplog.set_level(logging.DEBUG, logger="mcp_agent_mail.tool_surface")

        out = server.tools["contact_get"]("Ghost Person")
        assert json.loads(out)["status"] == "not_found"

        messages = [r.message for r in caplog.records]
        assert any(
            m == "[tool contact_get] call contact_get(name_or_email='Ghost Person')"
            for m in messages
        ), messages
        assert any("result" in m and "not_found" in m for m in messages), messages

    def test_tool_result_preview_is_bounded(self, tmp_project, caplog):
        import logging

        server = FakeServer()
        register_all(server, make_ctx(tmp_project))
        caplog.set_level(logging.DEBUG, logger="mcp_agent_mail.tool_surface")

        server.tools["contact_list"]()
        messages = [r.message for r in caplog.records]
        assert any("[tool contact_list] result" in m for m in messages), messages


class TestServerBuild:
    def test_register_all_exposes_full_toolset(self, tmp_project):
        server = FakeServer()
        register_all(server, make_ctx(tmp_project))
        assert len(server.tools) == 19
        assert set(server.tools) == {
            "email_check_inbox", "email_read", "email_send", "email_reply",
            "contact_list", "contact_get", "contact_add", "contact_link_key",
            "contact_set_fingerprint", "contact_clear_key", "contact_remove",
            "gpg_list_keys", "gpg_encrypt", "gpg_verify",
            "gpg_export_own_pubkey", "gpg_own_status",
            "archive_search", "archive_get",
            "get_current_datetime",
        }
