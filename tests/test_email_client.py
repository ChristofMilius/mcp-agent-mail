"""tests/test_email_client.py — body extraction, key interception, outbound gate."""
from __future__ import annotations

import types
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import pytest

from mcp_agent_mail.email_client import (
    BODY_CAP,
    EmailClient,
    KeyBlockStore,
    _cap,
    _decode,
)
from mcp_agent_mail.secrets import SecretString

FPR40 = "AABBCCDDEEFF00112233445566778899AABBCCDD"

BLOCK = """-----BEGIN PGP PUBLIC KEY BLOCK-----
%s
-----END PGP PUBLIC KEY BLOCK-----
""" % ("A" * 64 + "\n" * 30)


def make_cfg(tmp_project):
    root, env = tmp_project
    return types.SimpleNamespace(
        email_address="agent@example.com",
        email_display_name="Agent",
        email_password=SecretString("pw"),
        imap_host="imap.gmail.com",
        imap_port=993,
        smtp_host="smtp.gmail.com",
        smtp_port=587,
        smtp_use_ssl=False,
        contacts_path=env["CONTACTS_PATH"],
    )


class TestHeaderUtils:
    def test_decode_handles_encoded_words(self):
        assert _decode("=?utf-8?q?Gr=C3=BC=C3=9Fe?=") == "Grüße"

    def test_decode_plain(self):
        assert _decode("plain subject") == "plain subject"

    def test_decode_none(self):
        assert _decode(None) == ""

    def test_cap_truncates_and_marks(self):
        out = _cap("x" * 500, limit=100)
        assert len(out) <= 130
        assert "truncated" in out

    def test_cap_short_string_untouched(self):
        assert _cap("short") == "short"

    def test_cap_empty(self):
        assert _cap("") == ""


class TestExtractBody:
    def test_plain_text_single_part(self):
        msg = MIMEText("hello world", "plain", "utf-8")
        body, atts = EmailClient._extract_body(msg)
        assert body == "hello world"
        assert atts == []

    def test_multipart_text_and_attachment_metadata_only(self):
        outer = MIMEMultipart()
        outer.attach(MIMEText("body text", "plain", "utf-8"))
        import email.encoders
        import email.mime.base
        f = email.mime.base.MIMEBase("application", "pdf")
        f.set_payload(b"%" * 1000)
        email.encoders.encode_base64(f)
        f.add_header("Content-Disposition", "attachment", filename="report.pdf")
        outer.attach(f)

        body, atts = EmailClient._extract_body(outer)
        assert body == "body text"
        assert len(atts) == 1
        assert atts[0]["filename"] == "report.pdf"
        assert atts[0]["size"] == 1000

    def test_html_fallback_when_no_plain(self):
        outer = MIMEMultipart()
        outer.attach(MIMEText("<p>Hello <b>world</b></p>", "html", "utf-8"))
        body, atts = EmailClient._extract_body(outer)
        assert "Hello" in body
        assert "world" in body
        assert "<b>" not in body


ARMORED = "-----BEGIN PGP MESSAGE-----\n\nc2VjcmV0\n-----END PGP MESSAGE-----\n"


def _attached_pgp_message(filename="encrypted.asc", payload=ARMORED, ctype="application/octet-stream"):
    import email.encoders
    import email.mime.base

    outer = MIMEMultipart()
    outer.attach(MIMEText("", "plain", "utf-8"))
    f = email.mime.base.MIMEBase(*ctype.split("/", 1))
    f.set_payload(payload)
    email.encoders.encode_base64(f)
    f.add_header("Content-Disposition", "attachment", filename=filename)
    outer.attach(f)
    return outer


class TestPgpAttachmentDecrypt:
    def test_armored_attachment_text_extracted(self):
        msg = _attached_pgp_message()
        body, atts = EmailClient._extract_body(msg)
        assert body == ""
        assert atts[0]["filename"] == "encrypted.asc"
        assert atts[0]["size"] == len(ARMORED.encode("utf-8"))
        texts = EmailClient._pgp_attachment_texts(msg)
        assert len(texts) == 1
        assert "BEGIN PGP MESSAGE" in texts[0]

    def test_pdf_attachment_not_a_pgp_candidate(self):
        import email.encoders
        import email.mime.base

        outer = MIMEMultipart()
        outer.attach(MIMEText("notes", "plain", "utf-8"))
        f = email.mime.base.MIMEBase("application", "pdf")
        f.set_payload(b"%" * 1000)
        email.encoders.encode_base64(f)
        f.add_header("Content-Disposition", "attachment", filename="report.pdf")
        outer.attach(f)
        assert EmailClient._pgp_attachment_texts(outer) == []

    def test_marker_without_pgp_name_or_type_not_candidate(self):
        msg = _attached_pgp_message(filename="notes.txt", ctype="text/plain")
        assert EmailClient._pgp_attachment_texts(msg) == []

    def test_decrypt_falls_back_to_attachment(self):
        crypto = type("C", (), {"decrypt": lambda self, t: "DECRYPTED:" + t.splitlines()[1]})()
        client = EmailClient.__new__(EmailClient)
        client.crypto = crypto
        body, status, source, failed = client._decrypt_pgp("no inline marker", _attached_pgp_message())
        assert status == "decrypted"
        assert source == "attachment"
        assert failed is False
        assert body.startswith("DECRYPTED:")

    def test_decrypt_inline_wins(self):
        crypto = type("C", (), {"decrypt": lambda self, t: "INLINE-DECRYPTED"})()
        client = EmailClient.__new__(EmailClient)
        client.crypto = crypto
        body, status, source, failed = client._decrypt_pgp(ARMORED, _attached_pgp_message())
        assert status == "decrypted"
        assert source == "inline"
        assert body == "INLINE-DECRYPTED"

    def test_no_marker_means_not_encrypted(self):
        import email.encoders
        import email.mime.base

        crypto = type("C", (), {"decrypt": lambda self, t: "unused"})()
        client = EmailClient.__new__(EmailClient)
        client.crypto = crypto
        outer = MIMEMultipart()
        outer.attach(MIMEText("plain hello", "plain", "utf-8"))
        f = email.mime.base.MIMEBase("application", "pdf")
        f.set_payload(b"%" * 100)
        email.encoders.encode_base64(f)
        f.add_header("Content-Disposition", "attachment", filename="report.pdf")
        outer.attach(f)
        body, status, source, failed = client._decrypt_pgp("plain hello", outer)
        assert status == "not_encrypted"
        assert source == ""
        assert failed is False
        assert body == "plain hello"

    def test_decrypt_failure_reported(self):
        crypto = type("C", (), {
            "decrypt": lambda self, t: (_ for _ in ()).throw(RuntimeError("boom"))
        })()
        client = EmailClient.__new__(EmailClient)
        client.crypto = crypto
        body, status, source, failed = client._decrypt_pgp("no marker", _attached_pgp_message())
        assert status == "decrypt_failed"
        assert failed is True
        assert source == "attachment"
        assert body == ""


class _ImportCrypto:
    """Fake crypto capturing what gets imported and returning fingerprints."""

    def __init__(self, fingerprint=FPR40):
        self.fingerprint = fingerprint
        self.imported = []
        self.keys = []

    def import_key(self, material):
        self.imported.append(material)
        return {"imported": 1, "fingerprints": [self.fingerprint]}

    def list_keys(self, secret=False):
        return self.keys


class _Contacts:
    def __init__(self):
        self._data = {}

    def list_all(self):
        out = []
        for name, info in self._data.items():
            out.append({"name": name, "email": info["email"], "gpg_key_fingerprint": ""})
        return out

    def add(self, name, email, notes=""):
        self._data[name] = {"email": email}

    def set_fingerprint(self, name, fp):
        self._data[name]["fp"] = fp

    def _save(self):
        pass


class TestKeyBlockStore:
    def test_body_without_key_passes_through(self):
        cfg = object()
        crypto = _ImportCrypto()
        contacts = _Contacts()
        kbs = KeyBlockStore(cfg, crypto, contacts)
        body, results = kbs.process("no keys here", "alice@example.com")
        assert body == "no keys here"
        assert results == []
        assert crypto.imported == []

    def test_key_imported_and_block_stripped(self):
        cfg = object()
        crypto = _ImportCrypto()
        contacts = _Contacts()
        kbs = KeyBlockStore(cfg, crypto, contacts)
        body = "Hi!\n" + BLOCK + "\nregards"
        cleaned, results = kbs.process(body, "alice@example.com")
        assert len(crypto.imported) == 1
        assert "[PGP public key block intercepted" in cleaned
        assert "-----BEGIN PGP" not in cleaned
        assert results[0]["status"] == "ok"
        assert results[0]["fingerprint"] == FPR40

    def test_key_linked_to_sender_contact(self):
        cfg = object()
        crypto = _ImportCrypto()
        crypto.keys = [
            {"fingerprint": FPR40, "uids": ["Alice Example <alice@example.com>"]}
        ]
        contacts = _Contacts()
        contacts.add("Alice Example", "alice@example.com")
        kbs = KeyBlockStore(cfg, crypto, contacts)
        body, results = kbs.process(BLOCK, "alice@example.com")
        assert results[0]["contact_linked"] is True
        assert contacts._data["Alice Example"]["fp"] == FPR40

    def test_rejected_block_not_imported(self):
        cfg = object()
        crypto = _ImportCrypto()
        contacts = _Contacts()
        kbs = KeyBlockStore(cfg, crypto, contacts)
        bad = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nstuff\n-----END PGP PRIVATE KEY BLOCK-----\n"
        cleaned, results = kbs.process(bad, "alice@example.com")
        assert crypto.imported == []
        assert cleaned == bad  # private blocks are not matched/stripped


class TestOutboundGate:
    def test_encrypt_true_with_no_key_refuses(self, tmp_project):
        cfg = make_cfg(tmp_project)
        # no contacts, no crypto
        client = EmailClient(cfg, crypto=None, contacts=type("C", (), {
            "get_email": lambda self, to: "alice@example.com",
            "get_fingerprint": lambda self, to: None,
        })())
        with pytest.raises(ValueError, match="[Rr]efusing"):
            client.send_email("alice@example.com", "subj", "body", encrypt=True)

    def test_send_returns_explicit_result_on_plain_explicit(self, tmp_project):
        cfg = make_cfg(tmp_project)
        crypto = type("C", (), {"encrypt": lambda self, b, f: "ENCRYPTED"})()
        contacts = type("C", (), {
            "get_email": lambda self, to: "alice@example.com",
            "get_fingerprint": lambda self, to: FPR40,
        })()
        client = EmailClient(cfg, crypto=crypto, contacts=contacts)

        class _FakeSMTP:
            def __init__(self, *a, **k):
                pass

            def starttls(self, context=None):
                pass

            def login(self, *a):
                pass

            def sendmail(self, *a):
                pass

            def quit(self):
                pass

        import smtplib
        orig = smtplib.SMTP
        try:
            smtplib.SMTP = _FakeSMTP
            result = client.send_email("alice@example.com", "s", "b", encrypt=True)
        finally:
            smtplib.SMTP = orig
        assert result["gpg_status"] == "encrypted"
        assert result["encryption_note"] != ""


class TestBodyCapConstant:
    def test_body_cap_defined(self):
        assert BODY_CAP == 2000
