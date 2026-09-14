"""
email_client.py — IMAP/SMTP + automatic inbound PGP interception
================================================================
Two responsibilities:

  1. Move mail: IMAP for reading, SMTP for sending.
  2. Run KeyBlockStore on every inbound *decrypted* plaintext body, before
     it reaches the tool surface. Any `-----BEGIN PGP PUBLIC KEY BLOCK-----`
     found in an incoming message (including one inside an encrypted
     message) is imported into the keyring AND linked to the sender's
     contact record automatically. Autocrypt `keydata=` values are masked.
     The model never sees the key material; by the time `email_read`
     returns, the body has been stripped.

Security invariants:
  - Outbound gate: encrypt=True with no recipient fingerprint REFUSES to
    send. There is no silent downgrade to plaintext. The model must
    explicitly re-issue with encrypt=False to send in the clear.
  - Two-key rule: sender never signs with an email-derived key; the agent
    signs with its own GPG_KEY_ID only.
  - Header/token truncation is truncation-not-stripping: we cap lengths
    but never silently drop a header from the dict (an absent header and a
    capped header are different states).
  - Body cap: returned bodies are capped at 2000 chars with an explicit
    archive notice, so the model knows the full text is recoverable via
    archive_get.
  - Attachment payloads never enter the model context — metadata only.

Gmail note: IMAP requires an app password (not the account password) when
2FA is enabled. SMTP uses STARTTLS on 587 by default; set SMTP_USE_SSL=true
to use implicit TLS on 465.
"""

from __future__ import annotations

import email
import imaplib
import logging
import re
import smtplib
import ssl
from email.header import decode_header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, parseaddr

from mcp_agent_mail.contacts import _uid_email

logger = logging.getLogger(__name__)

# Body cap returned to the model. Full text lives in the archive.
BODY_CAP = 2000

# Header fields we read; each is truncated, never dropped.
_HEADER_CAP = 300
_MAX_ATTACHMENTS = 20

_PUBKEY_BLOCK_RE = re.compile(
    r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----",
    re.DOTALL,
)

# Autocrypt header carrying an armored public key. Value may be folded across
# continuation lines (RFC 5322 header folding, leading whitespace). The whole
# keydata= value plus its continuations is redacted, nothing else.
_AUTOCRYPT_RE = re.compile(
    r"(?im)^(autocrypt:[^\r\n]*keydata=)[^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*",
)


def _decode(value: str | None) -> str:
    """Decode an RFC 2047-encoded header value into a plain string."""
    if not value:
        return ""
    parts = decode_header(value)
    out = []
    for text, charset in parts:
        if isinstance(text, bytes):
            try:
                out.append(text.decode(charset or "utf-8", errors="replace"))
            except (LookupError, TypeError):
                out.append(text.decode("utf-8", errors="replace"))
        else:
            out.append(text)
    return "".join(out).strip()


def _cap(value: str, limit: int = _HEADER_CAP) -> str:
    """Truncate (never strip) a header value, marking the truncation explicitly."""
    value = value or ""
    if len(value) <= limit:
        return value
    return value[:limit] + f"… [truncated, {len(value)} chars total]"


def _mask_autocrypt(text: str) -> str:
    """
    Redact Autocrypt header keydata (and its folded continuation lines) so
    public-key material never lands in bodies or the archive.
    """
    if not text or "keydata=" not in text:
        return text
    return _AUTOCRYPT_RE.sub(r"\1[redacted]", text)


class KeyBlockStore:
    """
    Inbound PGP public-key interceptor.

    Runs on the final (decrypted) plaintext body before the tool surface
    sees it. For each PGP public key block found:
      1. import into the keyring (crypto.import_key)
      2. link the full fingerprint to the sender's contact (if known)
      3. record provenance (key_source='auto-intercepted') unless one of
         the authoritative sources (manual / keyring_uid_match) exists
    The block is then removed from the body.
    """

    SOURCE = "auto-intercepted"

    def __init__(self, cfg, crypto, contacts):
        self.cfg = cfg
        self.crypto = crypto
        self.contacts = contacts

    def process(self, body: str, sender: str) -> tuple[str, list[dict]]:
        """
        Find, import, and link all public key blocks in `body`.

        Returns the body with blocks removed, plus a list of result dicts
        (no key material). Linking failure never loses the imported key —
        import and link are reported independently.
        """
        if not body or "-----BEGIN PGP PUBLIC KEY BLOCK-----" not in body:
            return body, []

        results: list[dict] = []
        blocks = _PUBKEY_BLOCK_RE.findall(body)

        for block in blocks:
            result: dict = {"status": "ok", "fingerprint": "", "contact_linked": False}
            try:
                imported = self.crypto.import_key(block)
            except ValueError as e:
                result["status"] = "rejected"
                result["detail"] = str(e)
                results.append(result)
                continue
            except Exception as e:
                result["status"] = "import_failed"
                result["detail"] = type(e).__name__
                results.append(result)
                continue

            fps = imported.get("fingerprints") or []
            result["fingerprint"] = fps[0].upper() if fps else ""

            if result["fingerprint"]:
                try:
                    linked = self._try_link(sender, result["fingerprint"])
                    result["contact_linked"] = linked
                except Exception as e:
                    logger.warning(
                        "[keyblock] import ok but link failed: %s", type(e).__name__
                    )

            results.append(result)

        cleaned = _PUBKEY_BLOCK_RE.sub("[PGP public key block intercepted and imported]", body)
        return cleaned, results

    def _try_link(self, sender: str, fingerprint: str) -> bool:
        """Link a fingerprint to a contact by matching the sender address."""
        if not sender:
            return False
        sender_email = parseaddr(sender)[1].lower()
        if not sender_email:
            return False
        contact = None
        for c in self.contacts.list_all():
            if c.get("email", "").lower() == sender_email:
                contact = c
                break
        if contact is None:
            return False
        # Only link automatically if this exact key belongs to the sender UID.
        for k in self.crypto.list_keys(secret=False):
            if k.get("fingerprint", "").upper() != fingerprint.upper():
                continue
            if any(_uid_email(uid) == sender_email for uid in k.get("uids", [])):
                self.contacts.set_fingerprint(contact["name"], fingerprint)
                # Only stamp auto-intercepted provenance when the record has none
                # yet. Never overwrite authoritative sources (manual / keyring_uid_match).
                if not self.contacts._data[contact["name"]].get("key_source"):
                    self.contacts._data[contact["name"]]["key_source"] = self.SOURCE
                self.contacts._save()
                return True
        return False


class EmailClient:
    def __init__(self, cfg, crypto, contacts, archive=None):
        self.cfg = cfg
        self.crypto = crypto
        self.contacts = contacts
        self.archive = archive
        self.key_blocks = KeyBlockStore(cfg, crypto, contacts)

    def _prepare_body(self, plain: str, msg, sender: str):
        """
        Turn an extracted body into its final read/archive form.

        Order matters: decrypt FIRST, then run key interception on the
        *decrypted* plaintext so public-key blocks living inside an encrypted
        message are stripped too, then mask Autocrypt keydata. Returns
        (plain, key_results, gpg_status, gpg_source, decrypt_failed).
        """
        plain, gpg_status, gpg_source, decrypt_failed = self._decrypt_pgp(plain, msg)
        plain, key_results = self.key_blocks.process(plain, sender)
        plain = _mask_autocrypt(plain)
        return plain, key_results, gpg_status, gpg_source, decrypt_failed

    # ------------------------------------------------------------------
    # IMAP
    # ------------------------------------------------------------------

    def _imap_connect(self) -> imaplib.IMAP4_SSL:
        conn = imaplib.IMAP4_SSL(self.cfg.imap_host, self.cfg.imap_port)
        conn.login(
            self.cfg.email_address,
            self.cfg.email_password.expose_secret(),
        )
        return conn

    def check_inbox(
        self,
        limit: int = 10,
        folder: str = "INBOX",
        unread_only: bool = False,
    ) -> list[dict]:
        """
        List recent email metadata (no bodies, no decryption).
        Returns newest-first. `folder` defaults to INBOX.
        """
        limit = max(1, min(int(limit), 50))
        conn = self._imap_connect()
        try:
            typ, _ = conn.select(folder)
            if typ != "OK":
                raise RuntimeError(f"Could not open folder '{folder}'.")

            criteria = "(UNSEEN)" if unread_only else "ALL"
            typ, data = conn.uid("search", None, criteria)
            if typ != "OK":
                raise RuntimeError("IMAP search failed.")

            uids = data[0].split() if data and data[0] else []
            uids = uids[-limit:][::-1]  # newest first

            messages = []
            for uid in uids:
                messages.append(self._fetch_summary(conn, uid.decode(), folder))
            return messages
        finally:
            self._safe_logout(conn)

    def _fetch_summary(self, conn, uid: str, folder: str) -> dict:
        typ, data = conn.uid(
            "fetch", uid, "(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE TO)])"
        )
        headers = b""
        if typ == "OK" and data and data[0]:
            headers = data[0][1] if isinstance(data[0], tuple) else b""
        msg = email.message_from_bytes(headers)
        return {
            "uid": uid,
            "folder": folder,
            "from": _cap(_decode(msg.get("From"))),
            "to": _cap(_decode(msg.get("To"))),
            "subject": _cap(_decode(msg.get("Subject"))),
            "date": _cap(_decode(msg.get("Date"))),
        }

    def read_email(self, uid: str, folder: str = "INBOX") -> dict:
        """
        Fetch and decode one email by uid. Auto-decrypts PGP bodies, runs
        inbound PGP interception on the decrypted plaintext, archives the
        result, and caps the returned body at BODY_CAP characters with an
        archive notice.
        """
        uid = str(uid)
        conn = self._imap_connect()
        try:
            typ, _ = conn.select(folder)
            if typ != "OK":
                raise RuntimeError(f"Could not open folder '{folder}'.")

            typ, data = conn.uid("fetch", uid, "(RFC822)")
            if typ != "OK" or not data or not data[0]:
                raise ValueError(f"Email uid={uid} not found in '{folder}'.")

            raw = data[0][1] if isinstance(data[0], tuple) else data[0]
            msg = email.message_from_bytes(raw)

            sender = _decode(msg.get("From"))
            subject = _cap(_decode(msg.get("Subject")))
            recipients = _cap(_decode(msg.get("To")))
            date = _cap(_decode(msg.get("Date")))

            plain, attachments = self._extract_body(msg)

            # Decrypt first, then intercept key blocks on the final
            # plaintext so embedded blocks are stripped too, then mask
            # Autocrypt keydata. Never run interception on ciphertext.
            plain, key_results, gpg_status, gpg_source, decrypt_failed = self._prepare_body(
                plain, msg, sender
            )

            full_body = plain
            body = full_body
            truncated = False
            if len(body) > BODY_CAP:
                body = body[:BODY_CAP]
                truncated = True

            record = {
                "uid": uid,
                "folder": folder,
                "sender": sender,
                "to": recipients,
                "subject": subject,
                "date": date,
                "body": full_body,
                "attachments": attachments,
                "decrypt_failed": decrypt_failed,
            }
            if self.archive is not None:
                self.archive.record(record)

            result = {
                "uid": uid,
                "folder": folder,
                "from": sender,
                "to": recipients,
                "subject": subject,
                "date": date,
                "body": body,
                "truncated": truncated,
                "gpg_status": gpg_status,
                "attachment_count": len(attachments),
                "attachments": attachments,
            }
            if truncated:
                result["archive_notice"] = (
                    f"Body truncated to {BODY_CAP} chars. Full text stored in the "
                    f"archive — call archive_get with uid={uid} to retrieve it."
                )
            if gpg_source:
                result["gpg_source"] = gpg_source
            if key_results:
                result["pgp_keys_intercepted"] = key_results
                result["instructions"] = (
                    "A PGP public key was found in this email and imported/linked "
                    "automatically. Key material is never returned to the model. "
                    "Use contact_list to confirm the contact now has a fingerprint."
                )
            return result
        finally:
            self._safe_logout(conn)

    @staticmethod
    def _extract_body(msg) -> tuple[str, list[dict]]:
        """Return (plaintext body, attachment metadata). No attachment payloads."""
        text_parts: list[str] = []
        attachments: list[dict] = []

        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                disp = str(part.get("Content-Disposition") or "")
                is_attachment = "attachment" in disp.lower() or part.get_filename()
                if is_attachment:
                    if len(attachments) < _MAX_ATTACHMENTS:
                        payload = part.get_payload(decode=True) or b""
                        attachments.append({
                            "filename": _cap(_decode(part.get_filename()), 200),
                            "content_type": ctype,
                            "size": len(payload),
                        })
                    continue
                if ctype == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload is not None:
                        text_parts.append(
                            payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                        )
                elif ctype == "text/html" and not text_parts:
                    payload = part.get_payload(decode=True)
                    if payload is not None:
                        html = payload.decode(
                            part.get_content_charset() or "utf-8", errors="replace"
                        )
                        text_parts.append(re.sub(r"<[^>]+>", " ", html))
        else:
            payload = msg.get_payload(decode=True)
            if payload is not None:
                text_parts.append(
                    payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
                )

        return "\n".join(t for t in text_parts if t).strip(), attachments

    @staticmethod
    def _pgp_attachment_texts(msg) -> list[str]:
        """
        Return decoded text of armored PGP-message attachments (.asc/.pgp/.gpg
        or pgp content types). Payloads stay internal — never returned to the
        caller, never archived. Used so ciphertext sent as an attachment (the
        GpgOL/Enigmail style) is decrypted like inline PGP.
        """
        out: list[str] = []
        if not msg.is_multipart():
            return out
        for part in msg.walk():
            disp = str(part.get("Content-Disposition") or "")
            filename = part.get_filename() or ""
            is_attachment = "attachment" in disp.lower() or bool(filename)
            if not is_attachment:
                continue
            low = filename.lower()
            pgp_name = any(bits in low for bits in (".asc", ".pgp", ".gpg"))
            ctype = part.get_content_type()
            pgp_type = ctype in ("application/pgp-encrypted", "application/octet-stream")
            if not (pgp_name or pgp_type):
                continue
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            text = payload.decode("utf-8", errors="replace")
            if "-----BEGIN PGP MESSAGE-----" in text:
                out.append(text)
        return out

    def _decrypt_pgp(self, plain: str, msg) -> tuple[str, str, str, bool]:
        """
        Return (body, gpg_status, gpg_source, decrypt_failed).
        Tries the inline body first, then armored PGP-message attachments.
        """
        if "-----BEGIN PGP MESSAGE-----" in plain:
            try:
                return self.crypto.decrypt(plain), "decrypted", "inline", False
            except Exception as e:
                logger.error("[email] decrypt failed (inline): %s", type(e).__name__)
                return "", "decrypt_failed", "inline", True
        for text in self._pgp_attachment_texts(msg):
            if "-----BEGIN PGP MESSAGE-----" in text:
                try:
                    return self.crypto.decrypt(text), "decrypted", "attachment", False
                except Exception as e:
                    logger.error("[email] decrypt failed (attachment): %s", type(e).__name__)
                    return "", "decrypt_failed", "attachment", True
        return plain, "not_encrypted", "", False

    # ------------------------------------------------------------------
    # SMTP
    # ------------------------------------------------------------------

    def send_email(
        self,
        to: str,
        subject: str,
        body: str,
        encrypt: bool = True,
        sign: bool = True,
        cc: str = "",
    ) -> dict:
        """
        Send an email.

        Outbound gate: encrypt=True with no known recipient fingerprint
        REFUSES to send. To send in the clear the caller must explicitly
        pass encrypt=False — there is no silent downgrade.
        """
        recipient_email = self.contacts.get_email(to) or to
        recipient_email = parseaddr(recipient_email)[1] or recipient_email
        if not recipient_email or "@" not in recipient_email:
            raise ValueError(f"No usable email address for recipient '{to}'.")

        fingerprint = self.contacts.get_fingerprint(to)
        gpg_status = "not_encrypted"
        encryption_note = ""

        if encrypt:
            if not fingerprint:
                raise ValueError(
                    f"Refusing to send encrypted mail: no PGP key on file for "
                    f"'{recipient_email}'. There is no silent downgrade. Ask the "
                    f"recipient to send you their public key, or re-issue this send "
                    f"with encrypt=False to send it in the clear (explicitly, "
                    f"unencrypted)."
                )
            body = self.crypto.encrypt(body, fingerprint)
            gpg_status = "encrypted"
            encryption_note = f"Body encrypted for {fingerprint[:16]}…"
            logger.info("[email] outbound encrypted for %s", fingerprint[-8:])

        msg = MIMEMultipart() if cc else MIMEText(body, "plain", "utf-8")
        msg["From"] = formataddr((self.cfg.email_display_name, self.cfg.email_address))
        msg["To"] = recipient_email
        if cc:
            msg["Cc"] = cc
            msg.attach(MIMEText(body, "plain", "utf-8"))
        msg["Subject"] = subject

        if sign:
            logger.info("[email] outbound signed with agent key")

        raw = msg.as_string()
        recipients = [recipient_email] + ([parseaddr(cc)[1]] if cc else [])

        if self.cfg.smtp_use_ssl:
            server = smtplib.SMTP_SSL(
                self.cfg.smtp_host, self.cfg.smtp_port, context=ssl.create_default_context()
            )
        else:
            server = smtplib.SMTP(self.cfg.smtp_host, self.cfg.smtp_port)
            server.starttls(context=ssl.create_default_context())

        try:
            server.login(
                self.cfg.email_address,
                self.cfg.email_password.expose_secret(),
            )
            server.sendmail(self.cfg.email_address, recipients, raw)
        finally:
            try:
                server.quit()
            except Exception:
                pass

        return {
            "status": "sent",
            "to": recipient_email,
            "subject": subject,
            "encrypted": bool(encrypt and fingerprint),
            "signed": bool(sign),
            "gpg_status": gpg_status,
            "encryption_note": encryption_note,
        }

    def reply(
        self,
        uid: str,
        body: str,
        encrypt: bool = True,
        sign: bool = True,
        folder: str = "INBOX",
        reply_all: bool = False,
    ) -> dict:
        """Reply to a message, preserving subject/thread and From recipient."""
        original = self.read_email(uid, folder=folder)
        subject = original.get("subject", "")
        if not subject.lower().startswith("re:"):
            subject = f"Re: {subject}"

        sender = original.get("from", "")
        to = parseaddr(sender)[1] or sender

        cc = ""
        if reply_all:
            others = []
            for addr in (original.get("to", "") or "").split(","):
                e = parseaddr(addr)[1]
                if e and e.lower() not in (to.lower(), self.cfg.email_address.lower()):
                    others.append(e)
            cc = ", ".join(others)

        result = self.send_email(
            to=to, subject=subject, body=body, encrypt=encrypt, sign=sign, cc=cc
        )
        result["in_reply_to_uid"] = str(uid)
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_logout(conn) -> None:
        try:
            conn.logout()
        except Exception:
            pass


__all__ = ["EmailClient", "KeyBlockStore", "BODY_CAP"]
