"""
email_tools — inbox / read / send / reply
=========================================
Four tools over EmailClient. All return JSON. The outbound encryption gate
lives in EmailClient.send_email and surfaces here as a normal error string
(deliberately, so the model can read and act on it — it is not an internal
failure).
"""

from __future__ import annotations

import json

from mcp_agent_mail.email_client import EmailClient
from mcp_agent_mail.errors import tool_error


def register(server, ctx) -> None:
    client: EmailClient = ctx.email_client

    @server.tool()
    def email_check_inbox(
        limit: int = 10,
        folder: str = "INBOX",
        unread_only: bool = False,
    ) -> str:
        """List recent emails in a folder (metadata only: uid, from, to, subject, date).

        Use this to browse what is in a mailbox folder, newest first. For
        keyword search across already-read mail, use archive_search.

        Args:
            limit: Maximum number of messages to return (1-50).
            folder: IMAP folder to list. Defaults to INBOX.
            unread_only: If true, only unread messages.
        """
        try:
            messages = client.check_inbox(
                limit=limit, folder=folder, unread_only=unread_only
            )
            return json.dumps(
                {"folder": folder, "count": len(messages), "messages": messages},
                indent=2,
                ensure_ascii=False,
            )
        except Exception as e:
            return tool_error("email_check_inbox", e)

    @server.tool()
    def email_read(uid: str, folder: str = "INBOX") -> str:
        """Read one email by uid. Inbound PGP is intercepted and auto-decrypted.

        The body is capped at 2000 chars; when truncated the full text is in
        the archive (use archive_get). Attachment payloads are never returned —
        metadata only. Public keys found in the body are imported/linked and
        never shown.

        Returns: {uid, folder, from, to, subject, date, body (≤2000 chars),
        truncated, gpg_status, decrypt_failed, attachment_count, attachments}.
        gpg_status values: "decrypted" (PGP present and decrypted; gpg_source
        is "inline" or "attachment"), "decrypt_failed" (ciphertext present but
        undecryptable; body is empty and decrypt_failed is True),
        "not_encrypted" (plaintext, no PGP). When truncated, an archive_notice
        names the exact uid to pass to archive_get.

        Args:
            uid: IMAP uid from email_check_inbox.
            folder: Folder containing the message. Defaults to INBOX.
        """
        try:
            result = client.read_email(str(uid), folder=folder)
            return json.dumps(result, indent=2, ensure_ascii=False)
        except Exception as e:
            return tool_error("email_read", e)

    @server.tool()
    def email_send(
        to: str,
        subject: str,
        body: str,
        encrypt: bool = True,
        sign: bool = True,
        cc: str = "",
    ) -> str:
        """Send an email. Encrypts by default and REFUSES to downgrade silently.

        If encrypt=True (default) and no PGP key is on file for the recipient,
        the send is refused with an explicit message. To send in the clear you
        must re-issue with encrypt=False — unencrypted is always a deliberate,
        explicit choice.

        Returns: {status: "sent", to, subject, encrypted, signed, gpg_status,
        encryption_note}. Outbound gpg_status is "encrypted" when a key was
        used or "not_encrypted" when sent in the clear.

        Args:
            to: Contact name or email address.
            subject: Email subject.
            body: Email body text.
            encrypt: Encrypt the body to the recipient's PGP key (default true).
            sign: Sign the message (recorded in the result).
            cc: Optional comma-separated Cc recipients.
        """
        try:
            result = client.send_email(
                to=to, subject=subject, body=body,
                encrypt=encrypt, sign=sign, cc=cc,
            )
            return json.dumps(result, indent=2, ensure_ascii=False)
        except Exception as e:
            return tool_error("email_send", e)

    @server.tool()
    def email_reply(
        uid: str,
        body: str,
        encrypt: bool = True,
        sign: bool = True,
        folder: str = "INBOX",
        reply_all: bool = False,
    ) -> str:
        """Reply to an email by uid, preserving subject/thread.

        Returns: same shape as email_send (status, to, subject, encrypted,
        signed, gpg_status, encryption_note) plus in_reply_to_uid.

        Args:
            uid: IMAP uid of the message being replied to.
            body: Reply body text.
            encrypt: Encrypt to the original sender's key (default true).
            sign: Sign the reply.
            folder: Folder containing the original message.
            reply_all: Include other To/Cc recipients.
        """
        try:
            result = client.reply(
                uid=str(uid), body=body, encrypt=encrypt, sign=sign,
                folder=folder, reply_all=reply_all,
            )
            return json.dumps(result, indent=2, ensure_ascii=False)
        except Exception as e:
            return tool_error("email_reply", e)


__all__ = ["register"]
