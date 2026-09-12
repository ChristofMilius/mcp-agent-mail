"""
archive_tools — search and retrieve archived email bodies
========================================================
archive_search returns metadata hits only. archive_get recovers the full
body for a given uid — this is what makes email_read's 2000-char cap
non-lossy.
"""

from __future__ import annotations

import json

from mcp_agent_mail.archive import EmailArchive
from mcp_agent_mail.errors import tool_error


def register(server, ctx) -> None:
    archive: EmailArchive = ctx.archive

    @server.tool()
    def archive_search(query: str, limit: int = 20) -> str:
        """Search archived emails (subject/sender/body) — metadata only, no bodies.

        Use this for keyword lookup across mail you have already read. For a
        recency-sorted listing of a mailbox folder, use email_check_inbox.

        Returns: {query, count, hits}. Each hit is {uid, folder, sender,
        subject, date, decrypt_failed, archived_at}. Bodies are never included.

        Args:
            query: Case-insensitive substring to search for.
            limit: Maximum hits to return (1-200).
        """
        try:
            hits = archive.search(query, limit=limit)
            return json.dumps(
                {"query": query, "count": len(hits), "hits": hits},
                indent=2, ensure_ascii=False,
            )
        except Exception as e:
            return tool_error("archive_search", e)

    @server.tool()
    def archive_get(uid: str) -> str:
        """Retrieve the full archived body and metadata for an email uid.

        Precondition: the message must have been opened with email_read first —
        reading is what archives it. A uid that was merely listed
        (email_check_inbox / archive_search) is NOT archived, and this returns
        {"status": "not_found"} for it.

        Returns: the read message's full record — uid, folder, sender, to,
        subject, date, full uncapped body, attachment_count, attachments
        (metadata only), decrypt_failed (bool; True means the message could not
        be decrypted and the body is empty), archived_at (ISO timestamp).

        Args:
            uid: IMAP uid of the previously-read email.
        """
        try:
            record = archive.get(str(uid))
            if record is None:
                return json.dumps({"status": "not_found", "uid": str(uid)})
            return json.dumps(record, indent=2, ensure_ascii=False)
        except Exception as e:
            return tool_error("archive_get", e)


__all__ = ["register"]
