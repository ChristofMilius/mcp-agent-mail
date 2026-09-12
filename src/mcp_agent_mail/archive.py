"""
archive.py — lightweight JSONL email archive
============================================
Append-only record of every email the agent reads, so bodies survive after
they age out of the mailbox or are removed by the harness.

Format: one JSON object per line (JSONL). One file, `data/archive.emails.jsonl`.

What is stored:
  - uid, folder, sender, to, subject, date
  - body: the full DECRYPTED and SANITIZED body, but only AFTER inbound PGP
    interception has run (KeyBlockStore). Bodies that failed decryption are
    recorded with `decrypt_failed=True` and an empty body — we never archive
    ciphertext as if it were plaintext, and never archive a half-decrypted body.
  - attachment metadata only: filename / content_type / size.
    Attachment payloads are never written here.

Deduplication: by uid. `record()` is idempotent — re-reading the same email
does not create duplicate lines. The uid is the IMAP UID (stable per folder).

Security:
  - The archive is plaintext on disk. SECURITY.md documents this as a
    deliberate trade-off: it is the agent's own readable mail store, and it is
    what makes `email_read`'s 2000-char body cap recoverable via archive_get.
    Point ARCHIVE_PATH at an encrypted volume if at-rest encryption is needed.
  - No secrets, no key material, no ciphertext is ever written.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

_FILENAME_SAFE_RE = re.compile(r"[^\w.\-]")


class EmailArchive:
    """Append-only JSONL archive of read emails, deduplicated by uid."""

    def __init__(self, cfg):
        self.path = Path(cfg.archive_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seen_uids: set[str] = set()
        self._load_uids()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _load_uids(self) -> None:
        """Populate the uid index from the existing file (idempotent writes)."""
        if not self.path.exists():
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        uid = obj.get("uid")
                        if uid:
                            self._seen_uids.add(str(uid))
                    except json.JSONDecodeError:
                        logger.warning("[archive] skipping malformed JSONL line")
        except OSError as e:
            logger.warning("[archive] could not read archive index: %s", type(e).__name__)

    @staticmethod
    def _sanitize_filename(name: str) -> str:
        name = _FILENAME_SAFE_RE.sub("_", name or "")
        return name[:120] or "unnamed"

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def record(self, email: dict) -> bool:
        """
        Archive one email. Returns True if a new line was written, False if
        the uid was already archived or the record was rejected.

        `email` is a dict with keys: uid, folder, sender, to, subject, date,
        body, attachments (list of {filename, content_type, size}),
        decrypt_failed (bool).
        """
        uid = email.get("uid")
        if uid is None or str(uid) == "":
            logger.warning("[archive] refusing to archive email with no uid")
            return False
        uid = str(uid)

        if uid in self._seen_uids:
            return False

        decrypt_failed = bool(email.get("decrypt_failed", False))
        body = "" if decrypt_failed else (email.get("body") or "")

        if decrypt_failed:
            logger.info("[archive] uid=%s archived with decrypt_failed=True", uid)

        entry = {
            "uid": uid,
            "folder": email.get("folder", "INBOX"),
            "sender": email.get("sender", ""),
            "to": email.get("to", ""),
            "subject": email.get("subject", ""),
            "date": email.get("date", ""),
            "body": body,
            "attachment_count": len(email.get("attachments") or []),
            "attachments": [
                {
                    "filename": a.get("filename", ""),
                    "content_type": a.get("content_type", ""),
                    "size": a.get("size", 0),
                }
                for a in (email.get("attachments") or [])
            ],
            "decrypt_failed": decrypt_failed,
            "archived_at": datetime.now().isoformat(),
        }

        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError as e:
            logger.error("[archive] write failed: %s", type(e).__name__)
            return False

        self._seen_uids.add(uid)
        return True

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get(self, uid: str) -> dict | None:
        """Return the archived record for a uid, or None if absent."""
        uid = str(uid)
        if not self.path.exists():
            return None
        # Newest line wins if a uid somehow appears twice.
        found: dict | None = None
        try:
            with open(self.path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if str(obj.get("uid")) == uid:
                        found = obj
        except OSError as e:
            logger.warning("[archive] get failed: %s", type(e).__name__)
            return None
        return found

    def search(self, query: str, limit: int = 20) -> list[dict]:
        """
        Case-insensitive substring search over subject / sender / body.
        Returns metadata-only hits (no bodies) newest-first.
        """
        limit = max(1, min(int(limit), 200))
        q = (query or "").strip().lower()
        if not q:
            return []

        hits: list[dict] = []
        if not self.path.exists():
            return hits

        try:
            with open(self.path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if (
                        q in (obj.get("subject") or "").lower()
                        or q in (obj.get("sender") or "").lower()
                        or q in (obj.get("body") or "").lower()
                    ):
                        hits.append({
                            "uid": obj.get("uid", ""),
                            "folder": obj.get("folder", ""),
                            "sender": obj.get("sender", ""),
                            "subject": obj.get("subject", ""),
                            "date": obj.get("date", ""),
                            "decrypt_failed": bool(obj.get("decrypt_failed", False)),
                            "archived_at": obj.get("archived_at", ""),
                        })
        except OSError as e:
            logger.warning("[archive] search failed: %s", type(e).__name__)
            return []

        hits.sort(key=lambda h: h.get("archived_at", ""), reverse=True)
        return hits[:limit]


__all__ = ["EmailArchive"]
