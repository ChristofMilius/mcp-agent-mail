"""
contacts.py — Contact book manager
==================================
Security properties carried over intact:
  - set_fingerprint() accepts FULL 40-char fingerprints only.
    Short (16-char) key IDs are vulnerable to the 'Evil32' collision attack
    and are rejected, not merely warned about.
  - find_and_link_key() matches by exact UID email (not substring), and
    refuses when multiple keys match — ambiguity must be resolved via
    contact_set_fingerprint() with the exact full fingerprint.

Well-formed records:
  - Every contact is `given_name` + `surname` (the record key derives from
    them) + `email`. New contacts are well-formed by construction.
  - The only key identifier is the full 40-char fingerprint, stored in
    `gpg_key_fingerprint`. Short key IDs are never stored or accepted.
  - Key lifecycle provenance:
      `key_source`     "" | "keyring_uid_match" | "manual" | "cleared"
      `key_linked_at`  when the fingerprint was linked (set on link, kept as
                       history after a clear)
      `key_cleared_at` when the fingerprint was removed; non-empty means
                       "deliberately cleared" (no redundant boolean)
  - contact_add() clears a stale fingerprint when the email changes — a
    fingerprint linked to the old address is ambiguous for the new one.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

# Full GPG fingerprint: exactly 40 hex characters
_FULL_FINGERPRINT_RE = re.compile(r"^[0-9A-Fa-f]{40}$")

# Provenance values recorded when a fingerprint is linked / cleared.
SOURCE_KEYRING_MATCH = "keyring_uid_match"
SOURCE_MANUAL = "manual"
SOURCE_CLEARED = "cleared"


def _uid_email(uid: str) -> str:
    """
    Extract the email address from a GPG UID string ('Name <email>').
    Returns lowercased email, or lowercased full UID if no angle brackets.
    """
    match = re.search(r"<([^>]+)>", uid)
    return match.group(1).lower() if match else uid.lower()


def _plain(s: str) -> str:
    """Normalize a free-text string for comparison: lower, strip, collapse
    internal whitespace runs to a single space."""
    if not s:
        return ""
    return " ".join(s.lower().split())


class IdentityGuardError(Exception):
    """
    Raised when a tool tries to mutate one of the identity entries.

    The agent entry (EMAIL_ADDRESS) and the owner entry (OWNER_EMAIL) are
    fixed at setup; changing or removing them is a human act (re-setup or a
    future owner-facing CLI), not a model operation. Carries the role and
    record name so the tool surface can translate it into a readable
    response.
    """

    def __init__(self, role: str, name: str, reason: str):
        super().__init__(reason)
        self.role = role
        self.name = name


class ContactBook:
    def __init__(self, cfg):
        self.path = Path(cfg.contacts_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._data: dict = {}
        # Identity entries — fixed at setup, immutable from the tool surface.
        # Books built without these config values have inert identity guards.
        self._agent_email: str = (getattr(cfg, "email_address", "") or "").strip().lower()
        self._owner_email: str = (getattr(cfg, "owner_email", "") or "").strip().lower()
        self._load()

    def _identity_role(self, email: str) -> str:
        """Return 'agent', 'owner', or '' for a contact email."""
        e = (email or "").strip().lower()
        if self._agent_email and e == self._agent_email:
            return "agent"
        if self._owner_email and e == self._owner_email:
            return "owner"
        return ""

    def _raise_if_identity(self, key: str) -> None:
        """Refuse key-operations on the immutable identity entries."""
        role = self._identity_role(self._data[key].get("email", ""))
        if role:
            raise IdentityGuardError(
                role,
                key,
                f"'{key}' is the {role} identity and is immutable from the tool "
                f"surface. Changing or removing its key is an owner action "
                f"(re-setup / owner-facing CLI), not a model operation.",
            )

    def _load(self):
        if self.path.exists():
            with open(self.path, encoding="utf-8") as f:
                self._data = json.load(f)
            if self._migrate():
                self._save()
        else:
            self._data = {}
            self._save()

    def _migrate(self) -> bool:
        """
        Upgrade legacy flat records to the well-formed schema in place.

        Legacy shape: {name: {added, email, notes, updated, gpg_fingerprint,
        key_source, key_linked_at}}. Migration maps fields across and fills
        defaults; surnames cannot be invented, so they are left blank and must
        be completed during setup. Returns True if any record changed.
        """
        changed = False
        for name, record in self._data.items():
            if not isinstance(record, dict):
                continue
            if "given_name" not in record:
                record["given_name"] = name
                changed = True
            if "surname" not in record:
                record["surname"] = ""
                changed = True
            if "gpg_fingerprint" in record:
                record["gpg_key_fingerprint"] = record.pop("gpg_fingerprint")
                changed = True
            elif "gpg_key_fingerprint" not in record:
                record["gpg_key_fingerprint"] = ""
                changed = True
            for field in ("email", "notes", "added", "updated", "key_source", "key_linked_at"):
                if field not in record:
                    record[field] = ""
                    changed = True
            if "key_cleared_at" not in record:
                record["key_cleared_at"] = ""
                changed = True
        return changed

    def _save(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, ensure_ascii=False)

    def _normalize(self, name_or_email: str) -> str | None:
        """
        Resolve a query string to a record key.

        Tolerant lookup: leading/trailing whitespace is ignored, internal
        runs of whitespace collapse to a single space (so 'John  Smith'
        and ' John Smith ' both resolve), matching is case-insensitive,
        and a bare surname is accepted. Lookup order: exact key, exact email,
        key prefix, bare surname. The first match in each tier wins.
        """
        query = _plain(name_or_email)
        if not query:
            return None
        for key in self._data:
            if _plain(key) == query:
                return key
        for key, val in self._data.items():
            if _plain(val.get("email", "")) == query:
                return key
        for key in self._data:
            if _plain(key).startswith(query):
                return key
        for key, val in self._data.items():
            if val.get("surname") and _plain(val["surname"]) == query:
                return key
        return None

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def list_all(self) -> list:
        result = []
        for name, info in self._data.items():
            result.append(self._shape(name, info))
        return sorted(result, key=lambda x: x["name"].lower())

    def get(self, name_or_email: str) -> dict | None:
        key = self._normalize(name_or_email)
        if key is None:
            return None
        return self._shape(key, self._data[key])

    def _shape(self, key: str, info: dict) -> dict:
        """Shape a stored contact record into its public dict."""
        return {
            "name": key,
            "given_name": info.get("given_name", ""),
            "surname": info.get("surname", ""),
            "email": info.get("email", ""),
            "gpg_key_fingerprint": info.get("gpg_key_fingerprint", ""),
            "has_gpg_key": bool(info.get("gpg_key_fingerprint")),
            "key_source": info.get("key_source", ""),
            "key_linked_at": info.get("key_linked_at", ""),
            "key_cleared_at": info.get("key_cleared_at", ""),
            "notes": info.get("notes", ""),
            "added": info.get("added", ""),
            "updated": info.get("updated", ""),
        }

    def get_email(self, name_or_email: str) -> str | None:
        contact = self.get(name_or_email)
        if contact is None:
            return name_or_email if "@" in name_or_email else None
        return contact["email"]

    def get_fingerprint(self, name_or_email: str) -> str | None:
        contact = self.get(name_or_email)
        if contact:
            return contact.get("gpg_key_fingerprint") or None
        return None

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def add(self, given_name: str, surname: str, email: str, notes: str = "", crypto=None) -> dict:
        """
        Add or update a contact record. Accepts NO key material.

        given_name + surname are required and form the record's display name
        (the record key). Records are thus well-formed by construction.

        If the contact already exists with a DIFFERENT email, any previously
        linked fingerprint is cleared: a key linked to the old address is
        ambiguous for the new one. The returned record makes the resulting
        key state explicit.
        """
        given_name = given_name.strip()
        surname = surname.strip()
        email = email.strip()
        if not given_name or not surname:
            raise ValueError(
                "given_name and surname are required for a well-formed contact record."
            )

        name = f"{given_name} {surname}"
        role = self._identity_role(email)
        if role:
            raise IdentityGuardError(
                role,
                name,
                f"'{email}' is the {role} identity. Identity entries are immutable "
                f"from the tool surface — they exist once and are set at setup; "
                f"changing them is an owner action (re-setup).",
            )

        now = datetime.now().isoformat()
        existing = self._data.get(name)
        email_changed = existing is not None and existing.get("email", "").lower() != email.lower()

        if existing is None:
            self._data[name] = {
                "added": now,
                "given_name": given_name,
                "surname": surname,
                "email": email,
                "notes": notes,
                "updated": now,
                "gpg_key_fingerprint": "",
                "key_source": "",
                "key_linked_at": "",
                "key_cleared_at": "",
            }
        else:
            if email_changed and existing.get("gpg_key_fingerprint"):
                # Stale fingerprint under a changed address would be ambiguous.
                existing.pop("gpg_key_fingerprint", None)
                existing["key_source"] = SOURCE_CLEARED
                existing["key_cleared_at"] = now
            existing.update({
                "given_name": given_name,
                "surname": surname,
                "email": email,
                "notes": notes,
                "updated": now,
            })
        self._save()

        return {
            "name": name,
            "given_name": given_name,
            "surname": surname,
            "email": email,
            "gpg_key_fingerprint": self._data[name].get("gpg_key_fingerprint", ""),
            "has_gpg_key": bool(self._data[name].get("gpg_key_fingerprint")),
            "key_source": self._data[name].get("key_source", ""),
            "key_linked_at": self._data[name].get("key_linked_at", ""),
            "key_cleared_at": self._data[name].get("key_cleared_at", ""),
            "status": "added",
            "note": (
                "Contact added. If their key is in the keyring, "
                "call contact_link_key() to associate it."
            ),
        }

    def find_and_link_key(self, name_or_email: str, crypto) -> dict:
        """
        Search keyring for a key whose UID email matches the contact's email,
        then link the full fingerprint. No key material passes through here.

        Refuses when multiple keys match the same UID email — the ambiguity
        must be resolved manually with contact_set_fingerprint().
        """
        key = self._normalize(name_or_email)
        if key is None:
            raise ValueError(f"Contact not found: {name_or_email}")
        self._raise_if_identity(key)
        contact_email = self._data[key]["email"].lower()
        all_keys = crypto.list_keys(secret=False)
        matches = []
        for k in all_keys:
            for uid in k.get("uids", []):
                if _uid_email(uid) == contact_email:
                    matches.append(k)
                    break
        if not matches:
            raise ValueError(
                f"No key in keyring with UID matching '{contact_email}'. "
                f"Their key must arrive via email (intercepted automatically) "
                f"or be imported manually with: gpg --import keyfile.asc"
            )
        if len(matches) > 1:
            fps = sorted(m["fingerprint"] for m in matches)
            raise ValueError(
                f"Multiple keys match '{contact_email}': {fps}. "
                f"Ambiguous — use contact_set_fingerprint with the exact full fingerprint."
            )
        fingerprint = matches[0]["fingerprint"]
        now = datetime.now().isoformat()
        self._data[key]["gpg_key_fingerprint"] = fingerprint
        self._data[key]["key_source"] = SOURCE_KEYRING_MATCH
        self._data[key]["key_linked_at"] = now
        self._data[key]["key_cleared_at"] = ""
        self._data[key]["updated"] = now
        self._save()
        return {
            "name": key,
            "email": contact_email,
            "fingerprint": fingerprint,
            "keyid": matches[0].get("keyid", ""),
            "key_source": SOURCE_KEYRING_MATCH,
            "key_linked_at": now,
            "status": "linked",
        }

    def set_fingerprint(self, name_or_email: str, fingerprint: str) -> dict:
        """
        Directly associate an already-known GPG fingerprint with a contact.

        FALLBACK — prefer contact_link_key(). Only full 40-char fingerprints
        are accepted; short key IDs are rejected (Evil32 collision attack).
        Refuses on identity entries (they carry the setup-supplied key).
        """
        key = self._normalize(name_or_email)
        if key is None:
            raise ValueError(f"Contact not found: {name_or_email}")
        self._raise_if_identity(key)

        cleaned = fingerprint.replace(" ", "").upper()
        if not _FULL_FINGERPRINT_RE.match(cleaned):
            raise ValueError(
                f"Invalid fingerprint: expected exactly 40 hex characters (full GPG fingerprint), "
                f"got {len(cleaned)} characters: '{cleaned}'. "
                f"Short key IDs (16 chars) are not accepted — they are vulnerable to collision "
                f"attacks. Use the full fingerprint from gpg_list_keys output."
            )

        now = datetime.now().isoformat()
        self._data[key]["gpg_key_fingerprint"] = cleaned
        self._data[key]["key_source"] = SOURCE_MANUAL
        self._data[key]["key_linked_at"] = now
        self._data[key]["key_cleared_at"] = ""
        self._data[key]["updated"] = now
        self._save()
        return {
            "name": key,
            "fingerprint": cleaned,
            "key_source": SOURCE_MANUAL,
            "key_linked_at": now,
            "status": "updated",
        }

    def _no_match(self, name_or_email: str, fingerprint: str) -> dict:
        """
        Uniform refusal for any (name, fingerprint) pair that does not match.
        Echoes caller input only — never reveals whether the name or the
        fingerprint was the wrong half (no enumeration).
        """
        return {
            "status": "no_match",
            "query": name_or_email,
            "reason": f"could not find a matching pair, ({name_or_email}, {fingerprint})",
        }

    def clear_key(self, name_or_email: str, fingerprint: str) -> dict:
        """
        Deliberately remove a contact's linked PGP fingerprint.

        Deterministic and foolproof — user-facing outcomes never raise:
          - The (name, fingerprint) pair must match the book exactly. Any
            unknown name, keyless contact, or wrong fingerprint yields the
            same no_match result and changes nothing. Pass the contact's
            CURRENT fingerprint (from contact_get) unchanged.
          - Identity entries (agent, owner) are protected: clearing their key
            returns the 'protected' outcome — that is an owner action
            (re-setup), not a model operation.
          - Garbage or short fingerprints can never match a stored full
            fingerprint, so the pair check already rejects them.

        On success the record keeps full provenance: key_source becomes
        "cleared" and key_cleared_at is stamped; the original key_linked_at
        is preserved as history.
        """
        key = self._normalize(name_or_email)
        if key is None:
            return self._no_match(name_or_email, fingerprint)

        role = self._identity_role(self._data[key].get("email", ""))
        if role:
            return {
                "status": "protected",
                "identity": role,
                "query": name_or_email,
                "name": key,
                "reason": (
                    f"'{key}' is the {role} identity — its key is fixed at setup "
                    f"and cannot be cleared via the tool surface. Removing it is "
                    f"an owner action (re-setup / owner-facing CLI)."
                ),
            }

        current = self._data[key].get("gpg_key_fingerprint", "")

        if not current or fingerprint.replace(" ", "").upper() != current.upper():
            return self._no_match(name_or_email, fingerprint)

        cleaned = fingerprint.replace(" ", "").upper()
        now = datetime.now().isoformat()
        # Provenance: key_source="cleared" + key_cleared_at stamped; the
        # original key_linked_at stays as history of when the key was linked.
        self._data[key].pop("gpg_key_fingerprint", None)
        self._data[key]["key_source"] = SOURCE_CLEARED
        self._data[key]["key_cleared_at"] = now
        self._data[key]["updated"] = now
        self._save()
        return {
            "name": key,
            "email": self._data[key].get("email", ""),
            "gpg_key_fingerprint": "",
            "has_gpg_key": False,
            "cleared_fingerprint": cleaned,
            "key_source": SOURCE_CLEARED,
            "key_linked_at": self._data[key].get("key_linked_at", ""),
            "key_cleared_at": now,
            "status": "cleared",
            "note": (
                "Key deliberately cleared. Sends to this contact will be unencrypted "
                "until a new key is linked (contact_link_key)."
            ),
        }

    def remove(self, name_or_email: str):
        key = self._normalize(name_or_email)
        if key is None:
            raise ValueError(f"Contact not found: {name_or_email}")
        self._raise_if_identity(key)
        del self._data[key]
        self._save()


__all__ = [
    "ContactBook",
    "IdentityGuardError",
    "SOURCE_KEYRING_MATCH",
    "SOURCE_MANUAL",
    "SOURCE_CLEARED",
    "_uid_email",
]
