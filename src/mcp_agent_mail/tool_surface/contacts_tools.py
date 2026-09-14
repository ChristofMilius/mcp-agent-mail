"""
contacts_tools — contact book management
========================================
list / get / add / link_key / set_fingerprint / remove.

No tool here accepts or returns key material. contact_link_key searches the
keyring by exact UID email and links the full fingerprint; contact_set_-
fingerprint accepts only full 40-char fingerprints.
"""

from __future__ import annotations

import json

from mcp_agent_mail.contacts import ContactBook
from mcp_agent_mail.errors import tool_error


def register(server, ctx) -> None:
    contacts: ContactBook = ctx.contacts

    @server.tool()
    def contact_list() -> str:
        """List all contacts with their email and PGP key status (no key material)."""
        try:
            return json.dumps(contacts.list_all(), indent=2, ensure_ascii=False)
        except Exception as e:
            return tool_error("contact_list", e)

    @server.tool()
    def contact_get(name_or_email: str) -> str:
        """Look up one contact by name (prefix ok) or email.

        Args:
            name_or_email: Contact name or email address.
        """
        try:
            contact = contacts.get(name_or_email)
            if contact is None:
                return json.dumps({"status": "not_found", "query": name_or_email})
            return json.dumps(contact, indent=2, ensure_ascii=False)
        except Exception as e:
            return tool_error("contact_get", e)

    @server.tool()
    def contact_add(name: str, email: str, notes: str = "") -> str:
        """Add or update a contact. Does NOT accept key material.

        If an existing contact's email changes, any previously linked
        fingerprint is cleared (it belonged to the old address).

        Args:
            name: Contact display name.
            email: Contact email address.
            notes: Optional free-text notes.
        """
        try:
            result = contacts.add(name=name, email=email, notes=notes)
            return json.dumps(result, indent=2, ensure_ascii=False)
        except Exception as e:
            return tool_error("contact_add", e)

    @server.tool()
    def contact_link_key(name_or_email: str) -> str:
        """Find the contact's key in the keyring by exact UID email and link it.

        Keeps key material out of the model entirely — the tool links the full
        fingerprint internally and returns only metadata. Refuses on ambiguous
        matches; resolve those with contact_set_fingerprint.

        Args:
            name_or_email: Contact name or email address.
        """
        try:
            result = contacts.find_and_link_key(name_or_email, ctx.crypto)
            return json.dumps(result, indent=2, ensure_ascii=False)
        except Exception as e:
            return tool_error("contact_link_key", e)

    @server.tool()
    def contact_set_fingerprint(name_or_email: str, fingerprint: str) -> str:
        """Manually set a contact's PGP fingerprint (full 40-char fingerprint only).

        FALLBACK: prefer contact_link_key. Short 16-char key IDs are rejected
        (Evil32 collision attack). Use the full fingerprint from gpg_list_keys.

        Args:
            name_or_email: Contact name or email address.
            fingerprint: Full 40-character hex GPG fingerprint.
        """
        try:
            result = contacts.set_fingerprint(name_or_email, fingerprint)
            return json.dumps(result, indent=2, ensure_ascii=False)
        except Exception as e:
            return tool_error("contact_set_fingerprint", e)

    @server.tool()
    def contact_clear_key(name_or_email: str, fingerprint: str) -> str:
        """Deliberately remove a contact's linked PGP fingerprint.

        FOOLPROOF against accidental clears of valid fingerprints:
          - fingerprint MUST exactly match the contact's CURRENTLY linked
            fingerprint — read it via contact_get first, pass it unchanged.
          - A mismatch is refused to prevent destroying a valid key.
          - The agent's own key can never be cleared.
          - Contacts with no linked key are a no-op, not an error.

        Args:
            name_or_email: Contact name or email address.
            fingerprint: The contact's CURRENT fingerprint, from contact_get.
        """
        try:
            result = contacts.clear_key(name_or_email, fingerprint)
            return json.dumps(result, indent=2, ensure_ascii=False)
        except Exception as e:
            return tool_error("contact_clear_key", e)

    @server.tool()
    def contact_remove(name_or_email: str) -> str:
        """Remove a contact.

        Args:
            name_or_email: Contact name or email address.
        """
        try:
            contacts.remove(name_or_email)
            return json.dumps({"status": "removed", "query": name_or_email})
        except Exception as e:
            return tool_error("contact_remove", e)


__all__ = ["register"]
