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

from mcp_agent_mail.contacts import ContactBook, IdentityGuardError
from mcp_agent_mail.errors import tool_error


def _protected_json(e: IdentityGuardError) -> str:
    """Identity entries are immutable from the tool surface — readable refusal."""
    return json.dumps(
        {
            "status": "protected",
            "identity": e.role,
            "query": e.name,
            "reason": str(e),
        },
        indent=2,
        ensure_ascii=False,
    )


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
        """Look up one contact by name, surname, or email.

        Matching is case-insensitive and whitespace-tolerant (extra spaces
        ignored/collapsed). A full name, a name prefix, a bare surname, or
        the email address all resolve if unique enough; the first record
        whose key prefix matches wins for partial input.

        Args:
            name_or_email: Contact name, surname, or email address.
        """
        try:
            contact = contacts.get(name_or_email)
            if contact is None:
                return json.dumps({"status": "not_found", "query": name_or_email})
            return json.dumps(contact, indent=2, ensure_ascii=False)
        except Exception as e:
            return tool_error("contact_get", e)

    @server.tool()
    def contact_add(given_name: str, surname: str, email: str, notes: str = "") -> str:
        """Add or update a contact. Does NOT accept key material.

        Records are well-formed by construction: given_name and surname are
        required and form the display name. Key linking is a separate step
        (contact_link_key / contact_set_fingerprint).

        If an existing contact's email changes, any previously linked key is
        cleared (key_source='cleared', key_cleared_at=now): a key linked to
        the old address is ambiguous for the new one.

        Args:
            given_name: Contact's given (first) name.
            surname: Contact's surname (family name).
            email: Contact email address.
            notes: Optional free-text notes.
        """
        try:
            result = contacts.add(given_name=given_name, surname=surname, email=email, notes=notes)
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
        except IdentityGuardError as e:
            return _protected_json(e)
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
        except IdentityGuardError as e:
            return _protected_json(e)
        except Exception as e:
            return tool_error("contact_set_fingerprint", e)

    @server.tool()
    def contact_clear_key(name_or_email: str, fingerprint: str) -> str:
        """Deliberately remove a contact's linked PGP fingerprint (pair-matched).

        Deterministic and foolproof — the (name, fingerprint) pair must match
        the book exactly, otherwise nothing changes:
          - status='cleared': pair matched, key removed with provenance.
          - status='no_match': unknown name, keyless contact, or wrong
            fingerprint — same refusal either way, nothing changed.
          - status='protected': the name is the agent/owner identity entry;
            its key is fixed at setup and immune to tool changes.

        Read the CURRENT fingerprint via contact_get and pass it unchanged.

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
        except IdentityGuardError as e:
            return _protected_json(e)
        except Exception as e:
            return tool_error("contact_remove", e)


__all__ = ["register"]
