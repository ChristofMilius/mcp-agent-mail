# Security Model

## Threat model

The primary threat this design engineers against is **the model's own
fallibility**: an LLM — often a low-parameter local model — that can corrupt
consequence-critical data (private keys, passphrases, ciphertext) merely by
handling it. This is not hypothetical; the prototype demonstrated it in
practice. Everything here is arranged so that byte-exact material **never
enters the model's context window** in the first place.

Adversarial readings are secondary concerns that the same arrangement
satisfies:

- **The model as adversary** — an opaque, remotely-controlled consumer of the
  MCP tool surface that must not obtain key material, passphrases, or
  plaintext it is not entitled to.
- **Local processes** reading default-permission files.
- **Network observers** on the wire.

We optimize for **no accidental corruption or exposure** over convenience.
Where a feature would demand loosening a guarantee, the feature is excluded.
Reliability first; secrecy is a stricter consequence of the same rule.

## Guarantees

### 1. Secrets never enter the model context

- `SecretString` wraps passphrase and app password. `repr`, `str`, logging,
  and tracebacks always show `***`. JSON serialization and pickling raise.
- Equality is constant-time (`hmac.compare_digest`).
- `gpg_own_status` reports only booleans/identifiers, never values.
- `email_read` never returns attachment payloads, keys, or ciphertext.

### 2. Private key material is never exported, decrypted to the model, or shown

- No `gpg_decrypt` tool. No `export_secret_key`. Key material cannot be
  requested through any tool.
- Public-key export writes to disk (`PUBKEY_EXPORT_DIR`) and returns only
  the file path, fingerprint, and byte size.
- Inbound PGP public keys are stripped from bodies before the model sees
  them and imported/linked server-side.

### 3. No silent plaintext downgrade

- `email_send(encrypt=True)` with no recipient key **refuses to send** with
  an explanatory error. Sending in the clear requires explicit
  `encrypt=False`.
- Missing secrets abort startup. There are no fallback defaults anywhere.

### 4. Ambiguity is refused, not guessed

- Only full 40-char fingerprints are accepted; short key IDs (16 hex) are
  rejected everywhere (Evil32 collision attack).
- `contact_link_key` matches by exact UID email and **refuses** when multiple
  keys match an address — the model must resolve with a full fingerprint.
- `contact_clear_key` refuses to clear unless the caller passes the contact's
  **current linked fingerprint unchanged** (from `contact_get`), and refuses
  outright to clear the agent's own key. Clearing the wrong record fails.
- Contact records track provenance: `key_source` and `key_linked_at`.

### 5. Error boundaries

- Tool exceptions return only `{tool}: {ExceptionType}`. Tracebacks (file
  paths, key IDs, variable state) are logged server-side at DEBUG level only.
- gnupg stderr is never forwarded; a whitelist of safe status strings
  determines the surfaced message, anything else becomes
  `operation failed`.

## Attack surfaces and mitigations

| Surface | Mitigation |
|---|---|
| gpg subprocess | `--batch`, `--no-autostart`, `--pinentry-mode loopback`; passphrase via stdin; GPG_HOME chmod 0o700 |
| Key import | Structural marker validation in Python before gnupg runs; private-key markers rejected |
| Secret files `.env` | Documented as plaintext; M2 credential-store backends |
| Log files | Rotating, DEBUG-only server-side; do not put on shared volumes |
| Archive file | Plaintext JSONL by design (the agent's own mail store); point `ARCHIVE_PATH` at an encrypted volume for at-rest encryption |
| Public key files | Exported `0o644` — public by definition |

## Intentional trade-offs

- **The archive is plaintext.** It is the lookup that makes `email_read`'s
  2000-char body cap non-lossy. Bodies are stored **after** decryption and
  key interception, so keys and ciphertext never land in it. Encrypted
  volume recommended.
- **`env` backend is not production-ready.** Secrets in `.env` sit in
  plaintext. M2 adds Windows Credential Manager (DPAPI), KeePassXC,
  gpg-agent pinentry caching, and SecretService. Same `SecretProvider`
  interface, no model-visible change.
- **Logs include email addresses and subjects.** Needed for audit; no
  passphrases or key material ever.

## Operational checklist

1. Generate a **dedicated agent keypair**; use its fingerprint in
   `GPG_KEY_ID`.
2. Use a Gmail **app password**, never the account password.
3. Run with `SECRET_BACKEND=env` only on a machine whose disk you trust.
4. Keep `data/`, `logs/`, `exported_keys/` out of version control
   (`.gitignore` does this).
5. For M2: move passphrase & app password into a credential store and switch
   `SECRET_BACKEND`. The model-facing behavior does not change.