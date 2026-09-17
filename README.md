# mcp-agent-mail

Encrypted email + PGP for AI agents, as a local **MCP server**. Read, send,
and reply to GPG-encrypted mail; manage a contact book with key provenance;
archive and search everything you read.

Built to be called by any MCP-aware agent harness (Claude, opencode, etc.)
over stdio. Works with Gmail and any IMAP/SMTP provider.

> **Standalone rewrite.** This project is a clean, hardened rebuild of the
> earlier prototype, built around one hard-won invariant: consequence-critical
> bytes must **never** enter the model's context window. The prototype earned
> that invariant the hard way — a low-parameter local model reading and
> repeating high-bit key material corrupted it. This rewrite carries the
> invariant over verbatim; several deliberately-added behavioral changes are
> flagged with ⚠ below.

## Why this design

The model is the least reliable component in the pipeline. Small local models
(the ones that run on consumer hardware) occasionally mangle byte-exact data
— a quoting battle, a garbled regex, a corrupted key block. For ordinary text
that is noise; for private keys, passphrases, and ciphertext it is
unacceptable. So the design rule is:

**Anything whose bytes must not change never enters the model's context.**

That rule, not a threat model, is the primary reason for every invariant
below. They are reliability controls: they keep high-consequence data on
the side of the boundary the model cannot corrupt. The same controls also
happen to harden the tool against an untrusted model and a partially-trusted
host — useful, but derived. The primary enemy here is entropy, not malice.

There's a third, pragmatic face of the same rule: **context is the scarcest
resource on a local model, and high-entropy bytes are its worst possible
consumer.** A key block, an armored ciphertext, a base64 payload is nearly
incompressible noise — it burns tokens at maximal density and returns zero
usable signal. Keeping it out of the context window doesn't just protect its
bytes; it wins back expensive context the model would otherwise waste
repeating and re-mangling noise it was never going to use.


- **Inbound PGP key interception** — public keys that arrive by email are
  imported and linked to the sender's contact *before* the body reaches the
  model. The block is replaced by a notice, never shown.
- **No silent downgrade (⚠)** — `email_send` encrypts by default. If no key
  is on file for the recipient it **refuses to send**; the model must
  explicitly choose `encrypt=False` to send in the clear. A model that
  guesses wrong silently is worse than one that stops and asks.
- **Full fingerprints only** — 16-char key IDs are rejected everywhere
  (Evil32 collision attack).
- **Secrets are opaque** — `SecretString` wraps passphrase/password; reprs,
  logs, tracebacks show `***`. Private keys are never exported.
- **Fail-fast config (⚠)** — missing secrets abort startup with a list,
  never a warning and never a fallback default. A half-configured server is
  a guesser; fail-fast is fail-safe.
- **Immutable identity entries (⚠)** — the agent (`EMAIL_ADDRESS`) and the
  owner (`OWNER_EMAIL`) each have exactly one contact entry, fixed at setup.
  No tool can add, remove, re-key, or clear them, and the server refuses to
  start until both exist. Identity is a provisioning decision, not a model
  action.

## Tool surface

| Domain | Tools |
|---|---|
| Email | `email_check_inbox`, `email_read`, `email_send`, `email_reply` |
| Contacts | `contact_list`, `contact_get`, `contact_add`, `contact_link_key`, `contact_set_fingerprint`, `contact_clear_key`, `contact_remove` |
| GPG | `gpg_list_keys`, `gpg_encrypt`, `gpg_verify`, `gpg_export_own_pubkey`, `gpg_own_status` |
| Archive | `archive_search`, `archive_get` |
| Utility | `get_current_datetime` |

## Requirements

- Python 3.13+
- [uv](https://docs.astral.sh/uv/)
- GnuPG — **Gpg4win** on Windows, `gnupg2` on Linux/macOS
- An email account with IMAP/SMTP app-password access (Gmail: enable 2FA,
  create an app password)

## Install

```powershell
git clone <repo-url> mcp_agent_mail
cd mcp_agent_mail
uv sync
```

## Setup

1. Generate a dedicated agent PGP key pair:

   ```powershell
   gpg --full-generate-key
   ```

2. Create `.env` from the template and fill it (see `.env.example` for
   passphrase quoting pitfalls):

   ```powershell
   Copy-Item .env.example .env
   ```

   Required: `EMAIL_ADDRESS`, `OWNER_EMAIL`, `EMAIL_PASSWORD` (app password),
   `GPG_KEY_ID` (the agent key's full 40-char fingerprint),
   `GPG_PASSPHRASE`.

   > The `env` backend stores secrets in plaintext on disk. For production
   > use, follow `docs/SECURITY.md` and plan to move to a credential-store
   > backend (M2 roadmap: Windows Credential Manager / KeePassXC /
   > gpg-agent pinentry).

3. Sanity check:

   ```powershell
   uv run mcp-agent-mail setup      # deps + key presence + secret status
   uv run mcp-agent-mail doctor     # offline config diagnostics
   uv run mcp-agent-mail doctor --live   # opt-in IMAP + keyring checks
   ```

4. Provision the identity entries (see below). `doctor` shows a
   `[!!]` line and the server refuses to start until they exist.

### Identity & setup

Two contact entries pin the identity boundary of the whole system and are
**immutable from the tool surface**. They are provisioned once, by hand
(or by a future owner-facing CLI) — never created or edited by the tools:

- **Agent entry** — the record whose `email` equals `EMAIL_ADDRESS`. It is
  the agent's own identity inside the contact book and carries the agent key
  fingerprint (`GPG_KEY_ID`). Conventional surname: `agent of <owner given name>`.
- **Owner entry** — the record whose `email` equals `OWNER_EMAIL`. That is
  the human running the server.

`contact_add`, `contact_remove`, `contact_link_key`,
`contact_set_fingerprint` and `contact_clear_key` refuse to touch either
entry (status `protected`). The server fails fast at startup if an identity
email is absent or held by more than one record.

Minimal `data/contacts.json` with both identities provisioned:

```json
{
  "Hermes": {
    "added": "2026-09-13T00:00:00",
    "given_name": "Hermes",
    "surname": "agent of Chris",
    "email": "agent@example.com",
    "gpg_key_fingerprint": "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333",
    "key_source": "keyring_uid_match",
    "key_linked_at": "2026-09-13T00:00:00",
    "key_cleared_at": "",
    "notes": "",
    "updated": "2026-09-13T00:00:00"
  },
  "Chris": {
    "added": "2026-09-13T00:00:00",
    "given_name": "Chris",
    "surname": "Example",
    "email": "owner@example.com",
    "gpg_key_fingerprint": "4444555566667777888899990000AAAABBBBCCCC",
    "key_source": "keyring_uid_match",
    "key_linked_at": "2026-09-13T00:00:00",
    "key_cleared_at": "",
    "notes": "",
    "updated": "2026-09-13T00:00:00"
  }
}
```

> The `added`/`updated` timestamps are ISO 8601. `key_source` values:
> `"keyring_uid_match"`, `"manual"`, `"cleared"`.

## Usage

### Run as an MCP server (stdio — what harnesses expect)

```powershell
uv run mcp-agent-mail
```

To serve over HTTP instead:

```powershell
uv run mcp-agent-mail serve --http --port 8000
```

### Register in an MCP client

Point the client at the project — the server reads `.env` directly and does
not need the environment pre-seeded:

```json
{
  "mcpServers": {
    "mcp-agent-mail": {
      "command": "uv",
      "args": ["--project", "C:/path/to/mcp_agent_mail", "run", "mcp-agent-mail"]
    }
  }
}
```

### HTTP transport with curl (manual probing)

The HTTP mode speaks the standard MCP *streamable-http* transport. A raw
HTTP call is **not** a single request-response: MCP is session-based. You
initialize, then send JSON-RPC messages that carry an `Mcp-Session-Id`
header, and results come back as **Server-Sent Events**
(`text/event-stream`), not plain JSON.

Start the server:

```powershell
uv run mcp-agent-mail serve --http --port 8000
```

**1. Initialize the session** — the `mcp-session-id` header in the
response is the session token for every following call:

```bash
curl -s -D - -X POST http://127.0.0.1:8000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"curl-test","version":"1.0"}}}'
```

**2. Signal the client is initialized** (protocol requirement; produces
no response body):

```bash
curl -s -X POST http://127.0.0.1:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <session-id>" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'
```

**3. Call a tool** — list the three most recent inbox messages:

```bash
curl -s -X POST http://127.0.0.1:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <session-id>" \
  -d '{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"email_check_inbox","arguments":{"limit":3}}}'
```

The result arrives as an SSE frame; the useful payload is the `"text"`
field inside the JSON (example, sanitized):

```
event: message
data: {"jsonrpc":"2.0","id":2,"result":{"content":[{"text":"{\n  \"folder\": \"INBOX\",\n  \"count\": 1,\n  \"messages\": [\n    {\n      \"uid\": \"100\",\n      \"folder\": \"INBOX\",\n      \"from\": \"John Smith <john.smith@example.com>\",\n      \"to\": \"agent@example.com\",\n      \"subject\": \"Hello\",\n      \"date\": \"Tue, 01 Jan 2026 10:00:00 +0100\"\n    }\n  ]\n}","type":"text"}],"isError":false}}
```

Reading runs the same PGP pipeline as stdio: inbound ciphertext is
decrypted, sender key blocks are intercepted and linked in the contact
book, and key material never reaches you as raw bytes:

```bash
curl -s -X POST http://127.0.0.1:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <session-id>" \
  -d '{"jsonrpc":"2.0","method":"tools/call","id":3,"params":{"name":"email_read","arguments":{"uid":"100"}}}'
```

> stdio is what MCP harnesses expect and what the server runs by default.
> HTTP serves manual probing, remote access, and web-based clients — it
> changes the transport only, never which tools are exposed.

### Tighten your harness's tool-use prompt

Small local models occasionally misread an otherwise-unambiguous tool contract
on first use — e.g. batching two local MCP calls into one invocation array and
getting the batch rejected. Don't fight this in the server; fix it in the
harness. Add a one-line tool-use rule to the harness's always-injected context
(`SOUL.md`, `AGENTS.md`, `CLAUDE.md`, `.cursorrules` — whichever the harness
loads from *user-owned* data, so updates don't clobber it):

> One local tool invocation is exactly one entry per `tool_call`; only
> `connectors__`-type names may be batched together. Mixed or multi-local
> batches are rejected.

The rule costs tokens once per session prefix, not per call, and removes the
whole class of first-tool-call failures.

### CLI commands

| Command | Purpose |
|---|---|
| `serve` *(default)* | Run the MCP server. `--http --port` for streamable-http |
| `setup` | Check dependencies, key presence, secret status, identity setup |
| `doctor` | Offline diagnostics; `--live` runs IMAP/keyring checks |
| `keys` | List keyring keys (`--secret` for private keys) |
| `archive` | Inspect the JSONL archive (`--search <term>`) |

## Development

```powershell
uv run ruff check .
uv run pytest -q
```

127 tests cover: secret handling, fail-fast config, identity immutability,
fingerprint/key-block validation, contact provenance, archive dedup/search,
the outbound encryption gate, and the full tool surface. No `.env` or real
account is needed — tests seed fake secrets and mock the transports.

## Configuration reference

| Var | Default | Purpose |
|---|---|---|
| `EMAIL_ADDRESS` | — *(required)* | Agent account identity / IMAP+SMTP login |
| `OWNER_EMAIL` | — *(required)* | Owner (human) identity entry holder |
| `EMAIL_PASSWORD` | — *(required)* | IMAP/SMTP app password |
| `GPG_KEY_ID` | — *(required)* | Agent key fingerprint (40 hex) |
| `GPG_PASSPHRASE` | — *(required)* | Agent key passphrase |
| `SECRET_BACKEND` | `env` | Secret resolution backend (M2: more) |
| `IMAP_HOST` / `IMAP_PORT` | `imap.gmail.com` / `993` | IMAP (SSL) |
| `SMTP_HOST` / `SMTP_PORT` | `smtp.gmail.com` / `587` | SMTP (STARTTLS) |
| `SMTP_USE_SSL` | `false` | Set `true` for implicit TLS on 465 |
| `EMAIL_DISPLAY_NAME` | `AI Agent` | From display name |
| `CONTACTS_PATH` | `data/contacts.json` | Relative to project root |
| `ARCHIVE_PATH` | `data/archive.emails.jsonl` | JSONL mail archive |
| `LOGS_DIR` | `logs` | Rotating DEBUG logs (5×5 MB) |
| `PUBKEY_EXPORT_DIR` | `exported_keys` | Where public keys are exported |
| `GPG_HOME` | *(blank = system default)* | Must be blank or absolute |

## Documentation

- `docs/SECURITY.md` — threat model, guarantees, trade-offs
- `docs/ARCHITECTURE.md` — module map and data flow

## License

MIT © 2026 Christof Milius
