# mcp-agent-mail

Encrypted email + PGP for AI agents, as a local **MCP server**. Read, send,
and reply to GPG-encrypted mail; manage a contact book with key provenance;
archive and search everything you read.

Built to be called by any MCP-aware agent harness (Claude, opencode, etc.)
over stdio. Works with Gmail and any IMAP/SMTP provider.

> **Standalone rewrite.** This project is a clean, security-hardened
> rebuild of the earlier prototype. Core security invariants were carried
> over verbatim; several deliberately-added behavioral changes are flagged
> with ⚠ below.

## Why this design

Keys and bodies must **never** reach the model's context window:

- **Inbound PGP key interception** — public keys that arrive by email are
  imported and linked to the sender's contact *before* the body reaches the
  model. The block is replaced by a notice, never shown.
- **No silent downgrade (⚠)** — `email_send` encrypts by default. If no key
  is on file for the recipient it **refuses to send**; the model must
  explicitly choose `encrypt=False` to send in the clear.
- **Full fingerprints only** — 16-char key IDs are rejected everywhere
  (Evil32 collision attack).
- **Secrets are opaque** — `SecretString` wraps passphrase/password; reprs,
  logs, tracebacks show `***`. Private keys are never exported.
- **Fail-fast config (⚠)** — missing secrets abort startup with a list,
  never a warning and never a fallback default.

## Tool surface

| Domain | Tools |
|---|---|
| Email | `email_check_inbox`, `email_read`, `email_send`, `email_reply` |
| Contacts | `contact_list`, `contact_get`, `contact_add`, `contact_link_key`, `contact_set_fingerprint`, `contact_remove` |
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

   Required: `EMAIL_ADDRESS`, `EMAIL_PASSWORD` (app password),
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

### CLI commands

| Command | Purpose |
|---|---|
| `serve` *(default)* | Run the MCP server. `--http --port` for streamable-http |
| `setup` | Check dependencies, key presence, secret status |
| `doctor` | Offline diagnostics; `--live` runs IMAP/keyring checks |
| `keys` | List keyring keys (`--secret` for private keys) |
| `archive` | Inspect the JSONL archive (`--search <term>`) |

## Development

```powershell
uv run ruff check .
uv run pytest -q
```

101 tests cover: secret handling, fail-fast config, fingerprint/key-block
validation, contact provenance, archive dedup/search, the outbound encryption
gate, and the full tool surface. No `.env` or real account is needed — tests
seed fake secrets and mock the transports.

## Configuration reference

| Var | Default | Purpose |
|---|---|---|
| `EMAIL_ADDRESS` | — *(required)* | Account identity / IMAP+SMTP login |
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