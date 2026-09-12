# Architecture

## Module map

```
src/mcp_agent_mail/
├── __init__.py        entry → cli.main(); __version__
├── __main__.py        python -m mcp_agent_mail
├── cli.py             argparse: serve (default) / setup / doctor / keys / archive
├── server.py          wires everything into AppContext + MCPServer
├── context.py         frozen AppContext dataclass (the object graph)
├── config.py          Config — fail-fast, path resolution, masked repr
├── secrets.py         SecretString — opaque sensitive-value wrapper
├── logging_setup.py   rotating DEBUG file log + INFO console
├── errors.py          tool_error() — sanitized exception boundary
├── crypto.py          GPGCrypto — python-gnupg wrapper, agent+keyboxd init
├── contacts.py        ContactBook — JSON store, provenance, fingerprint rules
├── archive.py         EmailArchive — append-only JSONL, dedup by uid
├── email_client.py    EmailClient + KeyBlockStore — IMAP/SMTP, interception
├── secret_provider/   SecretProvider seam (M1: env backend)
│   ├── base.py        Protocol + MissingSecretError
│   ├── env_provider.py
│   ├── registry.py    SECRET_BACKEND selection; roadmap backends error
│   └── __init__.py
└── tool_surface/      one module per domain, register(server, ctx)
    ├── __init__.py    register_all()
    ├── email_tools.py
    ├── contacts_tools.py
    ├── crypto_tools.py
    ├── archive_tools.py
    └── misc_tools.py
tests/                 101 tests; seeded fake secrets, mocked transports
```

## Object graph

`server.build_context()` constructs dependencies bottom-up and freezes them
into an `AppContext`:

```
Config ──► logging          (called first, once)
Config ──► GPGCrypto        (starts gpg-agent + keyboxd)
Config ──► ContactBook      (loads data/contacts.json)
Config ──► EmailArchive     (loads uid index)
             \              (archive=)
Config ──► EmailClient ─────┘  (KeyBlockStore wired in)
AppContext(cfg, crypto, contacts, email_client, archive)
        ▲
register_all(server, ctx)   — tools close over ctx
```

## Data flow

### Reading mail (`email_read`)

```
IMAP fetch(RFC822)
   → _extract_body()        plain part(s) + attachment METADATA
   → KeyBlockStore.process()   find PGP public key blocks
        import_key() + link to sender contact + strip block
   → PGP MESSAGE present?  → crypto.decrypt()
   → archive.record()       full decrypted+sanitized body (dedup by uid)
   → body capped at 2000   + archive_notice → model
```

Order matters: the archive stores the **full** body so `archive_get` can
recover what `email_read` truncated, but only AFTER key interception and
decryption, and a `decrypt_failed` record stores an empty body.

### Sending mail (`email_send`)

```
contact resolve → recipient email + fingerprint?
   encrypt=True, no fingerprint  → REFUSE (explicit error)
   encrypt=True, fingerprint     → crypto.encrypt(body, fp)
   encrypt=False                 → plaintext, gpg_status=not_encrypted
sign with agent GPG_KEY_ID       (never the recipient's key)
SMTP login + sendmail
result: status / gpg_status / encryption_note
```

## Security-relevant decisions

| Decision | Where | Why |
|---|---|---|
| `SecretString` everywhere | `secrets.py` | Repr/log/traceback-proof secret carrier |
| `_tool_error` returns type only | `errors.py` | Tracebacks leak structure and values |
| Fail-fast `Config` | `config.py` | No half-configured server |
| No `gpg_decrypt` / secret export | surface + `crypto.py` | No legitimate path; removed on purpose |
| Fingerprint validator strips spaces, requires 40 hex | `crypto.py` | Accept gpg output, reject short IDs |
| KeyBlockStore before model | `email_client.py` | Keys never reach context |
| Outbound gate | `email_client.py` | No silent downgrade |
| Contact key provenance | `contacts.py` | Zero ambiguity about which key, linked when |
| Archive dedup by uid | `archive.py` | Idempotent reads |
| Secret provider seam | `secret_provider/` | M1 env, M2 stores, same surface |

## Transport notes

- `MCPServer` (mcp 2.x) runs `stdio` by default, or `streamable-http` with
  `--http`. `sse` is supported by the framework.
- SMTP default is STARTTLS on 587; `SMTP_USE_SSL=true` selects implicit TLS
  on 465.
- `GPG_HOME` must be blank or absolute (Windows gpg-agent socket path limit).
  GPGCrypto launches `gpg-agent` **and** `keyboxd` at construction — GnuPG
  2.3 cannot find secret keys without the keybox daemon running.