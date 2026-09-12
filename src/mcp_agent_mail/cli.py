"""
cli.py — command-line interface
==============================
Subcommands:
  serve    Run the MCP server (default). --http switches to streamable-http.
  setup    Check dependencies and GPG key presence. Never echoes a passphrase.
  doctor   Offline diagnostics (paths, deps, keyring, secret status).
           --live runs opt-in IMAP/SMTP/decrypt checks against the real account.
  keys     List GPG keys in the agent keyring.
  archive  List or search the local email archive.

The CLI is the setup/diagnosis console; it is NOT the model-facing surface.
Diagnostic output may include config paths (getpass-free), but never secret
values or key material.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys

from mcp_agent_mail import __version__


def _cmd_serve(args) -> int:
    from mcp_agent_mail.server import run

    transport = "streamable-http" if args.http else "stdio"
    run(transport=transport, host=args.host, port=args.port)
    return 0


def _cmd_setup(args) -> int:
    from mcp_agent_mail.config import Config, ConfigError
    from mcp_agent_mail.crypto import GPGCrypto

    print(f"mcp-agent-mail {__version__} — setup check\n")

    gpg = shutil.which("gpg") or shutil.which("gpg2")
    gpgconf = shutil.which("gpgconf")
    print(f"  gpg      : {gpg or 'NOT FOUND — install Gpg4win / gnupg2'}")
    print(f"  gpgconf  : {gpgconf or 'NOT FOUND — gpg-agent/keyboxd init unavailable'}")

    try:
        cfg = Config(require_secrets=False)
    except ConfigError as e:
        print(f"\n[config] {e}")
        return 1

    print(f"  backend  : {cfg.secret_backend}")
    print("\n  Secret status (values never shown):")
    for line in cfg.secret_status():
        print(f"    {line}")

    if gpg:
        try:
            crypto = GPGCrypto(cfg)
            keys = crypto.list_keys(secret=True)
            print(f"\n  Private keys in keyring: {len(keys)}")
            for k in keys:
                print(f"    {k['fingerprint']}  {', '.join(k['uids'][:1])}")
        except Exception as e:
            print(f"\n  [gpg] could not inspect keyring: {type(e).__name__}")

    print(
        "\nNext steps:\n"
        "  1. Put required values in .env (see .env.example).\n"
        "  2. Store the GPG passphrase in your credential manager (M2 backends)\n"
        "     or set SECRET_BACKEND=env for local development.\n"
        "  3. Run `mcp-agent-mail doctor` to verify, then `mcp-agent-mail` to serve."
    )
    return 0


def _cmd_doctor(args) -> int:
    from mcp_agent_mail.config import Config, ConfigError

    print(f"mcp-agent-mail {__version__} — doctor\n")

    try:
        cfg = Config(require_secrets=not args.live)
    except ConfigError as e:
        print(f"[config] {e}")
        if not args.live:
            print("\nRun with --live for live checks (requires full config).")
        return 1

    ok = True
    checks: list[tuple[str, bool, str]] = []

    checks.append(("gpg binary", bool(shutil.which("gpg") or shutil.which("gpg2")), ""))
    checks.append(("gpgconf binary", bool(shutil.which("gpgconf")), ""))
    for name, present, detail in checks:
        print(f"  [{'ok' if present else '!!'}] {name} {detail}")
        ok = ok and present

    print(f"\n  account  : {cfg.email_address}")
    print(f"  backend  : {cfg.secret_backend}")
    print(f"  contacts : {cfg.contacts_path}")
    print(f"  archive  : {cfg.archive_path}")
    print(f"  logs     : {cfg.logs_dir}")
    print(f"  pubkeys  : {cfg.pubkey_export_dir}")

    print("\n  Secret status:")
    for line in cfg.secret_status():
        mark = "ok" if line.endswith("set") else "!!"
        print(f"    [{mark}] {line}")
        if line.endswith("MISSING"):
            ok = False

    if not args.live:
        print("\nOffline checks only. Re-run with --live to test IMAP/SMTP/decrypt.")
        return 0 if ok else 1

    from mcp_agent_mail.server import build_context

    ctx = build_context(require_secrets=True)
    print("\n  Live checks:")

    try:
        msgs = ctx.email_client.check_inbox(limit=1)
        print(f"    [ok] IMAP login + INBOX ({len(msgs)} message sampled)")
    except Exception as e:
        print(f"    [!!] IMAP failed: {type(e).__name__}")
        ok = False

    try:
        keys = ctx.crypto.list_keys(secret=True)
        print(f"    [ok] keyring: {len(keys)} private key(s)")
    except Exception as e:
        print(f"    [!!] keyring inspect failed: {type(e).__name__}")
        ok = False

    print("\n  SMTP/decrypt checks require a target message and are not run here.")
    return 0 if ok else 1


def _cmd_keys(args) -> int:
    from mcp_agent_mail.config import Config
    from mcp_agent_mail.crypto import GPGCrypto

    cfg = Config(require_secrets=False)
    crypto = GPGCrypto(cfg)
    keys = crypto.list_keys(secret=args.secret)
    print(json.dumps(keys, indent=2, ensure_ascii=False))
    return 0


def _cmd_archive(args) -> int:
    from mcp_agent_mail.archive import EmailArchive
    from mcp_agent_mail.config import Config

    cfg = Config(require_secrets=False)
    archive = EmailArchive(cfg)

    if args.search:
        hits = archive.search(args.search, limit=args.limit)
        print(json.dumps(hits, indent=2, ensure_ascii=False))
    else:
        print(f"Archive file: {archive.path}")
        print(f"Archived messages: {len(archive._seen_uids)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-agent-mail",
        description="MCP server for encrypted email + PGP contact management.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command")

    p_serve = sub.add_parser("serve", help="Run the MCP server (default).")
    p_serve.add_argument("--http", action="store_true", help="Use streamable-http transport.")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.set_defaults(func=_cmd_serve)

    p_setup = sub.add_parser("setup", help="Check dependencies and key presence.")
    p_setup.set_defaults(func=_cmd_setup)

    p_doc = sub.add_parser("doctor", help="Diagnose configuration.")
    p_doc.add_argument("--live", action="store_true", help="Run live IMAP/keyring checks.")
    p_doc.set_defaults(func=_cmd_doctor)

    p_keys = sub.add_parser("keys", help="List GPG keys.")
    p_keys.add_argument("--secret", action="store_true", help="List private keys.")
    p_keys.set_defaults(func=_cmd_keys)

    p_arc = sub.add_parser("archive", help="Inspect the local email archive.")
    p_arc.add_argument("--search", default="", help="Search term.")
    p_arc.add_argument("--limit", type=int, default=20)
    p_arc.set_defaults(func=_cmd_archive)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        # Default action: serve over stdio (what MCP harnesses expect).
        args.http = False
        args.host = "127.0.0.1"
        args.port = 8000
        return _cmd_serve(args)

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())


__all__ = ["build_parser", "main"]
