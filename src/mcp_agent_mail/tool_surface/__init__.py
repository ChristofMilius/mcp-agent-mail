"""
tool_surface — MCP tool registration
====================================
Each module owns one domain and exposes a register(server, ctx) function
that attaches its tools to the MCPServer via closures over the AppContext.

Splitting by domain keeps each file small and testable. server.py composes
them; nothing here reads module globals or constructs its own dependencies.

Every tool:
  - returns a JSON string (json.dumps) — the model always gets structured data
  - routes unexpected exceptions through errors.tool_error() so tracebacks
    stay server-side
  - never returns key material, secrets, or file paths

Call auditing:
  register_all() hands every registrar an _AuditedServer whose @tool() wraps
  each handler so the mcp_agent_mail.tool_surface logger records a DEBUG line
  per call (also emitted by the file handler in logs/): tool name, argument
  name/value pairs, duration, and result size. This is what makes missing or
  malformed lookups diagnosable after the fact (e.g. a contact_get that
  returned not_found). Argument reprs and the result preview are capped so
  audit lines stay bounded even for email bodies or long listings.
"""

from __future__ import annotations

import functools
import inspect
import logging
import time
from collections.abc import Callable

from mcp_agent_mail.tool_surface import (
    archive_tools,
    contacts_tools,
    crypto_tools,
    email_tools,
    misc_tools,
)

logger = logging.getLogger(__name__)

# Bounds so audit lines never balloon: argument reprs and the result preview.
_MAX_ARG_CHARS = 200
_MAX_RESULT_PREVIEW = 120


def _short(value, limit=_MAX_ARG_CHARS) -> str:
    """repr() a value, truncated at `limit` with a cut suffix."""
    rendered = repr(value)
    if len(rendered) <= limit:
        return rendered
    return rendered[:limit] + f"...(+{len(rendered) - limit} chars cut)"


def _audit(fn: Callable) -> Callable:
    """
    Wrap a tool handler so every invocation is logged at DEBUG.

    Logs the tool name, its argument name/value pairs (hence diagnosable
    queries like ('contact_get', name_or_email='John  Smith')), the
    duration, and the result size / preview. Exceptions are logged here and
    re-raised unchanged so error handling stays in the tool's try/except.
    """
    tool_name = fn.__name__
    params = list(inspect.signature(fn).parameters.values())
    base = logger

    def _describe(args, kwargs) -> str:
        bound = []
        for i, param in enumerate(params):
            if i < len(args):
                bound.append(f"{param.name}={_short(args[i])}")
            elif param.name in kwargs:
                bound.append(f"{param.name}={_short(kwargs[param.name])}")
        return " ".join(bound) if bound else "(no args)"

    def _record_outcome(start, result=None, error=None):
        elapsed = time.perf_counter() - start
        if error is not None:
            base.debug(
                "[tool %s] raised %s: %s in %.3fs",
                tool_name, type(error).__name__, _short(str(error)), elapsed,
            )
        else:
            rendered = str(result)
            base.debug(
                "[tool %s] result %d chars in %.3fs: %s",
                tool_name, len(rendered), elapsed, _short(rendered[:_MAX_RESULT_PREVIEW]),
            )

    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_wrapper(*args, **kwargs):
            start = time.perf_counter()
            base.debug("[tool %s] call %s(%s)", tool_name, tool_name, _describe(args, kwargs))
            try:
                result = await fn(*args, **kwargs)
            except Exception as e:
                _record_outcome(start, error=e)
                raise
            _record_outcome(start, result=result)
            return result

        return async_wrapper

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        base.debug("[tool %s] call %s(%s)", tool_name, tool_name, _describe(args, kwargs))
        try:
            result = fn(*args, **kwargs)
        except Exception as e:
            _record_outcome(start, error=e)
            raise
        _record_outcome(start, result=result)
        return result

    return wrapper


class _AuditedServer:
    """
    Read-only forwarding stand-in handed to registrars.

    Only server.tool() is used by the registrars; the underlying MCPServer
    (or a test FakeServer) is never mutated. @tool() decorations on the
    returned proxy wrap the handler with _audit before the real registration.
    """

    def __init__(self, inner):
        self._inner = inner

    def tool(self, *args, **kwargs):
        def decorator(fn: Callable) -> Callable:
            return self._inner.tool(*args, **kwargs)(_audit(fn))

        return decorator


def register_all(server, ctx) -> None:
    """Register every domain's tools on the given MCPServer, audited."""
    server = _AuditedServer(server)
    misc_tools.register(server, ctx)
    email_tools.register(server, ctx)
    contacts_tools.register(server, ctx)
    crypto_tools.register(server, ctx)
    archive_tools.register(server, ctx)


__all__ = ["register_all"]
