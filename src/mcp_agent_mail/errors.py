"""
errors.py — safe error boundary
===============================
The single channel through which tool exceptions reach the model.

Full tracebacks contain file paths, module structure, and local variable
state — none of which belongs in the model's context window. tool_error()
logs the full exception server-side (exc_info=True) and returns only the
tool name and exception class name to the caller.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def tool_error(tool_name: str, exc: Exception) -> str:
    """
    Log the full exception server-side and return a safe, sanitized string.

    The model receives only: the tool name and the exception class name.
    Exception messages are NOT included — they may contain file paths,
    key IDs, or internal state.
    """
    logger.error("[%s] unhandled exception: %s", tool_name, exc, exc_info=True)
    return f"Error in {tool_name}: {type(exc).__name__}. Check server logs for details."


__all__ = ["tool_error"]
