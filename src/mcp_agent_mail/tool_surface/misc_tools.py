"""
misc_tools — utility tools
==========================
get_current_datetime: the model has no reliable clock; this gives it one.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime


def register(server, ctx) -> None:
    @server.tool()
    def get_current_datetime() -> str:
        """Return the current local and UTC date/time in ISO 8601 format."""
        now_local = datetime.now()
        return json.dumps(
            {
                "local": now_local.isoformat(),
                "utc": datetime.now(UTC).isoformat(),
                "weekday": now_local.strftime("%A"),
            },
            indent=2,
        )


__all__ = ["register"]
