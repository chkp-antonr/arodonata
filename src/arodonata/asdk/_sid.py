"""SID log hygiene (Backlog #25, #2).

A log line may name its session by a SID prefix — the first 8 characters, ``SID=[3f9a1c2e...]`` — at DEBUG (or TRACE)
only; nothing about the SID at INFO and above, and the full SID never anywhere. A prefix cannot be replayed; a full
live SID is a bearer token. Session UIDs are not secrets and stay in logs and spans at every level.
"""

from __future__ import annotations

import re

from pydantic import SecretStr

PREFIX_LENGTH = 8

# Check Point echoes the rejected SID: "Wrong session id [<SID>]. Session may be expired...".
_SESSION_ID_IN_MESSAGE = re.compile(r"(session[\s_-]*id\s*\[)[^\]]*(\])", re.IGNORECASE)


def _value(sid: SecretStr | str | None) -> str:
    return sid.get_secret_value() if isinstance(sid, SecretStr) else (sid or "")


def sid_prefix(sid: SecretStr | str | None) -> str:
    """``SID=[<first 8>...]`` for a DEBUG/TRACE log line; never use it at INFO and above."""
    value = _value(sid)
    return f"SID=[{value[:PREFIX_LENGTH]}...]" if value else "SID=[none]"


def redact_sid(text: str, sid: SecretStr | str | None) -> str:
    """Remove ``sid`` (the full value and every prefix of 8+ characters) and any SID inside a Check Point
    "session id [...]" phrase from a text that is logged or handed back (a server message or exception text)."""
    if not text:
        return text
    value = _value(sid)
    if value:
        text = text.replace(value, "***")
        for n in range(len(value) - 1, PREFIX_LENGTH - 1, -1):
            text = text.replace(value[:n], "***")
    return _SESSION_ID_IN_MESSAGE.sub(r"\1***\2", text)
