from __future__ import annotations

from typing import Any


def resolve_email_address(target: Any) -> str | None:
    """
    Extract an email address from plain strings or message dicts.
    """

    if isinstance(target, str):
        return target

    if isinstance(target, dict) and "address" in target:
        return str(target["address"])

    return None
