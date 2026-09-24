from __future__ import annotations

from pathlib import Path


def validate_file(value: str | Path) -> bool:
    """
    Return True when the value points to an existing regular file.
    """

    if not isinstance(value, (str, Path)):
        return False

    try:
        path = Path(value).expanduser()
    except (TypeError, ValueError):
        return False

    if not path.exists():
        return False

    if not path.is_file():
        return False

    return True