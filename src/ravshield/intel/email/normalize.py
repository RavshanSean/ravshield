from __future__ import annotations


def normalize_email(email: str) -> str:
    """
    Normalize an email address into RavShield's canonical format.
    """

    if not isinstance(email, str):
        raise TypeError("Email must be a string.")

    normalized = email.strip().lower()

    if not normalized:
        raise ValueError("Email cannot be empty.")

    return normalized