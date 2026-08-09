from __future__ import annotations

import re


def keyword_matches(
    text: str,
    keywords: set[str] | frozenset[str],
) -> list[str]:
    """
    Match keywords on token boundaries.

    Avoids substring false positives such as ``secure`` inside
    ``securely`` while still matching ``secure-login`` / ``/login/``.
    """

    lowered = text.lower()
    matched: list[str] = []

    for keyword in sorted(keywords):
        # Leading boundary rejects embedded tokens (``mypaypal``).
        # Trailing boundary allows numeric suffixes (``billing123``)
        # while rejecting alphabetic continuations (``securely``).
        pattern = (
            rf"(?<![a-z0-9]){re.escape(keyword.lower())}(?![a-z])"
        )

        if re.search(pattern, lowered):
            matched.append(keyword)

    return matched


def levenshtein_distance(left: str, right: str) -> int:
    if left == right:
        return 0

    if not left:
        return len(right)

    if not right:
        return len(left)

    previous = list(range(len(right) + 1))

    for i, left_char in enumerate(left, start=1):
        current = [i]

        for j, right_char in enumerate(right, start=1):
            insert_cost = current[j - 1] + 1
            delete_cost = previous[j] + 1
            replace_cost = previous[j - 1] + (
                left_char != right_char
            )
            current.append(
                min(insert_cost, delete_cost, replace_cost)
            )

        previous = current

    return previous[-1]


def brand_impersonation_matches(
    labels: list[str],
    brands: set[str] | frozenset[str],
    *,
    max_distance: int = 2,
) -> list[dict[str, object]]:
    """
    Detect near-miss brand labels commonly used in phishing domains.
    """

    matches: list[dict[str, object]] = []

    for label in labels:
        normalized = label.lower().strip("-")

        if not normalized or normalized in brands:
            continue

        if len(normalized) < 4:
            continue

        for brand in sorted(brands):
            if abs(len(normalized) - len(brand)) > max_distance:
                continue

            distance = levenshtein_distance(normalized, brand)

            if 0 < distance <= max_distance:
                matches.append(
                    {
                        "label": normalized,
                        "brand": brand,
                        "distance": distance,
                    }
                )

    return matches
