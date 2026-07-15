from datetime import datetime, timedelta, timezone

import pytest

from ravshield.enums import Verdict
from ravshield.intel import DetectionHistoryStore


VALID_SHA256 = "f" * 64
NOW = datetime.now(timezone.utc)


def test_create_first_observation():
    store = DetectionHistoryStore()

    history = store.observe(
        "SHA256",
        VALID_SHA256.upper(),
        source="File Scanner",
        verdict=Verdict.UNKNOWN,
        observed_at=NOW,
    )

    assert history.indicator_type == "sha256"
    assert history.value == VALID_SHA256
    assert history.first_seen == NOW
    assert history.last_seen == NOW
    assert history.observation_count == 1
    assert history.sources == {"File Scanner"}
    assert history.verdict_history == [Verdict.UNKNOWN]


def test_record_multiple_observations():
    store = DetectionHistoryStore()

    store.observe(
        "sha256",
        VALID_SHA256,
        source="File Scanner",
        verdict=Verdict.UNKNOWN,
        observed_at=NOW,
    )

    later = NOW + timedelta(hours=2)

    history = store.observe(
        "SHA256",
        VALID_SHA256.upper(),
        source="Threat Intelligence Feed",
        verdict=Verdict.MALICIOUS,
        observed_at=later,
    )

    assert history.observation_count == 2
    assert history.first_seen == NOW
    assert history.last_seen == later
    assert history.sources == {
        "File Scanner",
        "Threat Intelligence Feed",
    }
    assert history.verdict_history == [
        Verdict.UNKNOWN,
        Verdict.MALICIOUS,
    ]


def test_history_updates_first_seen_for_older_observation():
    store = DetectionHistoryStore()

    store.observe(
        "sha256",
        VALID_SHA256,
        source="Current Scan",
        verdict=Verdict.SUSPICIOUS,
        observed_at=NOW,
    )

    earlier = NOW - timedelta(days=5)

    history = store.observe(
        "sha256",
        VALID_SHA256,
        source="Imported Archive",
        verdict=Verdict.UNKNOWN,
        observed_at=earlier,
    )

    assert history.first_seen == earlier
    assert history.last_seen == NOW
    assert history.observation_count == 2


def test_history_lookup_and_remove():
    store = DetectionHistoryStore()

    store.observe(
        "sha256",
        VALID_SHA256,
        source="Test",
        verdict=Verdict.SAFE,
        observed_at=NOW,
    )

    assert store.get(
        "SHA256",
        VALID_SHA256.upper(),
    ) is not None

    assert store.remove(
        "sha256",
        VALID_SHA256,
    ) is True

    assert store.get(
        "sha256",
        VALID_SHA256,
    ) is None


def test_history_rejects_naive_datetime():
    store = DetectionHistoryStore()

    with pytest.raises(ValueError):
        store.observe(
            "sha256",
            VALID_SHA256,
            source="Test",
            verdict=Verdict.UNKNOWN,
            observed_at=datetime.now(),
        )


def test_history_store_tracks_unique_indicators():
    store = DetectionHistoryStore()

    store.observe(
        "sha256",
        VALID_SHA256,
        source="Test",
        verdict=Verdict.UNKNOWN,
        observed_at=NOW,
    )

    store.observe(
        "domain",
        "example.com",
        source="Test",
        verdict=Verdict.SAFE,
        observed_at=NOW,
    )

    assert len(store) == 2
    assert len(store.all()) == 2