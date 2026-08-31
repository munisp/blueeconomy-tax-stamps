"""Pin the declarations consumer's Kafka topic contract.

The only declaration producer in the platform is
blueeconomy-port-interoperability, which publishes envelope v1.0 lifecycle
events to the literal topic ``trade.declarations.v1``. The default
subscription pattern set must match that topic; the bare ``declarations.*``
family had no producer when the consumer idled (phase-10 audit P1) and is
retained by WP-1 as a wildcard alongside the real topic.
"""

import re

import pytest

from taxstamps.config import Settings
from taxstamps.events.consumer import topic_patterns_regex


def _default_regex() -> re.Pattern:
    return re.compile(topic_patterns_regex(Settings().kafka_declarations_topic_patterns))


def test_default_patterns_include_real_producer_topic():
    settings = Settings()
    assert "trade.declarations.v1" in settings.kafka_declarations_topic_patterns
    rx = _default_regex()
    assert rx.match("trade.declarations.v1"), "default patterns must match the real producer topic"


def test_default_patterns_reject_unrelated_topics():
    rx = _default_regex()
    for topic in (
        "trade.declarations.v2",
        "trade.declarations.v1.dlq",
        "ports.booking.v1",
        "xtrade.declarations.v1",
        "trade.declarations",
    ):
        assert not rx.match(topic), f"patterns must not match {topic}"


def test_wildcard_pattern_still_supported():
    rx = re.compile(topic_patterns_regex(("trade.declarations.*",)))
    assert rx.match("trade.declarations.v1")
    assert not rx.match("trade.declarations")


def test_empty_pattern_set_fails_closed():
    with pytest.raises(RuntimeError):
        topic_patterns_regex(())
