"""Pin the declarations consumer's Kafka topic contract.

The only declaration producer in the platform is
blueeconomy-port-interoperability, which publishes envelope v1.0 lifecycle
events to the literal topic ``trade.declarations.v1``. The default consumer
pattern must match that topic; the previous ``declarations.*`` default had
no producer and left the consumer idle forever (phase-10 audit P1).
"""

import re

from taxstamps.config import Settings
from taxstamps.events.consumer import topic_pattern_regex


def test_default_pattern_matches_real_producer_topic():
    settings = Settings()
    assert settings.kafka_declarations_topic_pattern == "trade.declarations.v1"
    rx = re.compile(topic_pattern_regex(settings.kafka_declarations_topic_pattern))
    assert rx.match("trade.declarations.v1"), "default pattern must match the real producer topic"


def test_default_pattern_rejects_unrelated_topics():
    rx = re.compile(topic_pattern_regex(Settings().kafka_declarations_topic_pattern))
    for topic in (
        "declarations.imported.v1",  # the old, producer-less default family
        "trade.declarations.v2",
        "trade.declarations.v1.dlq",
        "ports.booking.v1",
        "xtrade.declarations.v1",
    ):
        assert not rx.match(topic), f"pattern must not match {topic}"


def test_wildcard_pattern_still_supported():
    rx = re.compile(topic_pattern_regex("trade.declarations.*"))
    assert rx.match("trade.declarations.v1")
    assert not rx.match("trade.declarations")
