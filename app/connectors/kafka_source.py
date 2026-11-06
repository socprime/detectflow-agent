"""Kafka source connector for Apache Flink"""

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from pyflink.common.serialization import SimpleStringSchema
from pyflink.datastream.connectors.kafka import (
    KafkaOffsetResetStrategy,
    KafkaOffsetsInitializer,
    KafkaSource,
)

_VALID_OFFSETS = ("earliest", "latest", "committed")

if TYPE_CHECKING:
    from app.config.settings import Settings


def normalize_topics(topics: str | Sequence[str]) -> list[str]:
    """One topic or many → a non-empty, order-preserving, deduped list.

    Deduping matters: a repeated topic would be consumed twice by one source.
    """
    candidates = [topics] if isinstance(topics, str) else list(topics)
    seen: dict[str, None] = {}
    for topic in candidates:
        cleaned = topic.strip()
        if cleaned:
            seen[cleaned] = None
    if not seen:
        raise ValueError("create_kafka_source requires at least one non-empty topic")
    return list(seen)


def create_kafka_source(
    settings: "Settings",
    topics: str | Sequence[str],
    consumer_group_suffix: str = "",
    deserializer: Any = None,
    starting_offset_override: str | None = None,
) -> KafkaSource:
    """Create Kafka source with optional custom deserializer and offset override.

    Args:
        settings: Application settings with Kafka configuration.
        topics: One Kafka topic, or a sequence of them consumed by a SINGLE
            source operator. Many-topics-one-source is what keeps the job graph
            fixed-arity: correlation-job's member set changes over a correlation
            pipeline's life, and one `KafkaSource` per member would change the
            topology (and therefore every operator id) on every membership edit —
            see ``app/core/operator_uids.py``.
        consumer_group_suffix: Suffix appended to consumer group (e.g. ``"-events"``).
            Because one source now covers every member topic, the suffix is keyed by
            ROLE, not by topic name (``"-correlation"``, ``"-correlation-meta-<role>"``).
            That is safe: ``enable.auto.commit=false`` below means Flink checkpoints
            hold the authoritative offsets, so group ids only serve lag monitoring and
            the ``committed`` initializer — which neither the main source (pinned
            ``latest``) nor the meta sources (pinned ``earliest``) ever use. Kafka still
            reports lag per ``(group, topic, partition)``, and groups stay unique per
            correlation pipeline because ``job_id`` is in the id.
        deserializer: PyFlink ``DeserializationSchema`` wrapper. Must expose a
            ``_j_deserialization_schema`` attribute (Java object). Defaults to
            ``SimpleStringSchema()``.
        starting_offset_override: Starting offset — ``"earliest"``, ``"latest"``,
            or ``"committed"``. Defaults to ``settings.kafka_starting_offset``.

    Returns:
        Configured ``KafkaSource`` instance.

    Raises:
        ValueError: if ``topics`` resolves to no non-empty topic, or the starting
            offset is not one of ``earliest`` / ``latest`` / ``committed``.
    """
    resolved_topics = normalize_topics(topics)
    # Get auth config in Flink/Java format (JAAS for SASL)
    auth_props = settings.get_kafka_flink_auth_config()

    # Use override if provided, otherwise use settings
    offset_config = starting_offset_override or settings.kafka_starting_offset
    if offset_config not in _VALID_OFFSETS:
        raise ValueError(f"starting_offset must be one of {_VALID_OFFSETS}, got {offset_config!r}")

    if offset_config == "earliest":
        starting_offset = KafkaOffsetsInitializer.earliest()
    elif offset_config == "latest":
        starting_offset = KafkaOffsetsInitializer.latest()
    else:
        # Without an explicit reset strategy committed_offsets() defaults to
        # NONE: a brand-new consumer group throws NoOffsetForPartitionException
        # and crash-loops. EARLIEST makes the first deploy read the full topic
        # once, then resume from committed offsets on stateless restarts.
        starting_offset = KafkaOffsetsInitializer.committed_offsets(
            KafkaOffsetResetStrategy.EARLIEST
        )

    # Separate consumer groups per topic role; job_id keeps committed offsets
    # and lag monitoring distinct when several deployments share a cluster.
    consumer_group = f"{settings.kafka_consumer_group}-{settings.job_id}{consumer_group_suffix}"

    # Use custom deserializer if provided, otherwise default to SimpleStringSchema
    if deserializer is None:
        deserializer = SimpleStringSchema()

    builder = KafkaSource.builder()
    builder.set_bootstrap_servers(settings.kafka_bootstrap_servers)
    builder.set_topics(*resolved_topics)
    builder.set_group_id(consumer_group)
    builder.set_starting_offsets(starting_offset)
    builder.set_value_only_deserializer(deserializer)

    # Add authentication properties
    for key, value in auth_props.items():
        builder.set_property(key, value)

    # Add consumer-specific properties. NB: auto.offset.reset is force-set by
    # the KafkaSourceBuilder from the OffsetsInitializer's reset strategy —
    # setting it here would be dead config.
    builder.set_property("enable.auto.commit", "false")
    # Only read committed records. chains-raw / chains-analysed may carry
    # transactional (EXACTLY_ONCE) writes; the Kafka consumer default is
    # read_uncommitted, which surfaces records from aborted transactions
    # (e.g. an orphaned probe record in an aborted transaction can
    # crash-loop agent-job). Harmless for non-transactional
    # topics — there the LSO equals the high watermark.
    builder.set_property("isolation.level", "read_committed")

    return builder.build()
