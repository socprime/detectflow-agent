"""Kafka sink connector for Apache Flink"""

from typing import TYPE_CHECKING

from pyflink.common.serialization import SimpleStringSchema
from pyflink.datastream.connectors.kafka import (
    DeliveryGuarantee,
    KafkaRecordSerializationSchema,
    KafkaSink,
)

if TYPE_CHECKING:
    from app.config.settings import Settings


def create_kafka_sink(
    settings: "Settings",
    topic: str,
    *,
    delivery_guarantee: DeliveryGuarantee = DeliveryGuarantee.EXACTLY_ONCE,
    transactional_id_prefix: str | None = None,
) -> KafkaSink:
    """Create a Kafka sink for the given topic using Flink auth config.

    Args:
        settings: application settings (for bootstrap servers + auth).
        topic: target Kafka topic.
        delivery_guarantee: defaults to EXACTLY_ONCE; both job entrypoints
            pass AT_LEAST_ONCE (see the comments there).
        transactional_id_prefix: required when delivery_guarantee=EXACTLY_ONCE
            so concurrent jobs/restarts don't clash on transactional IDs.
            Falls back to ``f"{settings.job_id}-{topic}"``.
    """
    auth_props = settings.get_kafka_flink_auth_config()

    builder = (
        KafkaSink.builder()
        .set_bootstrap_servers(settings.kafka_bootstrap_servers)
        .set_record_serializer(
            # Records are produced with a NULL key — value-only serializer, no
            # key schema. Deliberate and part of the cross-team contract:
            # partitioning is the producer default
            # (sticky), so per-chain ordering is NOT guaranteed by partition
            # affinity. Ordering is handled instead by (a) the deterministic
            # chain_id + monotonic revision inside the envelope and (b) the
            # consumer's revision guard (detectflow-backend skips stored.revision >=
            # msg.revision). Do not "fix" by keying on chain_id without a
            # coordinated contract change with detectflow-backend.
            KafkaRecordSerializationSchema.builder()
            .set_topic(topic)
            .set_value_serialization_schema(SimpleStringSchema())
            .build()
        )
        .set_delivery_guarantee(delivery_guarantee)
    )

    if delivery_guarantee == DeliveryGuarantee.EXACTLY_ONCE:
        prefix = transactional_id_prefix or f"{settings.job_id}-{topic}"
        builder = builder.set_transactional_id_prefix(prefix)
        # Flink defaults the producer's transaction.timeout.ms to 1h; many
        # broker defaults cap transaction.max.timeout.ms at 15min (Kafka 4.x
        # default), causing InitProducerId failures. Cap explicitly — but it
        # MUST exceed the EOS job's checkpoint timeout (the transaction is
        # committed only when a checkpoint completes; the broker aborts any
        # transaction older than this, losing data on a slow checkpoint). The
        # agent entrypoint has a validator for it (`validate_eos_timeouts`),
        # disabled while its sink is AT_LEAST_ONCE. See
        # `flink_transaction_timeout_ms` / `agent_checkpoint_timeout_ms`.
        builder = builder.set_property(
            "transaction.timeout.ms", str(settings.flink_transaction_timeout_ms)
        )

    if settings.kafka_producer_compression_type != "none":
        builder = builder.set_property("compression.type", settings.kafka_producer_compression_type)

    for key, value in auth_props.items():
        builder.set_property(key, value)

    return builder.build()
