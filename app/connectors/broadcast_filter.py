"""Tombstone filter for compacted broadcast sources.

PyFlink 2.2 Python API only exposes `KafkaSource.set_value_only_deserializer`
— there is NO surface for reading the Kafka record key from Python. As a
result, when detectflow-backend emits a true Kafka tombstone (`producer.send(topic,
key=X, value=null)`), the matcher cannot attribute the deletion to a
specific entity from the value alone. The same constraint applies in
`detectflow-matchnode` and is the reason the existing platform-wide convention
is two-phase delete (logical envelope + Kafka tombstone), not Kafka
tombstones alone.

Cross-repo contract (mirrors the production pattern in
`detectflow-backend/apps/modules/kafka/rules.py:_prepare_logical_delete_message`
+ `_prepare_tombstone_message`, consumed by `detectflow-matchnode`'s
`sigma_broadcast.py`):

- **Phase 1 — Logical-delete envelope** is the deletion signal Flink
  acts on. The backend emits `key=X, value={"id": X, "deleted": true}`
  to the broadcast topic. The matcher reads `id` from the envelope and
  removes the entry from broadcast state (and the inverted index, for
  hos-rules).
- **Phase 2 — Kafka null-value tombstone** (`value=null`) is for log
  compaction only. This filter drops it at the deserializer so it never
  reaches the matcher's `process_broadcast_element`.

The order matters: detectflow-backend must emit Phase 1 BEFORE Phase 2. The
producer pair (`KafkaActiveThreatsProducer`, `KafkaHosRulesProducer`,
`KafkaChainsConfigProducer`) is detectflow-backend's responsibility and follows
the `KafkaRulesProducer` template that is already in production for
sigma-rules.
"""

from __future__ import annotations


def filter_and_decode_tombstones(value: bytes | None):
    """flat_map helper: drop null/empty Kafka values, decode bytes → str.

    Kafka tombstones (`value=null`) arrive as `None`; empty payloads are
    indistinguishable from tombstones for our purposes and are also
    dropped — detectflow-backend never emits a legitimately-empty envelope.
    """
    if not value:
        return []
    return [value.decode("utf-8")]
