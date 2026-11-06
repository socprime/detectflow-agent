"""Correlation-job entrypoint (Attack Chains).

Thread-mode (Pemja) PyFlink job by default — the matcher runs in-process,
sidestepping the process-mode (Beam/gRPC) first-keyed-bundle deadlock seen on
Kubernetes. Process mode is still selectable for A/B via
``CORRELATION_PYTHON_MODE=process``. It ingests tagged Sigma detections from the
tagged-events tech topic (single short-retention topic written by
detectflow-matchnode's matcher), joins them against active HoS rules + AT
definitions broadcast from detectflow-backend, groups by hostname, and emits
chain records to ``detectflow.chains-raw`` when seq-coverage crosses the
threshold.

Each event arrives with top-level ``hostname``, ``timestamp`` and
``pipeline_id`` fields — matcher-pre-parsed per logsource config — so the
operator does no ECS unwrapping. Isolation is the Kafka subscription
(``KAFKA_INPUT_TOPICS`` = the member detection pipelines' tagged-events
topics); there is no in-event destination-topic filter.

Run with (default tech topic from settings)::

    python -m app.jobs.correlation

Or override::

    python -m app.jobs.correlation --input-topics other-tech-topic
"""

import argparse
import json
import os
import sys

from dotenv import load_dotenv
from pyflink.common import Configuration, WatermarkStrategy
from pyflink.common.serialization import ByteArraySchema
from pyflink.common.typeinfo import Types
from pyflink.datastream import StreamExecutionEnvironment
from pyflink.datastream.connectors.kafka import DeliveryGuarantee
from pyflink.datastream.functions import MapFunction

from app.config.logging import get_logger
from app.config.settings import Settings, assert_distinct_job_identity, get_settings
from app.connectors.broadcast_filter import filter_and_decode_tombstones
from app.connectors.kafka_sink import create_kafka_sink
from app.connectors.kafka_source import create_kafka_source
from app.core import operator_uids
from app.jobs._flink_env import configure_flink_environment, ensure_pythonpath_for_workers
from app.observability.activity import ENTITY_NAME_CORRELATION, get_activity_reporter
from app.operators.hos_correlation_function import (
    ALL_BROADCAST_DESCRIPTORS,
    TOPIC_MARKER,
    HosCorrelationFunction,
)

load_dotenv()

logger = get_logger(__name__)

# Base Flink JOB name. `settings.flink_job_name()` suffixes it with the instance
# label so N correlation pipelines are distinguishable in the Flink UI, in
# metric scopes and in the integration tests — while the bare base survives for the
# legacy single deployment (JOB_ID=correlation-job). This is the JOB name only:
# operator uid()/name() are frozen by role in app/core/operator_uids.py and must
# stay identical across instances (they are a contract with on-disk state).
CORRELATION_JOB_BASE_NAME = "correlation-job"


class TagWithTopic(MapFunction):
    """Inject `_topic` marker into a JSON-string broadcast record.

    The matcher dispatches each broadcast record by its source topic;
    since PyFlink's SimpleStringSchema delivers values
    only, we annotate at union time per-source instead of at deserialize.
    """

    def __init__(self, topic: str):
        self._topic = topic

    def map(self, value):
        if value is None:
            return None
        try:
            payload = json.loads(value)
        except (TypeError, ValueError):
            return value  # let the matcher's JSON guard log + drop
        if isinstance(payload, dict):
            payload[TOPIC_MARKER] = self._topic
            return json.dumps(payload, separators=(",", ":"))
        return value


def _correlation_watermark_strategy() -> WatermarkStrategy:
    """No watermarks on the main source — event-time lives in the matcher.

    The KeyedBroadcastProcessFunction's operator watermark is
    min(keyed input, broadcast inputs), and the broadcast meta sources use
    ``no_watermarks()`` (no event-time semantics), so the operator watermark
    is pinned at Long.MIN **forever** regardless of what the main source
    emits. Source-side watermarks were therefore dead weight:

    - late-drop: the matcher's primary `watermark_ms > 0` check never fired;
      the per-key max-event-ts fallback clock (with its own 60s
      out-of-orderness allowance) is the ACTIVE mechanism — see
      `HosCorrelationFunction.process_element`.
    - window bucketing / coverage: computed from the event JSON `timestamp`
      directly, never from the runtime watermark.
    - cleanup timers: the matcher registers processing-time timers only
      (event-time timers behind a pinned watermark never fire and were
      removed — they leaked as checkpointed keyed state).

    The python timestamp assigner the strategy used to carry also put an
    extra python wrapper into the source chain in process mode — one more
    moving part in the Beam bundle plane for zero behavioral gain (the
    stable PyFlink reference, detectflow-matchnode's matcher, ships no
    timestamp assigner either)."""
    return WatermarkStrategy.no_watermarks()


def _hostname_key(value: str) -> str:
    """Key selector for the main stream — extract `hostname` from JSON.

    Returning an empty string for malformed events lumps them together; the
    matcher's per-element guard drops them with a counter, so the bad-key
    bucket is harmless."""
    try:
        obj = json.loads(value)
    except (TypeError, ValueError):
        return ""
    return obj.get("hostname") or ""


def _build_main_stream(env: StreamExecutionEnvironment, settings: Settings):
    """Subscribe to every tagged-events member topic through ONE source operator.

    Fixed arity is the point. Under the per-customer correlation-pipeline model
    ``kafka_input_topics`` is the comma-separated list
    of a correlation pipeline's member detection pipelines, and that list is
    edited over the pipeline's life. One ``KafkaSource`` per topic would make the
    operator count a function of the member count, so every membership change
    would change the topology — and, with ``upgradeMode: last-state``, restore
    into an incompatible graph. ``KafkaSourceBuilder.set_topics`` is varargs, so
    a single source covers all members and the member set becomes a change
    *inside* the source's own split state instead of a change to the job graph.

    Consumer-group consequence: the suffix is ``"-correlation"`` (one group), not
    ``f"-correlation-{topic}"`` (N groups). See ``create_kafka_source``'s docstring:
    Flink checkpoints hold the
    authoritative offsets, so this only re-points lag dashboards.
    """
    input_topics = settings.get_input_topics_list()
    if not input_topics:
        raise ValueError(
            "kafka_input_topics is empty — pass --input-topics or set KAFKA_INPUT_TOPICS"
        )

    # Override pinned to "latest" so a future global default change cannot
    # silently revert the runtime
    # contract (no backlog consumption on cold start).
    source = create_kafka_source(
        settings,
        input_topics,
        consumer_group_suffix="-correlation",
        starting_offset_override="latest",
    )
    logger.info("Correlation source created", topics=input_topics, source_count=1)

    # The operator NAME stays topic-free so the Flink UI is comparable across
    # correlation pipelines; the topic list is logged above instead.
    #
    # Defensive identity bridge: forces the Java Strings produced by
    # SimpleStringSchema through Python serialization before the
    # keyBy/broadcast connect. Likely removable in 2.2 thread mode (no
    # Beam type boundary to trip over); until that is verified it stays, with an explicit STRING output type so the shuffle
    # keeps the string serializer instead of downgrading to
    # PICKLED_BYTE_ARRAY.
    return (
        env.from_source(
            source=source,
            watermark_strategy=_correlation_watermark_strategy(),
            source_name="Tagged Events Source",
        )
        .uid(operator_uids.CORRELATION_TAGGED_EVENTS_SOURCE)
        .map(lambda x: x, output_type=Types.STRING())
        .uid(operator_uids.CORRELATION_TAGGED_EVENTS_BRIDGE)
        .name("Tagged Events Type Bridge")
    )


def _build_broadcast_stream(env: StreamExecutionEnvironment, settings: Settings):
    """Union the 3 meta topics into one broadcast stream, tagging each record
    with its source topic so `HosCorrelationFunction.process_broadcast_element`
    can dispatch into the right broadcast state descriptor."""
    # Keyed by ROLE, not by topic name: uids and consumer-group suffixes must be
    # identical across every correlation pipeline (the topic names become
    # per-pipeline), so one image serves all of
    # them and a topic rename never orphans operator state.
    meta_lanes: list[tuple[operator_uids.MetaRole, str]] = [
        ("active_threats", settings.kafka_active_threats_topic),
        ("hos_rules", settings.kafka_hos_rules_topic),
        ("chains_config", settings.kafka_chains_config_topic),
    ]

    streams = []
    for role, topic in meta_lanes:
        # ByteArraySchema gracefully decodes null Kafka values (compaction
        # tombstones) as Python None instead of crashing SimpleStringSchema.
        # `filter_and_decode_tombstones` then drops them and decodes valid
        # records to str (see app/connectors/broadcast_filter.py for the
        # cross-repo tombstone contract).
        source = create_kafka_source(
            settings,
            topic,
            consumer_group_suffix=f"-correlation-meta-{role}",
            starting_offset_override="earliest",
            deserializer=ByteArraySchema(),
        )
        stream = (
            env.from_source(
                source=source,
                watermark_strategy=WatermarkStrategy.no_watermarks(),
                source_name=f"Meta Source ({role})",
            )
            .uid(operator_uids.CORRELATION_META_SOURCE[role])
            .flat_map(filter_and_decode_tombstones, output_type=Types.STRING())
            .uid(operator_uids.CORRELATION_META_TOMBSTONE_FILTER[role])
            .name(f"Meta Tombstone Filter ({role})")
            .map(TagWithTopic(topic), output_type=Types.STRING())
            .uid(operator_uids.CORRELATION_META_TAG[role])
            .name(f"Meta Tag ({role})")
        )
        streams.append(stream)
        logger.info("Correlation meta source created", role=role, topic=topic)

    unioned = streams[0].union(*streams[1:]) if len(streams) > 1 else streams[0]
    return unioned.broadcast(*ALL_BROADCAST_DESCRIPTORS)


def build_pipeline(
    env: StreamExecutionEnvironment, settings: Settings, *, python_mode: str = "thread"
) -> None:
    """Wire main + broadcast sources → HosCorrelationFunction → chains-raw."""
    main_stream = _build_main_stream(env, settings)
    broadcast_stream = _build_broadcast_stream(env, settings)

    keyed = main_stream.key_by(_hostname_key, key_type=Types.STRING())

    matcher = HosCorrelationFunction(
        settings=settings,
        active_threats_topic=settings.kafka_active_threats_topic,
        hos_rules_topic=settings.kafka_hos_rules_topic,
        chains_config_topic=settings.kafka_chains_config_topic,
    )
    # uid()/name() stay adjacent to the transformation they identify; the
    # slot-sharing group is applied after. `correlation-hos-matcher` owns
    # `chain_buffers`, `key_max_event_ts_ms` and all 4 broadcast states — it is
    # the single most load-bearing uid in either job (see operator_uids.py).
    processed = (
        keyed.connect(broadcast_stream)
        .process(matcher, output_type=Types.STRING())
        .uid(operator_uids.CORRELATION_MATCHER)
        .name("HoS Correlation Matcher")
    )
    # PROCESS MODE ONLY: isolate the matcher in its own slot-sharing group so
    # it gets a DEDICATED Beam python environment. With everything in the
    # default group (one slot), all 5 python operators (4 source-side maps +
    # this co-process) share ONE python SDK harness over one control channel;
    # on Kubernetes that multiplexing deterministically wedged the FIRST
    # keyed bundle — the JVM blocks forever in ActiveBundle.close waiting for
    # a ProcessBundleResponse the harness never saw (py-spy: harness fully
    # idle; bundle threads were observed blocking in the shared
    # GetProcessBundleDescriptor unary call). The keyed stream + broadcasts
    # cross slot groups over the network exchange that already exists
    # (keyBy / broadcast), so this only costs one extra task slot (the
    # operator spawns a second TM when slots-per-TM is 1). The sink keeps the
    # same group so it stays chained to the matcher.
    # In THREAD mode (the default) there is no Beam harness to isolate — the
    # dedicated group would just cost an extra slot and force a cross-TM
    # exchange for nothing, so it is scoped to process mode.
    if python_mode == "process":
        processed = processed.slot_sharing_group("matcher")

    # AT_LEAST_ONCE (not EXACTLY_ONCE): chains-raw output must not be gated on
    # checkpoint completion (a stalled checkpoint would hide all chains), and the
    # transactional producer adds a hard dependency on the Kafka transaction
    # coordinator. Duplicates are safe — chain_id is deterministic
    # (uuid5 of correlation_pipeline_id|hos_id|hostname|window_start), so downstream dedupes idempotently.
    sink = create_kafka_sink(
        settings,
        settings.kafka_chains_raw_topic,
        delivery_guarantee=DeliveryGuarantee.AT_LEAST_ONCE,
    )
    sink_stream = (
        processed.sink_to(sink)
        .uid(operator_uids.CORRELATION_CHAINS_RAW_SINK)
        .name("Correlation Sink (chains-raw)")
    )
    if python_mode == "process":
        sink_stream.slot_sharing_group("matcher")
    logger.info(
        "Correlation sink wired",
        topic=settings.kafka_chains_raw_topic,
        slot_sharing_group="matcher" if python_mode == "process" else "(default)",
    )


def run(input_topics: list[str], job_id: str) -> None:
    ensure_pythonpath_for_workers()

    settings = get_settings()
    settings.kafka_input_topics = ",".join(input_topics)
    settings.job_id = job_id
    # Before any Kafka source exists: a job id shared with another instance
    # collapses consumer groups, EOS transactional-id prefixes and the activity
    # entity_id onto one key. See assert_distinct_job_identity for what that
    # actually breaks (and what it does not — Flink assigns partitions from the
    # JM enumerator, so nobody "steals" them).
    assert_distinct_job_identity(settings)

    logger.info("Job starting up...", job_name="Correlation Job", job_id=job_id)

    conf = Configuration()
    # Execution mode. Default `thread` (Pemja). Process mode (Beam/gRPC)
    # DEADLOCKED the first keyed bundle on Kubernetes: the JVM blocks in
    # ActiveBundle.close awaiting a ProcessBundleResponse the python harness
    # never receives (broadcast side processes fine, keyed side hangs at element
    # #1 — the gRPC state channel never delivers the first keyed ProcessBundle).
    # Reproduced across java11/java17, aligned/unaligned checkpoints, shared vs
    # isolated python env. Thread mode runs the python operator in-process
    # (no gRPC control/state/data channels) and sidesteps it entirely.
    # NB: Pemja exposes broadcast state as a Java proxy without `.keys()`, so
    # the matcher never scans broadcast state (gauges seed 0 + track deltas).
    # correlation does NOT use
    # flink-agents, so thread mode here does not conflict with anything.
    # `CORRELATION_PYTHON_MODE=process` forces the old mode for A/B.
    python_mode = os.getenv("CORRELATION_PYTHON_MODE", "thread").strip().lower()
    if python_mode not in ("process", "thread"):
        python_mode = "thread"
    if python_mode == "process":
        logger.warning(
            "CORRELATION_PYTHON_MODE=process selected — process mode (Beam/gRPC) "
            "is known to deadlock the first keyed bundle on Kubernetes (matcher "
            "never emits a chain). Use only for A/B diagnosis; "
            "thread mode is the supported default.",
        )
    conf.set_string("python.execution-mode", python_mode)
    conf.set_string("python.executable", sys.executable)
    conf.set_string("python.client.executable", sys.executable)
    # Local MiniCluster only (opt-in env var; unset on k8s where the
    # operator owns TM sizing): in process mode the matcher's dedicated
    # "matcher" slot-sharing group needs a 2nd slot, but an embedded
    # MiniCluster defaults to 1 — without this the source tasks stay
    # SCHEDULED forever. (Thread mode uses the default group and fits in 1.)
    local_slots = os.getenv("FLINK_LOCAL_TASK_SLOTS")
    if local_slots:
        conf.set_string("taskmanager.numberOfTaskSlots", local_slots)
    # Set for symmetry with agent-job (whose flink-agents execute() takes no job
    # name, making this config the only lever): the explicit `execute(job_name)`
    # below still wins, but a future execute_async path cannot regress the name.
    job_name = settings.flink_job_name(CORRELATION_JOB_BASE_NAME)
    conf.set_string("pipeline.name", job_name)
    logger.info(
        "Flink environment created",
        python_mode=python_mode,
        python_executable=sys.executable,
        local_task_slots=local_slots or "(cluster-managed)",
    )

    env = StreamExecutionEnvironment.get_execution_environment(conf)
    configure_flink_environment(env, settings)

    build_pipeline(env, settings, python_mode=python_mode)

    # Job-health "started" event on the cross-team detectflow.activity channel. Emitted
    # from the driver right before submit (status_change / info,
    # changes={status:{old:starting,new:running}}); per-worker degradation
    # alerts + heartbeats are wired inside HosCorrelationFunction. No-op when
    # kafka_activity_topic is unset. The reporter never raises into this path.
    reporter = get_activity_reporter(ENTITY_NAME_CORRELATION)
    reporter.emit_started()
    reporter.flush()

    logger.info("Job starting", job_name=job_name, job_id=settings.job_id)
    env.execute(job_name)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Attack Chains correlation job",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--job-id",
        type=str,
        default=os.getenv("JOB_ID", "local"),
        help="Job identifier — used for transactional id prefixes and metrics labels",
    )
    parser.add_argument(
        "--input-topics",
        type=str,
        default=os.getenv("KAFKA_INPUT_TOPICS"),
        help=(
            "Tagged-events tech topic(s) — comma-separated. Defaults to the "
            "settings value (typically a single canonical tech topic). "
            "Override only when sharding tagged events across multiple topics."
        ),
    )
    args = parser.parse_args()

    if args.input_topics:
        input_topics = [t.strip() for t in args.input_topics.split(",") if t.strip()]
    else:
        input_topics = get_settings().get_input_topics_list()

    if not input_topics:
        parser.error(
            "no tagged-events topic configured — set kafka_input_topics in settings "
            "or pass --input-topics"
        )

    run(input_topics=input_topics, job_id=args.job_id)


if __name__ == "__main__":
    main()
