"""HosCorrelationFunction — operator-level behaviour over stub Flink contexts.

The pure helpers (sigma_index, chain_buffer, chain_record, chain_id) already
have dedicated unit tests. Here we verify the orchestration: broadcast routing
with the `_topic` marker, drop counters, AT.enabled gate, threshold emission,
revision monotonicity for the same window, deterministic chain_id, and the
on_timer cleanup path.
"""

from __future__ import annotations

import json
import uuid

import pytest

import app.observability.activity as activity_mod
from app.config.settings import Settings
from app.core.chain_id import build_chain_id
from app.observability.activity import ActivityReporter, reset_activity_reporter
from app.operators.hos_correlation_function import (
    AT_STATE,
    CONFIG_STATE,
    HOS_RULES_STATE,
    SIGMA_INDEX_STATE,
    HosCorrelationFunction,
)

# ---------------------------------------------------------------------------
# Stub Flink runtime
# ---------------------------------------------------------------------------


class StubMapState:
    def __init__(self):
        self._data: dict = {}

    def get(self, k):
        return self._data.get(k)

    def put(self, k, v):
        self._data[k] = v

    def remove(self, k):
        self._data.pop(k, None)

    def keys(self):
        return list(self._data.keys())

    def items(self):
        return list(self._data.items())

    def __contains__(self, k):
        return k in self._data


class StubValueState:
    """Single-slot ValueState. Tests in this module use one hostname per case
    so a single slot models keyed state correctly; cross-key fan-out is
    exercised on the live cluster (tests/integration/test_late_drop.py)."""

    def __init__(self):
        self._value = None

    def value(self):
        return self._value

    def update(self, v):
        self._value = v

    def clear(self):
        self._value = None


class StubBroadcastCtx:
    def __init__(self, states: dict):
        self._states = states

    def get_broadcast_state(self, descriptor):
        return self._states[descriptor.get_name()]


class StubTimerService:
    def __init__(self, watermark_ms: int = 0, processing_time_ms: int = 0):
        self.registered: list[int] = []
        self.registered_processing: list[int] = []
        self._watermark_ms = watermark_ms
        self._processing_time_ms = processing_time_ms

    def register_event_time_timer(self, ts_ms: int):
        self.registered.append(ts_ms)

    def register_processing_time_timer(self, ts_ms: int):
        self.registered_processing.append(ts_ms)

    def current_watermark(self) -> int:
        return self._watermark_ms

    def current_processing_time(self) -> int:
        return self._processing_time_ms

    def set_watermark(self, ts_ms: int) -> None:
        self._watermark_ms = ts_ms


class StubKeyedCtx(StubBroadcastCtx):
    def __init__(
        self,
        states: dict,
        current_key: str = "host",
        watermark_ms: int = 0,
        processing_time_ms: int = 0,
    ):
        super().__init__(states)
        self._current_key = current_key
        self._timer_service = StubTimerService(
            watermark_ms=watermark_ms, processing_time_ms=processing_time_ms
        )

    def timer_service(self):
        return self._timer_service

    def get_current_key(self):
        return self._current_key


class StubOnTimerCtx(StubKeyedCtx):
    """on_timer context exposing the firing time_domain (PROCESSING_TIME / EVENT_TIME)."""

    def __init__(
        self,
        states: dict,
        *,
        processing: bool,
        processing_time_ms: int = 0,
        current_key: str = "host",
    ):
        super().__init__(states, current_key=current_key, processing_time_ms=processing_time_ms)
        from pyflink.datastream import TimeDomain

        self._time_domain = TimeDomain.PROCESSING_TIME if processing else TimeDomain.EVENT_TIME

    def time_domain(self):
        return self._time_domain


class StubRuntimeContext:
    def __init__(self):
        self._map_states: dict = {}
        self._value_states: dict = {}

    def get_map_state(self, descriptor):
        name = descriptor.get_name()
        self._map_states.setdefault(name, StubMapState())
        return self._map_states[name]

    def get_state(self, descriptor):
        name = descriptor.get_name()
        self._value_states.setdefault(name, StubValueState())
        return self._value_states[name]

    def get_metrics_group(self):
        # Return None equivalent — Metrics() in stub mode handles None root.
        return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


AT_TOPIC = "detectflow.active-threats"
HOS_TOPIC = "detectflow.hos-rules"
CONFIG_TOPIC = "detectflow.chains-config"
# Bare correlation_pipelines.id UUID — identity only, never a topic/chain_id input.
PIPELINE_UUID = "3f2b8c14-9f6a-4c3d-8f21-2a7b5c9d1e04"


def _settings(**overrides) -> Settings:
    base: dict = {
        "kafka_bootstrap_servers": "dummy",
        "kafka_auth_method": "PLAINTEXT",
        "chain_coverage_threshold_pct": 60,
        # Most tests in this module pin the legacy emit-per-event behavior;
        # the debounce suite opts in explicitly via _make_op(...) overrides.
        "chain_reemit_debounce_seconds": 0,
    }
    base.update(overrides)
    return Settings(**base)


def _make_op(**setting_overrides) -> tuple[HosCorrelationFunction, dict, StubRuntimeContext]:
    op = HosCorrelationFunction(
        settings=_settings(**setting_overrides),
        active_threats_topic=AT_TOPIC,
        hos_rules_topic=HOS_TOPIC,
        chains_config_topic=CONFIG_TOPIC,
    )
    states = {
        HOS_RULES_STATE.get_name(): StubMapState(),
        AT_STATE.get_name(): StubMapState(),
        CONFIG_STATE.get_name(): StubMapState(),
        SIGMA_INDEX_STATE.get_name(): StubMapState(),
    }
    rc = StubRuntimeContext()
    op.open(rc)
    # Replace the metrics with a fresh stub-mode Metrics tied to no JVM —
    # default ctor already does this; ensure we can introspect after.
    return op, states, rc


def _broadcast(op, states, msg_with_topic: dict):
    """Drive process_broadcast_element through the stub ctx, swallowing the
    generator (broadcast handler does not yield)."""
    bctx = StubBroadcastCtx(states)
    raw = json.dumps(msg_with_topic)
    list(op.process_broadcast_element(raw, bctx) or [])


def _process(
    op, states, event: dict, *, watermark_ms: int = 0, processing_time_ms: int = 0
) -> list[dict]:
    kctx = StubKeyedCtx(states, watermark_ms=watermark_ms, processing_time_ms=processing_time_ms)
    out = list(op.process_element(json.dumps(event), kctx) or [])
    return [json.loads(x) for x in out]


# ---------------------------------------------------------------------------
# Activity-reporter test rig
# ---------------------------------------------------------------------------
#
# The operator obtains its job-health reporter from the per-process singleton
# get_activity_reporter() in open(). The accessor is built from get_settings()
# (env-based), whose default activity topic is non-empty — so without isolation
# a unit test would open a real confluent_kafka.Producer against the configured
# broker. The autouse fixture below installs a DISABLED no-op reporter as the
# singleton, keeping every existing test broker-free, and the activity-specific
# tests opt into an enabled stub-backed reporter via _install_stub_reporter().


class _StubProducer:
    """Captures produced records instead of talking to a broker."""

    def __init__(self, _config):
        self.produced: list[tuple] = []

    def produce(self, topic, key=None, value=None):
        self.produced.append((topic, key, value))

    def poll(self, _timeout):
        return 0

    def flush(self, _timeout=5.0):
        return 0


@pytest.fixture(autouse=True)
def _disabled_activity_reporter(monkeypatch):
    """Default every test to a disabled (no-op) activity reporter singleton."""
    reset_activity_reporter()
    disabled = ActivityReporter(
        Settings(
            kafka_bootstrap_servers="dummy",
            kafka_auth_method="PLAINTEXT",
            kafka_activity_topic="",
        ),
        entity_name="test",
    )
    monkeypatch.setattr(activity_mod, "_reporter", disabled)
    yield
    reset_activity_reporter()


def _install_stub_reporter(monkeypatch, *, flood_cooldown_seconds: int = 300) -> _StubProducer:
    """Replace the singleton with an ENABLED reporter backed by a stub producer.

    Returns the stub producer so tests can introspect emitted activity events.
    """
    stub = _StubProducer(None)
    reporter = ActivityReporter(
        Settings(
            kafka_bootstrap_servers="dummy",
            kafka_auth_method="PLAINTEXT",
            kafka_activity_topic="detectflow.activity",
            activity_flood_cooldown_seconds=flood_cooldown_seconds,
            activity_heartbeat_seconds=60,
        ),
        entity_name="Attack Chains Correlation Job",
        producer_factory=lambda _cfg: stub,
    )
    monkeypatch.setattr(activity_mod, "_reporter", reporter)
    return stub


def _activity_events(stub: _StubProducer) -> list[dict]:
    return [json.loads(value.decode("utf-8")) for _topic, _key, value in stub.produced]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_open_registers_the_pipeline_identity_metric():
    """One low-cardinality identity metric, registered in open() — NOT in the
    _apply_* broadcast handlers, which run per message and would re-register it.
    It is the only place a pipeline label is used (see metrics.py's docstring)."""
    op, _states, _rc = _make_op(correlation_pipeline_id=PIPELINE_UUID)
    assert op._metrics.get_counter("correlation_pipeline_info", pipeline_id=PIPELINE_UUID) == 1


def test_identity_metric_label_is_none_for_the_legacy_deployment():
    """Unset CORRELATION_PIPELINE_ID → the literal "none", keeping the label
    cardinality at exactly 1 rather than emitting an empty label value."""
    op, _states, _rc = _make_op()
    assert op._metrics.get_counter("correlation_pipeline_info", pipeline_id="none") == 1


def test_identity_metric_is_a_counter_not_a_gauge():
    """Deliberate: a PyFlink gauge registers a Python callable that Flink's
    metrics thread invokes through Pemja, and that callback outliving its
    interpreter SIGSEGVs the TaskManager on job cancel. Counters are push-only — nothing calls back."""
    op, _states, _rc = _make_op(correlation_pipeline_id=PIPELINE_UUID)
    assert op._metrics.get_gauge("correlation_pipeline_info", pipeline_id=PIPELINE_UUID) is None


def test_broadcast_routing_writes_to_correct_state(
    hos_envelope_apt28, hos_apt28, at_apt28, chains_config
):
    op, states, _ = _make_op()
    _broadcast(op, states, {**hos_envelope_apt28, "_topic": HOS_TOPIC})
    _broadcast(op, states, {**at_apt28, "_topic": AT_TOPIC})
    _broadcast(op, states, {**chains_config, "_topic": CONFIG_TOPIC})

    assert hos_envelope_apt28["id"] in states[HOS_RULES_STATE.get_name()]
    assert at_apt28["id"] in states[AT_STATE.get_name()]
    assert "global" in states[CONFIG_STATE.get_name()]
    # Sigma index derived: every rule_id from the parsed APT28 body is
    # indexed. `hos_apt28` is the post-parse internal body — the matcher
    # built the same shape on broadcast and stored it in HOS_RULES_STATE.
    index = states[SIGMA_INDEX_STATE.get_name()]
    for s in hos_apt28["seqs"]:
        for rule_id in s["rule_ids"]:
            assert rule_id in index, f"{rule_id} missing from derived index"


def test_hos_tombstone_clears_state_and_index(hos_envelope_apt28):
    op, states, _ = _make_op()
    _broadcast(op, states, {**hos_envelope_apt28, "_topic": HOS_TOPIC})
    assert hos_envelope_apt28["id"] in states[HOS_RULES_STATE.get_name()]
    assert "5e000002-0000-4000-8000-000000000002" in states[SIGMA_INDEX_STATE.get_name()]

    _broadcast(op, states, {"_topic": HOS_TOPIC, "deleted": True, "id": hos_envelope_apt28["id"]})
    assert hos_envelope_apt28["id"] not in states[HOS_RULES_STATE.get_name()]
    assert "5e000002-0000-4000-8000-000000000002" not in states[SIGMA_INDEX_STATE.get_name()]


def test_at_logical_delete_envelope_clears_at_state(at_apt28, at_apt28_delete):
    """Cross-repo two-phase delete contract: detectflow-backend emits the Phase 1
    logical envelope (`{"id": X, "deleted": true}`) and the matcher must
    remove the AT from broadcast state when it arrives. The Phase 2 Kafka
    tombstone is for compaction only and is dropped at the deserializer."""
    op, states, _ = _make_op()
    _broadcast(op, states, {**at_apt28, "_topic": AT_TOPIC})
    assert at_apt28["id"] in states[AT_STATE.get_name()]

    _broadcast(op, states, {**at_apt28_delete, "_topic": AT_TOPIC})
    assert at_apt28["id"] not in states[AT_STATE.get_name()]


def test_kafka_null_tombstone_is_dropped_at_deserializer_level(hos_envelope_apt28):
    """Wire-level contract: a Kafka null-value record (`value=None` from
    librdkafka) must NEVER reach `process_broadcast_element`. PyFlink 2.2
    Python API has no surface for reading the Kafka key, so a null-value
    record carries no information the matcher could act on. The
    `filter_and_decode_tombstones` flat_map drops it; the matcher's
    invariant is that every record it sees is a non-empty JSON envelope.

    This test wires bytes → filter → TagWithTopic → operator end-to-end
    and asserts the matcher's broadcast state is unchanged when fed null."""
    from app.connectors.broadcast_filter import filter_and_decode_tombstones
    from app.jobs.correlation.__main__ import TagWithTopic

    op, states, _ = _make_op()
    _broadcast(op, states, {**hos_envelope_apt28, "_topic": HOS_TOPIC})
    snapshot_hos = dict(states[HOS_RULES_STATE.get_name()]._data)
    snapshot_idx = dict(states[SIGMA_INDEX_STATE.get_name()]._data)

    tagger = TagWithTopic(HOS_TOPIC)
    bctx = StubBroadcastCtx(states)
    for raw_bytes in (None, b""):
        decoded = list(filter_and_decode_tombstones(raw_bytes))
        assert decoded == []  # nothing flows downstream
        # Sanity-check: even if something *did* flow through, the
        # full chain (decode → tag → operator) would be a no-op too.
        for s in decoded:
            tagged = tagger.map(s)
            list(op.process_broadcast_element(tagged, bctx) or [])

    # State and derived index unchanged after null/empty bytes attempts.
    assert states[HOS_RULES_STATE.get_name()]._data == snapshot_hos
    assert states[SIGMA_INDEX_STATE.get_name()]._data == snapshot_idx


_UNSET = object()


def _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config):
    _broadcast(op, states, {**hos_envelope_apt28, "_topic": HOS_TOPIC})
    _broadcast(op, states, {**at_apt28, "_topic": AT_TOPIC})
    _broadcast(op, states, {**chains_config, "_topic": CONFIG_TOPIC})


def test_event_without_hostname_is_dropped(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    op, states, _ = _make_op()
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)
    bad = dict(events_apt28[0])
    bad.pop("hostname")
    out = _process(op, states, bad)
    assert out == []
    assert op._metrics.get_counter("events_dropped_missing_hostname") == 1


def _strip(events, *keys):
    return [{k: v for k, v in ev.items() if k not in keys} for ev in events]


def test_events_without_any_source_topic_still_correlate(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """Destination topic names left the contract entirely: isolation is the Kafka
    subscription, so events carrying neither `source_topic` nor `source_topics[]`
    must still build a chain.

    Asserted on the emitted chain, not on the retired drop counters — those read
    0 for any name the stub never saw, so asserting them proves nothing.
    """
    op, states, _ = _make_op()
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)

    emitted = _emit_all(op, states, _strip(events_apt28, "source_topic", "source_topics"))

    assert emitted, "a full APT28 chain must emit with no destination topic present"
    chain = emitted[-1]
    assert chain["coverage"] > 0
    assert "pipeline_names" not in chain
    # The surviving per-flow dimension rides on each event.
    assert all(ev["pipeline_id"] for ev in chain["events"])


def test_event_without_pipeline_id_is_counted_but_never_dropped(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """`pipeline_id` is the prompt's grouping dimension, not a correlation input.

    A missing value must never cost a chain (isolation is the subscription), but it
    silently collapses every prompt group into one `<unknown-pipeline>` bucket — so
    it gets a counter to make the matcher regression visible.
    """
    op, states, _ = _make_op()
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)

    emitted = _emit_all(op, states, _strip(events_apt28, "pipeline_id"))

    assert emitted, "a missing pipeline_id must not cost us the chain"
    assert op._metrics.get_counter("events_missing_pipeline_id") == len(events_apt28)
    assert all(ev["pipeline_id"] is None for ev in emitted[-1]["events"])


def test_pipeline_id_present_does_not_bump_the_missing_counter(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    op, states, _ = _make_op()
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)
    _emit_all(op, states, events_apt28)
    assert op._metrics.get_counter("events_missing_pipeline_id") == 0


def test_event_with_no_index_hits_is_dropped(hos_envelope_apt28, at_apt28, chains_config):
    op, states, _ = _make_op()
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)
    unrelated = {
        "event_id": "x",
        "hostname": "WKST-FIN-05",
        "timestamp": "2026-04-22T09:31:11Z",
        "detectflow": {"matches": [{"sigma_rule_uuid": "00000000-0000-0000-0000-000000000000"}]},
        "source_topic": "any-topic",
    }
    assert _process(op, states, unrelated) == []
    assert op._metrics.get_counter("events_dropped_no_hits") == 1


def test_globally_blocked_at_is_dropped_even_when_not_excluded(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """Monitoring gate 1: `enabled=false` on the SHARED active-threats
    topic IS the "blocked for all pipelines" flag (`is_blocked = NOT enabled`).
    It is independent of the per-pipeline
    deny-list — here the exclusion list is empty and the AT is still dropped."""
    op, states, _ = _make_op()
    disabled_at = {**at_apt28, "enabled": False}
    _seed_apt28(op, states, hos_envelope_apt28, disabled_at, chains_config)
    # Push all 5 events — none should produce a chain.
    emitted = [out for ev in events_apt28 for out in _process(op, states, ev)]
    assert emitted == []


def test_threshold_emit_and_revision_monotonicity(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    op, states, _ = _make_op()
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)

    # First two events: 1/6 and 2/6 hits — below 60% threshold, no emit.
    assert _process(op, states, events_apt28[0]) == []
    assert _process(op, states, events_apt28[1]) == []
    # Third event takes coverage to 3/6 = 50% — still below threshold.
    assert _process(op, states, events_apt28[2]) == []
    # Fourth event: 4/6 ≈ 66.67% — crosses threshold, revision 1 emitted.
    out4 = _process(op, states, events_apt28[3])
    assert len(out4) == 1
    assert out4[0]["revision"] == 1
    assert out4[0]["coverage"] == pytest.approx(66.67)
    # Fifth event: 5/6 ≈ 83.33% — same chain_id (deterministic), revision 2.
    out5 = _process(op, states, events_apt28[4])
    assert len(out5) == 1
    assert out5[0]["revision"] == 2
    assert out5[0]["chain_id"] == out4[0]["chain_id"]
    assert out5[0]["coverage"] == pytest.approx(83.33)
    assert op._metrics.get_counter("chains_emitted_total", hos_id=hos_envelope_apt28["id"]) == 2


def test_chain_id_is_deterministic_across_runs(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """Same `(hos_id, hostname, window_start)` MUST yield the same UUID even
    if the operator is rebuilt (drives idempotent upsert
    on the detectflow-backend consumer)."""
    chain_ids_per_run: list[str] = []
    for _ in range(2):
        op, states, _ = _make_op()
        _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)
        records: list[dict] = []
        for ev in events_apt28:
            records.extend(_process(op, states, ev))
        chain_ids_per_run.append(records[0]["chain_id"])
    assert chain_ids_per_run[0] == chain_ids_per_run[1]


def test_active_threat_is_inlined_on_emission(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    op, states, _ = _make_op()
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)
    records: list[dict] = []
    for ev in events_apt28:
        records.extend(_process(op, states, ev))
    final = records[-1]
    assert final["active_threat"]["name"] == "APT28"
    assert "summary" in final["active_threat"]
    # Operational fields excluded
    assert "id" not in final["active_threat"]
    assert "enabled" not in final["active_threat"]


def _replace_in_yaml(envelope: dict, search: str, replace: str) -> dict:
    return {**envelope, "yaml_text": envelope["yaml_text"].replace(search, replace)}


def _drop_yaml_lines(envelope: dict, *substrs: str) -> dict:
    text = envelope["yaml_text"]
    kept = [line for line in text.splitlines() if not any(s in line for s in substrs)]
    return {**envelope, "yaml_text": "\n".join(kept) + "\n"}


# ---------------------------------------------------------------------------
# Negative envelope rejection — parser errors flow through the handler to the
# `hos_rules_rejected_total{reason=...}` counter. Each branch verifies state
# untouched + counter labeled with the right reason. Parser-level coverage
# lives in test_hos_yaml.py; this exercises the handler routing.
# ---------------------------------------------------------------------------


def test_envelope_with_no_yaml_text_is_rejected_invalid_yaml(hos_envelope_apt28):
    op, states, _ = _make_op()
    bad = {k: v for k, v in hos_envelope_apt28.items() if k != "yaml_text"}
    _broadcast(op, states, {**bad, "_topic": HOS_TOPIC})
    assert hos_envelope_apt28["id"] not in states[HOS_RULES_STATE.get_name()]
    assert states[SIGMA_INDEX_STATE.get_name()]._data == {}
    assert op._metrics.get_counter("hos_rules_rejected_total", reason="invalid_yaml") == 1


def test_envelope_with_unparseable_yaml_is_rejected_invalid_yaml(hos_envelope_apt28):
    op, states, _ = _make_op()
    bad = {**hos_envelope_apt28, "yaml_text": ":\n  - not\n: : valid yaml"}
    _broadcast(op, states, {**bad, "_topic": HOS_TOPIC})
    assert hos_envelope_apt28["id"] not in states[HOS_RULES_STATE.get_name()]
    assert op._metrics.get_counter("hos_rules_rejected_total", reason="invalid_yaml") == 1


def test_envelope_missing_detection_block_is_rejected(hos_envelope_apt28):
    op, states, _ = _make_op()
    bad = {**hos_envelope_apt28, "yaml_text": "title: x\nid: y\nlevel: high\n"}
    _broadcast(op, states, {**bad, "_topic": HOS_TOPIC})
    assert hos_envelope_apt28["id"] not in states[HOS_RULES_STATE.get_name()]
    assert op._metrics.get_counter("hos_rules_rejected_total", reason="missing_detection") == 1


def test_envelope_with_no_seq_keys_is_rejected_empty_seqs(hos_envelope_apt28):
    """Detection block exists but every seqN entry is stripped."""
    op, states, _ = _make_op()
    bad_yaml = "detection:\n  timeframe: 30m\n  condition: chain by hostname\nlevel: high\n"
    bad = {**hos_envelope_apt28, "yaml_text": bad_yaml}
    _broadcast(op, states, {**bad, "_topic": HOS_TOPIC})
    assert hos_envelope_apt28["id"] not in states[HOS_RULES_STATE.get_name()]
    assert op._metrics.get_counter("hos_rules_rejected_total", reason="empty_seqs") == 1


@pytest.mark.parametrize("bad_condition", ["chain by username", "count() > 5", "chain by user"])
def test_envelope_with_unsupported_condition_is_rejected(hos_envelope_apt28, bad_condition):
    op, states, _ = _make_op()
    bad = _replace_in_yaml(
        hos_envelope_apt28,
        "condition: chain by hostname",
        f"condition: '{bad_condition}'",
    )
    _broadcast(op, states, {**bad, "_topic": HOS_TOPIC})
    assert hos_envelope_apt28["id"] not in states[HOS_RULES_STATE.get_name()]
    assert op._metrics.get_counter("hos_rules_rejected_total", reason="unsupported_condition") == 1


def test_handler_in_process_happy_path_emits_chain_with_yaml_envelope(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """End-to-end (in-process) verification of the thin-envelope flow:
    wire envelope → broadcast handler → parse → SIGMA_INDEX_STATE populated
    → process_element → emit chain JSON. Real-Kafka verify is deferred
    until the integration Dockerfile pemja issue is fixed (tracked
    separately); this in-process path covers the same logic without the
    container stack."""
    op, states, _ = _make_op()
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)

    # Sigma index populated from yaml_text — at least one well-known APT28 rule.
    assert "5e000002-0000-4000-8000-000000000002" in states[SIGMA_INDEX_STATE.get_name()]

    emitted: list[dict] = []
    for ev in events_apt28:
        emitted.extend(_process(op, states, ev))

    assert emitted, "expected at least one chain emission across the APT28 fixture burst"
    final = emitted[-1]
    assert final["hos_rule_id"] == hos_envelope_apt28["id"]
    assert final["active_threat"]["name"] == "APT28"
    assert final["coverage"] == pytest.approx(83.33)


@pytest.mark.parametrize("bad_timeframe", [0, -1, -3600])
def test_hos_with_non_positive_timeframe_is_rejected(hos_envelope_apt28, bad_timeframe):
    """Non-positive `timeframe` must be rejected
    at the broadcast boundary so bucket math downstream never sees it.

    Post-pivot: `timeframe` lives inside `yaml_text`, parser raises
    `InvalidTimeframeError`, handler routes to the
    `hos_rules_rejected_total{reason=invalid_timeframe}` counter. The
    HoS body must NOT land in state and the derived sigma index must
    remain unchanged."""
    op, states, _ = _make_op()
    bad_yaml = hos_envelope_apt28["yaml_text"].replace(
        "timeframe: 30m", f"timeframe: {bad_timeframe}"
    )
    bad_envelope = {**hos_envelope_apt28, "yaml_text": bad_yaml}
    _broadcast(op, states, {**bad_envelope, "_topic": HOS_TOPIC})
    assert hos_envelope_apt28["id"] not in states[HOS_RULES_STATE.get_name()]
    assert states[SIGMA_INDEX_STATE.get_name()]._data == {}
    assert op._metrics.get_counter("hos_rules_rejected_total", reason="invalid_timeframe") == 1


def test_process_element_registers_no_event_time_timer(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """Event-time timers were REMOVED: behind the Long.MIN-pinned operator
    watermark they could never fire, but every registration persisted as
    immortal checkpointed keyed state — one timer per (hostname, window_end),
    monotonic checkpoint growth. Buffer GC rides the processing-time
    maintenance timer instead."""
    op, states, _ = _make_op()
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)

    kctx = StubKeyedCtx(states, processing_time_ms=1_000)
    for ev in events_apt28:
        list(op.process_element(json.dumps(ev), kctx) or [])

    assert kctx.timer_service().registered == [], "no event-time timer may ever be registered"
    # The processing-time maintenance timer (heartbeat + GC) is still wired.
    assert kctx.timer_service().registered_processing


def test_event_time_on_timer_is_noop():
    """A stray event-time firing (only possible from pre-fix restored state)
    must be ignored: buffers untouched, empty iterable returned (the
    return-on-every-path contract is load-bearing — see the on_timer
    docstring). GC happens exclusively on the processing-time path."""
    op, states, _ = _make_op()
    window_start = 1_000_000
    _seed_two_buffers(op, window_start=window_start)

    # Fire well past both windows' ends — on the event-time path nothing moves.
    out = op.on_timer(timestamp=(window_start + 10_000) * 1000, ctx=StubKeyedCtx(states))
    assert out == []
    assert len(op._buffers_state.keys()) == 2, "event-time path must not touch buffers"
    assert op._metrics.get_counter("buffers_expired") == 0


def test_invalid_json_is_swallowed(hos_envelope_apt28, at_apt28, chains_config):
    op, states, _ = _make_op()
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)
    kctx = StubKeyedCtx(states)
    # Non-JSON main-stream payload — must not raise.
    assert list(op.process_element("not-json", kctx)) == []
    bctx = StubBroadcastCtx(states)
    assert list(op.process_broadcast_element("not-json", bctx) or []) == []


# ---------------------------------------------------------------------------
# Watermark / late-drop
# ---------------------------------------------------------------------------


def _epoch_ms(iso: str) -> int:
    from datetime import datetime

    return int(datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp() * 1000)


def test_late_event_is_dropped_when_behind_watermark(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """Event whose timestamp has fallen behind the source watermark
    (forBoundedOutOfOrderness(60s)) MUST be dropped before any matcher work.
    Without this, a late seq-6 event arriving after coverage=83.33 was
    emitted could resurrect/skew the buffer and cause spurious revisions."""
    op, states, _ = _make_op()
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)

    # Watermark advanced to 09:31:36 (approx where the steady-state burst
    # would put it: max event ts 09:31:31 minus 60s ≈ 09:30:31; we pick a
    # higher watermark to make the late-event check unambiguous).
    watermark = _epoch_ms("2026-04-22T09:31:36Z")
    # Use the canonical late-fixture timestamp (09:30:00Z, well past tolerance).
    late_event = {
        "event_id": "evt-late",
        "hostname": "WKST-FIN-05",
        "timestamp": "2026-04-22T09:30:00Z",
        # seq-6 rule
        "detectflow": {"matches": [{"sigma_rule_uuid": "5e000010-0000-4000-8000-000000000010"}]},
        "source_topic": "dest-windows-events-raw",
    }
    out = _process(op, states, late_event, watermark_ms=watermark)
    assert out == []
    assert op._metrics.get_counter("events_late_dropped") == 1
    # Crucially: the seq-6 hit was NOT recorded — buffer untouched.
    assert len(op._buffers_state.keys()) == 0


def test_on_time_event_passes_when_at_watermark(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """Event exactly at the watermark MUST pass (only `<` is late)."""
    op, states, _ = _make_op()
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)

    ev = events_apt28[0]
    watermark = _epoch_ms(ev["timestamp"])
    out = _process(op, states, ev, watermark_ms=watermark)
    # No emit yet (1/6 coverage), but no late-drop counter either.
    assert out == []
    assert op._metrics.get_counter("events_late_dropped") == 0


def test_zero_watermark_at_startup_does_not_late_drop(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """Before the first watermark advances, current_watermark() returns 0
    (or Long.MIN). The matcher must not treat startup as `everything is
    late`. The `watermark_ms > 0` guard in the late-drop check covers this."""
    op, states, _ = _make_op()
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)

    # Default StubKeyedCtx uses watermark_ms=0 → must not late-drop.
    out = _process(op, states, events_apt28[0])
    assert op._metrics.get_counter("events_late_dropped") == 0
    assert out == []  # 1/6 below threshold, but the event was processed
    # Confirm the buffer was actually updated (not silently dropped).
    assert len(op._buffers_state.keys()) == 1


def test_late_drop_fallback_per_key_clock_when_watermark_pinned(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """In `KeyedBroadcastProcessFunction`, `current_watermark()` is
    `min(keyed_input, broadcast_inputs)`, and pyflink+KafkaSource v2 does not
    propagate idleness through `connect()` from a broadcast input — so the
    operator watermark stays pinned at Long.MIN even when the keyed source
    has advanced. The matcher's `watermark_ms > 0` primary gate then never
    fires; the per-key max-event-ts fallback (mirroring
    forBoundedOutOfOrderness(60s)) MUST drop events older than `key_max-60s`
    so late-drop stays a working signal in prod."""
    op, states, _ = _make_op()
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)

    on_time = events_apt28[0]
    on_time_ms = _epoch_ms(on_time["timestamp"])

    # First event (watermark=0 stays pinned) seeds the per-key clock.
    _process(op, states, on_time)  # default watermark_ms=0
    assert op._metrics.get_counter("events_late_dropped") == 0
    buf_snapshot = {k: op._buffers_state.get(k) for k in op._buffers_state.keys()}
    assert buf_snapshot, "first on-time event must have populated the buffer"

    # Late event ~90s behind on_time — exceeds the 60s tolerance.
    late_event = {
        "event_id": "evt-late-fallback",
        "hostname": on_time["hostname"],
        "timestamp": "2026-04-22T09:29:41Z",  # 90s before events_apt28[0] 09:31:11Z
        # seq-6 rule
        "detectflow": {"matches": [{"sigma_rule_uuid": "5e000010-0000-4000-8000-000000000010"}]},
        "source_topic": on_time["source_topic"],
    }
    # Sanity-check the fixture distance — protects the test from a future
    # tweak to events_apt28[0]'s timestamp invalidating the 90s offset.
    assert on_time_ms - _epoch_ms(late_event["timestamp"]) > 60_000

    out = _process(op, states, late_event)  # watermark_ms still 0
    assert out == []
    assert op._metrics.get_counter("events_late_dropped") == 1
    # Buffer not touched by the late event — same keys, same serialized values.
    assert {k: op._buffers_state.get(k) for k in op._buffers_state.keys()} == buf_snapshot


def test_late_drop_boundary_is_strict_lt(hos_envelope_apt28, at_apt28, chains_config, events_apt28):
    """Review #4a: lock the `<` boundary semantic. An event with ts equal to
    watermark passes; an event one millisecond behind the watermark is dropped.
    The matcher gate is `ts_epoch * 1000 < watermark_ms` — this test pins
    that semantic so a future refactor to `<=` would fail loudly."""
    ev = events_apt28[0]
    ev_ms = _epoch_ms(ev["timestamp"])

    # ts == watermark → passes
    op, states, _ = _make_op()
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)
    _process(op, states, ev, watermark_ms=ev_ms)
    assert op._metrics.get_counter("events_late_dropped") == 0
    assert len(op._buffers_state.keys()) == 1

    # ts < watermark by 1ms → dropped
    op2, states2, _ = _make_op()
    _seed_apt28(op2, states2, hos_envelope_apt28, at_apt28, chains_config)
    _process(op2, states2, ev, watermark_ms=ev_ms + 1)
    assert op2._metrics.get_counter("events_late_dropped") == 1
    assert len(op2._buffers_state.keys()) == 0


def test_config_update_applies_prospectively_not_retroactively(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """Review #4b: a chains-config broadcast update mid-window must take
    effect on the NEXT event, not retroactively. Already-emitted chains keep
    their original threshold/coverage decision; only subsequent events use
    the new value.

    Scenario: emit 4 events to cross the 60% threshold (revision=1). Push a
    new config with threshold=100% (effectively unreachable). Emit the 5th
    event — it would have been revision=2 at the old threshold, but at 100%
    it must NOT emit. The previous emission stands; only the new value
    governs going forward."""
    op, states, _ = _make_op()
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)

    # First 4 events → cross 60% threshold, revision=1 emitted.
    emitted: list[dict] = []
    for ev in events_apt28[:4]:
        emitted.extend(_process(op, states, ev))
    assert len(emitted) == 1
    assert emitted[0]["revision"] == 1

    # Hot config update: bump threshold to 100% (unreachable for 5/6).
    tightened = {**chains_config, "threshold_pct": 100, "_topic": CONFIG_TOPIC}
    _broadcast(op, states, tightened)

    # 5th event: 5/6 = 83.33% < new 100% → NO new revision.
    out5 = _process(op, states, events_apt28[4])
    assert out5 == []
    # Sanity: buffer still tracking the hit, just below the new threshold.
    assert len(op._buffers_state.keys()) == 1
    # Original emission stands — not retroactively invalidated.
    assert op._metrics.get_counter("chains_emitted_total", hos_id=hos_envelope_apt28["id"]) == 1


# ---------------------------------------------------------------------------
# Poison-pill timestamp guard
# ---------------------------------------------------------------------------


def test_malformed_timestamp_is_dropped_not_raised(
    monkeypatch, hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """A non-empty unparseable `timestamp` must DROP the event, never raise —
    an exception out of process_element fails the job, and Kafka offset
    redelivery of the same record turns it into a permanent crash loop.
    Garbage strings raise ValueError inside fromisoformat; a JSON number (or
    any non-str) raises AttributeError on `.replace`. Both are contract
    violations, so the drop carries a counter + ONE gated alert."""
    stub = _install_stub_reporter(monkeypatch)
    op, states, _ = _make_op()
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)

    bad_timestamps = [
        "definitely-not-a-timestamp",  # ValueError from fromisoformat
        1776850271,  # JSON number → AttributeError on .replace
        ["2026-04-22T09:31:11Z"],  # non-str container → AttributeError
    ]
    for bad_ts in bad_timestamps:
        bad = {**events_apt28[0], "timestamp": bad_ts}
        assert _process(op, states, bad) == []  # dropped, not raised

    assert op._metrics.get_counter("events_dropped_bad_timestamp") == len(bad_timestamps)
    # The poisoned events never touched keyed state.
    assert len(op._buffers_state.keys()) == 0
    # Gated alert: 3 drops collapse to exactly one activity event.
    events = _activity_events(stub)
    assert len(events) == 1
    assert events[0]["changes"]["drop_reason"] == "bad_timestamp"


# ---------------------------------------------------------------------------
# Job-health activity wiring (detectflow.activity side channel)
# ---------------------------------------------------------------------------


def test_disabled_reporter_means_no_activity_on_drop(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """The default autouse fixture installs a disabled reporter — the matcher
    must run normally and open no producer / emit nothing on the hot path."""
    op, states, _ = _make_op()
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)
    bad = dict(events_apt28[0])
    bad.pop("hostname")
    assert _process(op, states, bad) == []
    # Reporter is the disabled singleton — never built a producer.
    assert op._activity.enabled is False
    assert op._activity._producer is None


def test_hos_reject_emits_gated_activity_alert(monkeypatch, hos_envelope_apt28):
    """Malformed HoS envelope → alert/warning on detectflow.activity, reason in changes,
    gated per reason so a burst of identically-broken rules does not flood."""
    stub = _install_stub_reporter(monkeypatch)
    op, states, _ = _make_op()
    # yaml_text missing → invalid_yaml reject.
    bad = {k: v for k, v in hos_envelope_apt28.items() if k != "yaml_text"}
    for _ in range(3):
        _broadcast(op, states, {**bad, "_topic": HOS_TOPIC})

    events = _activity_events(stub)
    # Gated per reason: 3 identical rejects collapse to exactly one alert.
    assert len(events) == 1
    ev = events[0]
    assert ev["action"] == "alert"
    assert ev["severity"] == "warning"
    assert ev["entity_type"] == "flink"
    assert ev["source"] == "flink"
    # entity_name carries the instance label — here the stub reporter's settings
    # leave JOB_ID at its "local" default, so that is the label.
    assert ev["entity_name"] == "Attack Chains Correlation Job [local]"
    assert ev["changes"]["reason_code"] == "invalid_yaml"
    assert ev["changes"]["hos_id"] == hos_envelope_apt28["id"]
    # No non-standard top-level keys leaked.
    assert set(ev) == {
        "id",
        "timestamp",
        "action",
        "entity_type",
        "entity_id",
        "entity_name",
        "user_id",
        "user_email",
        "details",
        "changes",
        "source",
        "severity",
    }


def test_drop_flood_is_gated_one_alert_per_reason(
    monkeypatch, hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """A burst of identically-dropped records emits at most one alert per reason
    inside the cooldown — never one event per dropped record."""
    stub = _install_stub_reporter(monkeypatch)
    op, states, _ = _make_op()
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)

    bad = dict(events_apt28[0])
    bad.pop("hostname")
    for _ in range(50):
        _process(op, states, bad)

    # 50 dropped records → exactly one gated alert.
    assert op._metrics.get_counter("events_dropped_missing_hostname") == 50
    events = _activity_events(stub)
    assert len(events) == 1
    assert events[0]["action"] == "alert"
    assert events[0]["severity"] == "warning"
    assert events[0]["changes"]["drop_reason"] == "missing_hostname"


def test_distinct_drop_reasons_emit_independently(
    monkeypatch, hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """Different drop reasons use distinct flood keys → independent alerts."""
    stub = _install_stub_reporter(monkeypatch)
    op, states, _ = _make_op()
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)

    no_host = dict(events_apt28[0])
    no_host.pop("hostname")
    bad_ts = dict(events_apt28[0])
    bad_ts["timestamp"] = "not-a-timestamp"
    _process(op, states, no_host)
    _process(op, states, bad_ts)

    reasons = {ev["changes"]["drop_reason"] for ev in _activity_events(stub)}
    assert reasons == {"missing_hostname", "bad_timestamp"}


def test_process_element_registers_processing_time_heartbeat_timer(
    monkeypatch, hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """A processing-time timer is registered, aligned to the next heartbeat
    boundary (multiple of activity_heartbeat_seconds in ms)."""
    _install_stub_reporter(monkeypatch)
    op, states, _ = _make_op()
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)

    # Drive process_element with a controlled processing-time clock.
    kctx = StubKeyedCtx(states, processing_time_ms=1_000)
    list(op.process_element(json.dumps(events_apt28[0]), kctx) or [])

    interval = 60_000  # activity_heartbeat_seconds=60 → 60_000 ms
    assert kctx.timer_service().registered_processing == [interval]  # next boundary after 1s


def test_processing_time_timer_emits_one_heartbeat_per_interval(monkeypatch):
    """on_timer in the processing-time domain emits a single heartbeat, and the
    per-task guard suppresses a second fire inside the same interval."""
    stub = _install_stub_reporter(monkeypatch)
    op, states, _ = _make_op()

    interval = op._heartbeat_interval_ms
    # First processing-time fire at t=interval → one heartbeat.
    op.on_timer(interval, StubOnTimerCtx(states, processing=True, processing_time_ms=interval))
    # Second fire inside the same interval (t=interval+1) → suppressed.
    op.on_timer(
        interval + 1, StubOnTimerCtx(states, processing=True, processing_time_ms=interval + 1)
    )
    # Fire after the interval elapses → second heartbeat.
    op.on_timer(
        interval * 3,
        StubOnTimerCtx(states, processing=True, processing_time_ms=interval * 3),
    )

    events = _activity_events(stub)
    assert len(events) == 2
    for ev in events:
        assert ev["action"] == "status_change"
        assert ev["severity"] == "info"
        assert ev["details"] == "heartbeat"
        assert ev["changes"]["subtask_index"] == 0


def test_event_time_timer_neither_cleans_nor_heartbeats(
    monkeypatch, hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """A stray event-time firing (pre-fix restored state) does nothing: no
    buffer cleanup (that rides the processing-time maintenance timer) and no
    heartbeat — only the processing-time domain drives liveness."""
    stub = _install_stub_reporter(monkeypatch)
    op, states, _ = _make_op()
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)
    for ev in events_apt28[:2]:
        _process(op, states, ev)
    assert len(op._buffers_state.keys()) == 1

    # Event-time fire well past window_end → no-op on every front.
    out = op.on_timer(
        (1776850200 + 1801) * 1000,
        StubOnTimerCtx(states, processing=False),
    )
    assert out == []
    assert len(op._buffers_state.keys()) == 1
    assert op._metrics.get_counter("buffers_expired") == 0
    # No heartbeat events emitted from the event-time path.
    assert _activity_events(stub) == []


# ---------------------------------------------------------------------------
# Processing-time buffer GC (MATCH-1 — keyed-state-leak fix)
# ---------------------------------------------------------------------------
#
# The event-time cleanup timer can never fire on the live job (operator
# watermark pinned at Long.MIN — the broadcast meta inputs carry no
# watermarks). Keyed-buffer GC therefore rides the processing-time
# maintenance timer, reclaiming a buffer once wall-clock passes
# window_end + chain_buffer_cleanup_grace_seconds.


def _seed_two_buffers(op, *, window_start: int) -> None:
    from app.operators.chain_buffer import BufferEntry, ChainBuffer
    from app.operators.hos_correlation_function import _serialize_buffer

    short_buf = ChainBuffer(
        window_start_epoch=window_start,
        window_end_epoch=window_start + 60,  # 60s timeframe
        last_activity_epoch=window_start + 30,
        seqs_hit={1: [BufferEntry(rule_id="r-short", event={"event_id": "es"})]},
    )
    long_buf = ChainBuffer(
        window_start_epoch=window_start,
        window_end_epoch=window_start + 300,  # 300s timeframe
        last_activity_epoch=window_start + 30,
        seqs_hit={1: [BufferEntry(rule_id="r-long", event={"event_id": "el"})]},
    )
    op._buffers_state.put(f"hos-short|{window_start}", _serialize_buffer(short_buf))
    op._buffers_state.put(f"hos-long|{window_start}", _serialize_buffer(long_buf))


def test_processing_time_timer_garbage_collects_expired_buffers(monkeypatch):
    """Processing-time maintenance timer reclaims buffers past window_end+grace,
    keeps still-open ones, and schedules a follow-up timer for the survivors so
    a host that goes silent is still fully cleaned without new events."""
    _install_stub_reporter(monkeypatch)
    op, states, _ = _make_op()
    grace = op._cleanup_grace_s
    window_start = 1_000_000
    _seed_two_buffers(op, window_start=window_start)
    assert len(op._buffers_state.keys()) == 2

    now_s = window_start + 60 + grace + 1  # past short window_end + grace
    ctx = StubOnTimerCtx(states, processing=True, processing_time_ms=now_s * 1000)
    op.on_timer(now_s * 1000, ctx)

    keys = op._buffers_state.keys()
    assert f"hos-short|{window_start}" not in keys, "expired short buffer must be GC'd"
    assert f"hos-long|{window_start}" in keys, "still-open long buffer must be retained"
    assert op._metrics.get_counter("buffers_expired") == 1
    # Follow-up timer scheduled at the survivor's expiry (window_end + grace).
    assert (window_start + 300 + grace + 1) * 1000 in ctx.timer_service().registered_processing


def test_processing_time_cleanup_respects_grace(monkeypatch):
    """A buffer past its window end but still inside the grace period is NOT
    reclaimed — cleaning before window_end + grace would be premature."""
    _install_stub_reporter(monkeypatch)
    op, states, _ = _make_op()
    grace = op._cleanup_grace_s
    window_start = 1_000_000
    _seed_two_buffers(op, window_start=window_start)

    now_s = window_start + 60 + (grace - 1)  # inside the grace window for short
    ctx = StubOnTimerCtx(states, processing=True, processing_time_ms=now_s * 1000)
    op.on_timer(now_s * 1000, ctx)

    assert len(op._buffers_state.keys()) == 2, "nothing GC'd inside the grace window"
    assert op._metrics.get_counter("buffers_expired") == 0


def test_maintenance_timer_registered_even_when_activity_disabled(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """Buffer GC must run even with the activity reporter disabled, so the
    processing-time maintenance timer is registered unconditionally (the GC is
    not gated on the health channel)."""
    # No _install_stub_reporter → the autouse disabled reporter is active.
    op, states, _ = _make_op()
    assert op._activity.enabled is False
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)

    kctx = StubKeyedCtx(states, processing_time_ms=1_000)
    list(op.process_element(json.dumps(events_apt28[0]), kctx) or [])

    assert kctx.timer_service().registered_processing == [60_000]  # next boundary, GC tick


def test_parse_iso_naive_timestamp_is_treated_as_utc():
    """A timezone-less event timestamp must be parsed as UTC (not worker-local),
    so window bucketing and the deterministic chain_id are host-TZ-independent."""
    from datetime import UTC, datetime

    from app.operators.hos_correlation_function import _parse_iso_to_epoch

    z = _parse_iso_to_epoch("2026-05-15T20:30:00Z")
    offset = _parse_iso_to_epoch("2026-05-15T20:30:00+00:00")
    naive = _parse_iso_to_epoch("2026-05-15T20:30:00")
    assert z == offset == naive
    assert z == int(datetime(2026, 5, 15, 20, 30, 0, tzinfo=UTC).timestamp())


# ---------------------------------------------------------------------------
# Broadcast hot-path scan regression
# ---------------------------------------------------------------------------
#
# The broadcast handler used to materialize the FULL inverted index
# (items() scan) and recompute gauges with full keys() scans on EVERY
# hos-rules / active-threats record. In process mode each entry read is a
# gRPC round trip, so a cold-start replay of N meta records cost O(N²)
# round trips — ~1 record/min in practice, stalling the keyed stream
# until every checkpoint expired. The handler must now touch only the index
# keys wired by the affected hos_id, and must NEVER scan broadcast state at
# all: besides the O(N²) replay cost, `broadcast_state.keys()/.items()` is
# unavailable in thread mode (Pemja hands back a raw Java proxy with no
# `.keys()`), so any scan crash-loops the matcher. The
# gauges therefore seed from 0 and track deltas instead of scanning.


class _ScanCountingMapState(StubMapState):
    """StubMapState that counts full-scan calls (items/keys/values)."""

    def __init__(self):
        super().__init__()
        self.scans = 0

    def items(self):
        self.scans += 1
        return super().items()

    def keys(self):
        self.scans += 1
        return super().keys()

    def values(self):
        self.scans += 1
        return list(super()._data.values())


def _make_scan_counting_op() -> tuple[HosCorrelationFunction, dict]:
    op = HosCorrelationFunction(
        settings=_settings(),
        active_threats_topic=AT_TOPIC,
        hos_rules_topic=HOS_TOPIC,
        chains_config_topic=CONFIG_TOPIC,
    )
    states = {
        HOS_RULES_STATE.get_name(): _ScanCountingMapState(),
        AT_STATE.get_name(): _ScanCountingMapState(),
        CONFIG_STATE.get_name(): _ScanCountingMapState(),
        SIGMA_INDEX_STATE.get_name(): _ScanCountingMapState(),
    }
    op.open(StubRuntimeContext())
    return op, states


def test_hos_replay_never_scans_broadcast_state(hos_envelope_apt28):
    """N HoS upserts must NEVER scan broadcast state — not per record, not even
    once for a gauge seed (thread-mode Pemja proxies have no .keys())."""
    op, states = _make_scan_counting_op()
    n = 25
    for i in range(n):
        envelope = {**hos_envelope_apt28, "id": f"hos-{i:03d}", "_topic": HOS_TOPIC}
        _broadcast(op, states, envelope)

    assert states[HOS_RULES_STATE.get_name()].scans == 0
    assert states[SIGMA_INDEX_STATE.get_name()].scans == 0


def test_at_replay_never_scans_broadcast_state(at_apt28):
    op, states = _make_scan_counting_op()
    n = 25
    for i in range(n):
        _broadcast(op, states, {**at_apt28, "id": f"at-{i:03d}", "_topic": AT_TOPIC})

    assert states[AT_STATE.get_name()].scans == 0


def test_hos_update_rewires_index_incrementally(hos_envelope_apt28, hos_apt28):
    """Re-upserting a HoS with different rule wiring must drop the stale index
    keys and add the new ones — equivalence with the full-rebuild semantics."""
    op, states, _ = _make_op()
    _broadcast(op, states, {**hos_envelope_apt28, "_topic": HOS_TOPIC})
    index = states[SIGMA_INDEX_STATE.get_name()]
    old_rule_ids = [r for s in hos_apt28["seqs"] for r in s["rule_ids"]]
    assert all(r in index for r in old_rule_ids)

    # Second HoS shares one rule_id with the first — its entries must coexist.
    shared_rule = old_rule_ids[0]
    yaml_text = (
        "title: Other chain\n"
        "detection:\n"
        f"  seq1:\n    ruleid|contains:\n      - {shared_rule}\n"
        "  timeframe: 30m\n"
        "  condition: chain by hostname\n"
    )
    other = {**hos_envelope_apt28, "id": "hos-other", "yaml_text": yaml_text}
    _broadcast(op, states, {**other, "_topic": HOS_TOPIC})
    entries = json.loads(index.get(shared_rule))
    assert {e[0] for e in entries} == {hos_envelope_apt28["id"], "hos-other"}

    # Update the FIRST HoS to a body that no longer references shared_rule:
    # its pointer must vanish from that key while hos-other's survives.
    new_yaml = (
        "title: Rewired chain\n"
        "detection:\n"
        "  seq1:\n    ruleid|contains:\n      - 99999999-aaaa-bbbb-cccc-000000000001\n"
        "  timeframe: 30m\n"
        "  condition: chain by hostname\n"
    )
    _broadcast(op, states, {**hos_envelope_apt28, "yaml_text": new_yaml, "_topic": HOS_TOPIC})
    entries = json.loads(index.get(shared_rule))
    assert {e[0] for e in entries} == {"hos-other"}
    assert "99999999-aaaa-bbbb-cccc-000000000001" in index
    # All other previously-wired keys of the first HoS are gone.
    for rule_id in old_rule_ids[1:]:
        assert rule_id not in index, f"stale index key {rule_id} survived rewire"


# ---------------------------------------------------------------------------
# Record-size guard (>1MiB chains crash the sink)
# ---------------------------------------------------------------------------


def test_oversized_chain_record_is_shrunk_to_fit(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """A chain whose inlined events exceed chain_max_record_kb must be
    re-rendered with fewer per-seq events until it fits — never emitted
    oversized (RecordTooLargeException restarts the job forever)."""
    op, states, _ = _make_op(
        chain_max_events_per_seq=50,
        chain_max_record_kb=64,  # floor of the setting — easy to exceed
    )
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)

    # Cross the coverage threshold with the normal-size fixture events first.
    outputs = []
    for ev in events_apt28[:6]:
        outputs.extend(_process(op, states, ev))
    assert outputs, "expected the fixture corpus to emit a chain"

    # Then pile ~30KiB events onto ONE seq: every post-threshold hit re-emits
    # a revision, and the accumulated fat entries push the record over the
    # 64KiB cap — forcing the per-seq shrink loop.
    big = "x" * 30_000
    seq1_event = events_apt28[0]
    fat_outputs = []
    for i in range(8):
        fat = {**seq1_event, "event_id": f"fat-{i}", "parsed_event": {"blob": big, "i": i}}
        fat_outputs.extend(_process(op, states, fat))

    assert fat_outputs, "post-threshold hits must keep re-emitting revisions"
    assert op._metrics.get_counter("chain_record_shrunk_total") >= 1
    last = fat_outputs[-1]
    # Shrunk below the raw accumulation and self-describing about the drop.
    total_hits = sum(len(v) for v in [last["events"]]) + last["events_dropped"]
    assert last["events_dropped"] > 0
    assert last["event_count"] < total_hits
    # The emitted payload respects the cap up to the 1-per-seq floor.
    assert (
        len(json.dumps(last, separators=(",", ":")).encode()) <= 64 * 1024 + 40_000
    )  # floor slack: one fat event may remain per seq


def test_oversized_record_strips_parsed_event_as_final_fallback(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """Tier-2 guard: with many seqs × ONE large parsed_event each, the per-seq
    shrink loop bottoms out at 1 event/seq with the payload still over the cap
    (the loop used to exit there and emit anyway → RecordTooLargeException →
    deterministic crash loop). The fallback strips parsed_event bodies; the
    match metadata (rule ids, seqs, timestamps, techniques) survives."""
    op, states, _ = _make_op(chain_max_record_kb=64)
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)

    big = "x" * 30_000
    outputs: list[dict] = []
    for ev in events_apt28:
        fat = {**ev, "parsed_event": {"blob": big}}
        outputs.extend(_process(op, states, fat))

    assert outputs, "threshold crossings must still emit (stripped, not dropped)"
    last = outputs[-1]
    # 5 distinct seqs × 1 × 30KiB parsed_event ≈ 150KiB — no per-seq shrink can
    # fit that into 64KiB, so every inlined event must have been stripped.
    assert all(e["parsed_event"] == {} for e in last["events"])
    # Metadata survives the strip.
    assert all(e["sigma_rule_id"] for e in last["events"])
    assert len(json.dumps(last, separators=(",", ":")).encode()) <= 64 * 1024
    assert op._metrics.get_counter("chain_record_stripped_total") >= 1
    assert op._metrics.get_counter("chains_dropped_oversized_total") == 0


def test_oversized_record_undeliverable_is_dropped_with_alert(
    monkeypatch, hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """Tier-3 guard: if the record exceeds the cap even after the parsed_event
    strip (pathologically fat metadata), it must NOT be yielded — the sink
    would reject it and crash-loop the job. Counter + ONE gated alert."""
    stub = _install_stub_reporter(monkeypatch)
    op, states, _ = _make_op(chain_max_record_kb=64)
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)

    # event_id survives the parsed_event strip — 30KiB each × 4+ events > 64KiB.
    outputs: list[dict] = []
    for i, ev in enumerate(events_apt28):
        fat = {**ev, "event_id": "x" * 30_000 + str(i)}
        outputs.extend(_process(op, states, fat))

    assert outputs == [], "an undeliverable record must never be emitted"
    # Threshold crossed at events 4 and 5 — both render attempts dropped.
    assert op._metrics.get_counter("chains_dropped_oversized_total") == 2
    assert op._metrics.get_counter("chains_emitted_total", hos_id=hos_envelope_apt28["id"]) == 0
    # Gated: 2 drops collapse to one alert.
    events = _activity_events(stub)
    assert len(events) == 1
    assert events[0]["changes"]["reason"] == "chain_dropped_oversized"
    assert events[0]["changes"]["hos_id"] == hos_envelope_apt28["id"]


# ---------------------------------------------------------------------------
# Normal-case drops are counter-only (no activity alert)
# ---------------------------------------------------------------------------
#
# no_hits is the NORMAL fate of most tagged events (they match no HoS rule).
# A perpetual gated alert for that re-fires every cooldown forever and
# desensitizes detectflow.activity — alerts are reserved for contract violations.


def test_no_hits_drop_is_counter_only_no_alert(
    monkeypatch, hos_envelope_apt28, at_apt28, chains_config
):
    stub = _install_stub_reporter(monkeypatch)
    op, states, _ = _make_op()
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)
    unrelated = {
        "event_id": "x",
        "hostname": "WKST-FIN-05",
        "timestamp": "2026-04-22T09:31:11Z",
        "detectflow": {"matches": [{"sigma_rule_uuid": "00000000-0000-0000-0000-000000000000"}]},
        "source_topic": "any-topic",
    }
    for _ in range(10):
        assert _process(op, states, unrelated) == []
    assert op._metrics.get_counter("events_dropped_no_hits") == 10
    assert _activity_events(stub) == [], "no_hits must never reach detectflow.activity"


# ---------------------------------------------------------------------------
# Per-key fallback-clock state hygiene
# ---------------------------------------------------------------------------


def test_cleanup_clears_key_max_clock_when_no_live_buffers(monkeypatch):
    """`_key_max_ts_state` is a per-hostname ValueState; without clearing it the
    matcher leaks one long per hostname ever seen. The GC clears it together
    with the key's LAST buffer (a later event simply reseeds it; resurrection
    is bounded by the grace logic), and must NOT clear it while any buffer for
    the key is still live."""
    _install_stub_reporter(monkeypatch)
    op, states, _ = _make_op()
    grace = op._cleanup_grace_s
    window_start = 1_000_000
    _seed_two_buffers(op, window_start=window_start)
    op._key_max_ts_state.update(123_456_789)

    # Pass 1: short buffer expires, long one survives → clock retained.
    now_s = window_start + 60 + grace + 1
    op.on_timer(
        now_s * 1000, StubOnTimerCtx(states, processing=True, processing_time_ms=now_s * 1000)
    )
    assert len(op._buffers_state.keys()) == 1
    assert op._key_max_ts_state.value() == 123_456_789

    # Pass 2: last buffer expires → clock cleared with it.
    now_s = window_start + 300 + grace + 1
    op.on_timer(
        now_s * 1000, StubOnTimerCtx(states, processing=True, processing_time_ms=now_s * 1000)
    )
    assert len(op._buffers_state.keys()) == 0
    assert op._key_max_ts_state.value() is None


# ---------------------------------------------------------------------------
# Revision re-emit debounce (chain_reemit_debounce_seconds)
# ---------------------------------------------------------------------------
#
# Pre-debounce, EVERY post-threshold matching event re-emitted the full chain
# with a bumped revision — N events → ~N chains, each an LLM
# call downstream. Semantics under test:
# - first threshold-crossing emit is never delayed;
# - material re-emits inside the debounce window are suppressed + marked dirty;
# - the window-cleanup timer flushes ONE final revision for a dirty buffer;
# - non-material re-emits (capped-seq duplicate that only bumps
#   dropped_events) are suppressed outright when debounce>0;
# - debounce=0 reproduces the old emit-per-event behavior exactly (including
#   non-material re-emits — strict compat).

# Fixture window: events at ~09:31 bucket to window_start 1776850200 with the
# APT28 rule's 1800s timeframe → window_end 1776852000.
_FIXTURE_WINDOW_END_S = 1776852000
_T0_MS = 1_776_850_300_000  # processing time roughly aligned with event time


def test_debounce_first_threshold_emit_is_immediate(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    op, states, _ = _make_op(chain_reemit_debounce_seconds=30)
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)

    emitted: list[dict] = []
    for ev in events_apt28[:4]:
        emitted.extend(_process(op, states, ev, processing_time_ms=_T0_MS))
    assert len(emitted) == 1, "the threshold-crossing emit must not be delayed"
    assert emitted[0]["revision"] == 1
    assert op._metrics.get_counter("chain_reemits_suppressed_total", reason="debounce") == 0


def test_debounce_suppresses_burst_within_window(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    from app.operators.hos_correlation_function import _deserialize_buffer

    op, states, _ = _make_op(chain_reemit_debounce_seconds=30)
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)
    for ev in events_apt28[:4]:
        _process(op, states, ev, processing_time_ms=_T0_MS)

    # 5th event 5s later — material (new seq) but inside the 30s debounce.
    out5 = _process(op, states, events_apt28[4], processing_time_ms=_T0_MS + 5_000)
    assert out5 == []
    assert op._metrics.get_counter("chain_reemits_suppressed_total", reason="debounce") == 1
    # The buffer recorded the hit AND is flagged for the final flush.
    buf = _deserialize_buffer(op._buffers_state.get(op._buffers_state.keys()[0]))
    assert buf.pending_dirty is True
    assert buf.emitted_revision == 1
    assert len(buf.seqs_hit) == 5  # the suppressed hit is in state, not lost


def test_debounce_reemits_after_window_elapsed(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    op, states, _ = _make_op(chain_reemit_debounce_seconds=30)
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)
    emitted: list[dict] = []
    for ev in events_apt28[:4]:
        emitted.extend(_process(op, states, ev, processing_time_ms=_T0_MS))

    # Material 5th event AFTER the debounce window → re-emit allowed.
    out5 = _process(op, states, events_apt28[4], processing_time_ms=_T0_MS + 31_000)
    assert len(out5) == 1
    assert out5[0]["revision"] == 2
    assert out5[0]["chain_id"] == emitted[0]["chain_id"]
    assert out5[0]["coverage"] == pytest.approx(83.33)


def test_debounce_cleanup_flushes_final_dirty_revision(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """The window-cleanup timer must flush a final revision for a dirty buffer
    BEFORE deleting state — the last revision detectflow-backend consumes has to
    reflect the complete buffer, including all debounce-suppressed hits."""
    op, states, _ = _make_op(chain_reemit_debounce_seconds=30)
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)
    emitted: list[dict] = []
    for ev in events_apt28[:4]:
        emitted.extend(_process(op, states, ev, processing_time_ms=_T0_MS))
    assert [r["revision"] for r in emitted] == [1]

    # 5th event suppressed by the debounce → buffer dirty.
    assert _process(op, states, events_apt28[4], processing_time_ms=_T0_MS + 1_000) == []

    # GC tick past window_end + grace: flush, then delete.
    flush_s = _FIXTURE_WINDOW_END_S + op._cleanup_grace_s + 1
    ctx = StubOnTimerCtx(
        states,
        processing=True,
        processing_time_ms=flush_s * 1000,
        # The keyed timer fires under the buffer's hostname key — the flush
        # rebuilds the deterministic chain_id from it.
        current_key=events_apt28[0]["hostname"],
    )
    flushed = [json.loads(p) for p in op.on_timer(flush_s * 1000, ctx)]

    assert len(flushed) == 1, "dirty buffer must flush exactly one final revision"
    final = flushed[0]
    assert final["revision"] == 2  # continues the emitted sequence
    assert final["chain_id"] == emitted[0]["chain_id"]  # deterministic id preserved
    assert final["event_count"] == 5  # the suppressed 5th hit is included
    assert final["coverage"] == pytest.approx(83.33)
    assert op._metrics.get_counter("chains_emitted_total", hos_id=hos_envelope_apt28["id"]) == 2
    # State is gone after the flush (flush-then-delete, never flush-twice).
    assert len(op._buffers_state.keys()) == 0
    assert op._metrics.get_counter("buffers_expired") == 1


def test_debounce_cleanup_does_not_flush_clean_buffers(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """A buffer with no suppressed changes (or one that never crossed the
    threshold) is GC'd silently — no spurious final revision."""
    op, states, _ = _make_op(chain_reemit_debounce_seconds=30)
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)
    # Only 2 events → below threshold, never emitted, never dirty.
    for ev in events_apt28[:2]:
        _process(op, states, ev, processing_time_ms=_T0_MS)

    flush_s = _FIXTURE_WINDOW_END_S + op._cleanup_grace_s + 1
    ctx = StubOnTimerCtx(
        states,
        processing=True,
        processing_time_ms=flush_s * 1000,
        current_key=events_apt28[0]["hostname"],
    )
    assert op.on_timer(flush_s * 1000, ctx) == []
    assert len(op._buffers_state.keys()) == 0


def test_debounce_suppresses_non_material_reemit_outright(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """With debounce>0, a duplicate hit on an already-capped seq (only bumps
    `dropped_events`) must not re-emit even AFTER the debounce window — and
    must not mark the buffer dirty (there is nothing material to flush)."""
    from app.operators.hos_correlation_function import _deserialize_buffer

    op, states, _ = _make_op(chain_reemit_debounce_seconds=30, chain_max_events_per_seq=1)
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)
    emitted: list[dict] = []
    for ev in events_apt28[:4]:
        emitted.extend(_process(op, states, ev, processing_time_ms=_T0_MS))
    assert len(emitted) == 1

    # Same seq-1 rule again — seq already at the 1-event cap.
    dup = {**events_apt28[0], "event_id": "dup-1"}
    out = _process(op, states, dup, processing_time_ms=_T0_MS + 60_000)
    assert out == []
    assert (
        op._metrics.get_counter("chain_reemits_suppressed_total", reason="no_material_change") == 1
    )
    buf = _deserialize_buffer(op._buffers_state.get(op._buffers_state.keys()[0]))
    assert buf.pending_dirty is False
    assert buf.dropped_events == 1  # the duplicate is still accounted in state


def test_debounce_zero_reproduces_old_emit_per_event_behavior(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """debounce=0 is strict compat with the pre-debounce matcher: EVERY
    post-threshold matching event re-emits a bumped revision — including a
    non-material capped-seq duplicate (the no-material-change suppression is
    deliberately gated behind debounce>0)."""
    op, states, _ = _make_op(chain_reemit_debounce_seconds=0, chain_max_events_per_seq=1)
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)
    emitted: list[dict] = []
    for ev in events_apt28[:4]:
        emitted.extend(_process(op, states, ev, processing_time_ms=_T0_MS))
    assert [r["revision"] for r in emitted] == [1]

    # Non-material duplicate at the SAME processing instant → still re-emits.
    dup = {**events_apt28[0], "event_id": "dup-1"}
    out = _process(op, states, dup, processing_time_ms=_T0_MS)
    assert len(out) == 1
    assert out[0]["revision"] == 2
    assert op._metrics.get_counter("chain_reemits_suppressed_total", reason="debounce") == 0
    assert (
        op._metrics.get_counter("chain_reemits_suppressed_total", reason="no_material_change") == 0
    )


def test_buffer_serialization_is_backward_compatible_with_pre_debounce_state():
    """A buffer checkpointed by a pre-debounce build (no `last_emit_epoch` /
    `pending_dirty` keys) must restore with safe defaults — restored jobs keep
    their windows."""
    from app.operators.chain_buffer import BufferEntry
    from app.operators.hos_correlation_function import _deserialize_buffer, _serialize_buffer

    old_raw = json.dumps(
        {
            "window_start_epoch": 1_000_000,
            "window_end_epoch": 1_001_800,
            "last_activity_epoch": 1_000_100,
            "emitted_revision": 2,
            "dropped_events": 1,
            "seqs_hit": {"1": [{"rule_id": "r", "event": {"event_id": "e"}}]},
        },
        separators=(",", ":"),
    )
    buf = _deserialize_buffer(old_raw)
    assert buf.last_emit_epoch == 0  # debounce gate passes on the next re-emit
    assert buf.pending_dirty is False
    assert buf.emitted_revision == 2
    assert buf.seqs_hit[1] == [BufferEntry(rule_id="r", event={"event_id": "e"})]
    # Round-trip through the NEW serializer preserves everything.
    assert _deserialize_buffer(_serialize_buffer(buf)) == buf


# ---------------------------------------------------------------------------
# Per-event chains-config caching
# ---------------------------------------------------------------------------


class _GetCountingMapState(StubMapState):
    """StubMapState that counts point reads (.get)."""

    def __init__(self):
        super().__init__()
        self.gets = 0

    def get(self, k):
        self.gets += 1
        return super().get(k)


def test_chains_config_is_parsed_once_per_update_not_per_event(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """The config gates every main-stream event; the parsed blob must be cached
    on the operator (one broadcast-state read per config update, not one
    .get + json.loads per record) and invalidated when a new config broadcast
    lands — behavioral prospectivity is pinned separately by
    test_config_update_applies_prospectively_not_retroactively."""
    op, states, _ = _make_op()
    counting = _GetCountingMapState()
    states[CONFIG_STATE.get_name()] = counting
    _seed_apt28(op, states, hos_envelope_apt28, at_apt28, chains_config)
    assert counting.gets == 0  # seeding only writes

    for _ in range(10):
        _process(op, states, events_apt28[0])
    assert counting.gets == 1, "config must be read from broadcast state exactly once"

    # A config update invalidates the cache → exactly one more read.
    _broadcast(op, states, {**chains_config, "threshold_pct": 80, "_topic": CONFIG_TOPIC})
    for _ in range(5):
        _process(op, states, events_apt28[0])
    assert counting.gets == 2, "cache must be reloaded exactly once after the update"


# ---------------------------------------------------------------------------
# chains-config v2 — window override, AT deny-list, pipeline stamp
# ---------------------------------------------------------------------------
#
# Fixture geometry used below: the APT28 rule declares timeframe 1800s and the
# five events sit at ~2026-04-22T09:31 → window_start 09:30:00Z. A 3600s
# override re-buckets them onto 09:00:00Z, which is what makes the override
# observable end-to-end (window_start is part of the chain_id seed).

_RULE_WINDOW_START_ISO = "2026-04-22T09:30:00Z"  # rule timeframe 1800s
_OVERRIDE_WINDOW_START_ISO = "2026-04-22T09:00:00Z"  # override 3600s
_OVERRIDE_S = 3600
AT_ID_APT28 = "a7000000-0000-4000-8000-000000000028"


def _seed(op, states, hos_envelope, at, chains_config, **cfg_overrides):
    """Seed HoS + AT + a chains-config with explicit field overrides."""
    cfg = {**chains_config, **cfg_overrides}
    _broadcast(op, states, {**hos_envelope, "_topic": HOS_TOPIC})
    _broadcast(op, states, {**at, "_topic": AT_TOPIC})
    _broadcast(op, states, {**cfg, "_topic": CONFIG_TOPIC})


def _emit_all(op, states, events, **kwargs) -> list[dict]:
    return [out for ev in events for out in _process(op, states, ev, **kwargs)]


# ---- (a) window override ---------------------------------------------------


def test_config_window_override_wins_over_hos_timeframe(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """A non-null `correlation_window_seconds` is an EXPLICIT
    override that beats the rule's `detection.timeframe`. Observable through
    the bucket: 3600s re-buckets the 09:31 events onto the 09:00 window."""
    op, states, _ = _make_op()
    _seed(op, states, hos_envelope_apt28, at_apt28, chains_config, correlation_window_seconds=3600)
    emitted = _emit_all(op, states, events_apt28)
    assert emitted, "threshold must still be crossed under the override"
    assert emitted[-1]["window_start"] == _OVERRIDE_WINDOW_START_ISO
    assert op._metrics.get_counter(
        "chain_window_overridden_total", hos_id=hos_envelope_apt28["id"]
    ) == len(events_apt28)


def test_null_window_override_inherits_hos_timeframe(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """NULL ⇒ today's behaviour: the rule's 1800s timeframe still decides."""
    op, states, _ = _make_op()
    _seed(op, states, hos_envelope_apt28, at_apt28, chains_config, correlation_window_seconds=None)
    emitted = _emit_all(op, states, events_apt28)
    assert emitted[-1]["window_start"] == _RULE_WINDOW_START_ISO
    assert (
        op._metrics.get_counter("chain_window_overridden_total", hos_id=hos_envelope_apt28["id"])
        == 0
    )


@pytest.mark.parametrize("bad", [0, -1, "abc", True, {}])
def test_invalid_window_override_falls_back_to_hos_timeframe(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28, bad
):
    """A garbage override MUST NOT reach `bucket_window_start` — it raises
    ValueError, which escapes process_element, fails the job and crash-loops on
    Kafka redelivery of the same record. Degrade to "no override" + counter."""
    op, states, _ = _make_op()
    _seed(op, states, hos_envelope_apt28, at_apt28, chains_config, correlation_window_seconds=bad)
    emitted = _emit_all(op, states, events_apt28)  # must not raise
    assert emitted[-1]["window_start"] == _RULE_WINDOW_START_ISO
    assert op._metrics.get_counter("config_window_override_invalid_total") == 1


def test_window_override_change_rebuckets_and_mints_new_chain_id(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """Documented consequence of a deterministic id: changing the window at
    runtime re-buckets subsequent events, so the same attack appears as two
    chains either side of the change. Not a bug to work around."""
    op, states, _ = _make_op()
    _seed(op, states, hos_envelope_apt28, at_apt28, chains_config, correlation_window_seconds=None)
    before = _emit_all(op, states, events_apt28)
    assert before[-1]["window_start"] == _RULE_WINDOW_START_ISO

    _broadcast(
        op,
        states,
        {
            **chains_config,
            "correlation_window_seconds": _OVERRIDE_S,
            "_topic": CONFIG_TOPIC,
        },
    )
    after = _emit_all(op, states, events_apt28)
    assert after, "the re-bucketed window must reach the threshold on its own"
    assert after[-1]["window_start"] == _OVERRIDE_WINDOW_START_ISO
    assert after[-1]["chain_id"] != before[-1]["chain_id"]
    assert after[0]["revision"] == 1, "the re-bucketed window starts its own revision sequence"


def test_window_change_leaves_in_flight_buffer_to_drain_on_cleanup(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """In-flight buffers DRAIN, they are not discarded — a buffer persists its
    own `window_end_epoch`, so the processing-time GC still flushes its final
    revision under the ORIGINAL window after the config changed. Discarding
    would leave the control plane on a last revision that does not reflect the
    complete buffer."""
    op, states, _ = _make_op(chain_reemit_debounce_seconds=30)
    _seed(op, states, hos_envelope_apt28, at_apt28, chains_config, correlation_window_seconds=None)
    emitted = _emit_all(op, states, events_apt28[:4], processing_time_ms=_T0_MS)
    assert [r["revision"] for r in emitted] == [1]
    # 5th event suppressed by the debounce → buffer dirty, still on the old window.
    assert _process(op, states, events_apt28[4], processing_time_ms=_T0_MS + 1_000) == []

    _broadcast(
        op,
        states,
        {
            **chains_config,
            "correlation_window_seconds": _OVERRIDE_S,
            "_topic": CONFIG_TOPIC,
        },
    )

    flush_s = _FIXTURE_WINDOW_END_S + op._cleanup_grace_s + 1
    ctx = StubOnTimerCtx(
        states,
        processing=True,
        processing_time_ms=flush_s * 1000,
        current_key=events_apt28[0]["hostname"],
    )
    flushed = [json.loads(p) for p in op.on_timer(flush_s * 1000, ctx)]
    assert len(flushed) == 1, "the old-window buffer must still flush its final revision"
    assert flushed[0]["window_start"] == _RULE_WINDOW_START_ISO
    assert flushed[0]["chain_id"] == emitted[0]["chain_id"]
    assert flushed[0]["event_count"] == 5


def test_window_change_logs_and_counts_config_transition(
    hos_envelope_apt28, at_apt28, chains_config
):
    op, states, _ = _make_op()
    _seed(op, states, hos_envelope_apt28, at_apt28, chains_config, correlation_window_seconds=300)
    # First config an instance sees has no known predecessor — recorded, not counted.
    assert op._metrics.get_counter("chain_window_config_changes_total") == 0
    assert op._metrics.get_gauge("config_correlation_window_seconds") == 300

    _broadcast(
        op, states, {**chains_config, "correlation_window_seconds": 900, "_topic": CONFIG_TOPIC}
    )
    assert op._metrics.get_counter("chain_window_config_changes_total") == 1
    assert op._metrics.get_gauge("config_correlation_window_seconds") == 900

    # Re-publishing the same window is not a transition.
    _broadcast(
        op, states, {**chains_config, "correlation_window_seconds": 900, "_topic": CONFIG_TOPIC}
    )
    assert op._metrics.get_counter("chain_window_config_changes_total") == 1


# ---- (c) excluded_active_threat_ids — the deny-list --------------------------


def test_excluded_at_is_dropped_with_counter(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    op, states, _ = _make_op()
    _seed(
        op,
        states,
        hos_envelope_apt28,
        at_apt28,
        chains_config,
        excluded_active_threat_ids=[AT_ID_APT28],
    )
    assert _emit_all(op, states, events_apt28) == []
    assert op._metrics.get_counter("events_dropped_at_excluded") == len(events_apt28)


def test_excluded_at_drop_emits_no_activity_alert(
    monkeypatch, hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """An analyst-configured steady state, exactly like topic_filtered — a
    perpetual gated alert on detectflow.activity would desensitize the channel."""
    stub = _install_stub_reporter(monkeypatch)
    op, states, _ = _make_op()
    _seed(
        op,
        states,
        hos_envelope_apt28,
        at_apt28,
        chains_config,
        excluded_active_threat_ids=[AT_ID_APT28],
    )
    assert _emit_all(op, states, events_apt28) == []
    assert _activity_events(stub) == [], "at_excluded must never reach detectflow.activity"


@pytest.mark.parametrize("excluded", [_UNSET, None, []])
def test_absent_or_empty_exclusion_list_monitors_every_catalog_at(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28, excluded
):
    """Opt-OUT by construction: absent, null and [] all mean "nothing
    excluded". There is no branch that can mean "correlate nothing"."""
    overrides = {} if excluded is _UNSET else {"excluded_active_threat_ids": excluded}
    op, states, _ = _make_op()
    cfg = {k: v for k, v in chains_config.items() if k != "excluded_active_threat_ids"}
    _seed(op, states, hos_envelope_apt28, at_apt28, cfg, **overrides)
    assert _emit_all(op, states, events_apt28), "every catalogue AT is monitored by default"
    assert op._metrics.get_counter("events_dropped_at_excluded") == 0


def test_is_blocked_field_is_honoured_when_enabled_is_absent(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """The control plane's flag is `is_blocked`; older envelopes carry only
    `enabled`. Read whichever is present so neither repo has to land first."""
    blocked = {k: v for k, v in at_apt28.items() if k != "enabled"}
    blocked["is_blocked"] = True
    op, states, _ = _make_op()
    _seed(op, states, hos_envelope_apt28, blocked, chains_config)
    assert _emit_all(op, states, events_apt28) == []

    op2, states2, _ = _make_op()
    unblocked = {**blocked, "is_blocked": False}
    _seed(op2, states2, hos_envelope_apt28, unblocked, chains_config)
    assert _emit_all(op2, states2, events_apt28), "is_blocked=false must correlate"


@pytest.mark.parametrize("gate", ["excluded", "blocked"])
def test_pending_dirty_flush_applies_exclusion_and_block_gates(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28, gate
):
    """A buffer that went dirty BEFORE the exclusion/block was applied must not
    still flush one last revision for a threat that is no longer monitored."""
    op, states, _ = _make_op(chain_reemit_debounce_seconds=30)
    _seed(op, states, hos_envelope_apt28, at_apt28, chains_config)
    assert len(_emit_all(op, states, events_apt28[:4], processing_time_ms=_T0_MS)) == 1
    assert _process(op, states, events_apt28[4], processing_time_ms=_T0_MS + 1_000) == []

    if gate == "excluded":
        _broadcast(
            op,
            states,
            {
                **chains_config,
                "excluded_active_threat_ids": [AT_ID_APT28],
                "_topic": CONFIG_TOPIC,
            },
        )
    else:
        _broadcast(op, states, {**at_apt28, "is_blocked": True, "_topic": AT_TOPIC})

    flush_s = _FIXTURE_WINDOW_END_S + op._cleanup_grace_s + 1
    ctx = StubOnTimerCtx(
        states,
        processing=True,
        processing_time_ms=flush_s * 1000,
        current_key=events_apt28[0]["hostname"],
    )
    assert op.on_timer(flush_s * 1000, ctx) == []
    assert len(op._buffers_state.keys()) == 0, "the buffer is still GC'd, just not flushed"


# ---- (d) the correlation-pipeline stamp ------------------------------------


def test_chain_envelope_carries_correlation_pipeline_id_from_config(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    op, states, _ = _make_op(correlation_pipeline_id=PIPELINE_UUID)
    _seed(
        op,
        states,
        hos_envelope_apt28,
        at_apt28,
        chains_config,
        correlation_pipeline_id=PIPELINE_UUID,
        correlation_pipeline_name="Correlation Pipeline A",
    )
    emitted = _emit_all(op, states, events_apt28)
    assert emitted[-1]["correlation_pipeline_id"] == PIPELINE_UUID
    assert emitted[-1]["correlation_pipeline_name"] == "Correlation Pipeline A"


def test_chain_envelope_falls_back_to_settings_pipeline_id_when_config_lacks_it(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """Config-less cold start (or an old control plane): the
    CORRELATION_PIPELINE_ID env var is the fallback for both the stamp and the
    chain_id scope."""
    op, states, _ = _make_op(correlation_pipeline_id=PIPELINE_UUID)
    cfg = {k: v for k, v in chains_config.items() if k != "correlation_pipeline_id"}
    _seed(op, states, hos_envelope_apt28, at_apt28, cfg)
    emitted = _emit_all(op, states, events_apt28)
    assert emitted[-1]["correlation_pipeline_id"] == PIPELINE_UUID
    assert emitted[-1]["chain_id"] == build_chain_id(
        uuid.NAMESPACE_DNS,
        hos_envelope_apt28["id"],
        events_apt28[0]["hostname"],
        _RULE_WINDOW_START_ISO,
        PIPELINE_UUID,
    )


def test_chain_envelope_never_stamps_job_id(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """JOB_ID is the K8s deployment name (`corr-<uuid>`), NOT a UUID, and the
    control-plane consumer validates this field as a UUID — stamping it would
    make the consumer discard the whole record. `None` is the correct value for
    the legacy single-instance deployment, and the id stays the 3-part one."""
    op, states, _ = _make_op(job_id="corr-3f2b8c14-9f6a-4c3d-8f21-2a7b5c9d1e04")
    cfg = {k: v for k, v in chains_config.items() if k != "correlation_pipeline_id"}
    _seed(op, states, hos_envelope_apt28, at_apt28, cfg)
    emitted = _emit_all(op, states, events_apt28)
    assert emitted[-1]["correlation_pipeline_id"] is None
    assert emitted[-1]["chain_id"] == build_chain_id(
        uuid.NAMESPACE_DNS,
        hos_envelope_apt28["id"],
        events_apt28[0]["hostname"],
        _RULE_WINDOW_START_ISO,
    )


def test_envelope_pipeline_id_mismatch_increments_counter(
    hos_envelope_apt28, at_apt28, chains_config, events_apt28
):
    """The envelope this instance consumes belongs to a different pipeline —
    both chain_id and the stamp follow the envelope, so surface it rather than
    silently re-keying every chain the instance emits."""
    other = "8c41d0f7-6b52-4e19-a3d7-1f5c8e2b90a6"
    op, states, _ = _make_op(correlation_pipeline_id=PIPELINE_UUID)
    _seed(op, states, hos_envelope_apt28, at_apt28, chains_config, correlation_pipeline_id=other)
    emitted = _emit_all(op, states, events_apt28)
    assert op._metrics.get_counter("config_pipeline_id_mismatch_total") == 1
    assert emitted[-1]["correlation_pipeline_id"] == other, "the envelope wins"
