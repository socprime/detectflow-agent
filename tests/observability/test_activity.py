"""ActivityReporter — wire-contract, gating, disabled, and never-raises tests.

All tests run without a Kafka broker: a stub producer captures
``(topic, key, value)`` tuples, and the disabled path opens no producer at all.
"""

from __future__ import annotations

import json
from datetime import datetime
from uuid import UUID

import pytest

from app.config.settings import Settings
from app.observability.activity import (
    ENTITY_NAME_AGENT,
    ENTITY_NAME_CORRELATION,
    ActivityReporter,
    _FloodGate,
    get_activity_reporter,
    reset_activity_reporter,
)

PIPELINE_UUID = "3f2b8c14-9f6a-4c3d-8f21-2a7b5c9d1e04"
DEPLOYMENT_NAME = f"corr-{PIPELINE_UUID}"


class StubProducer:
    """Captures produced records in memory; never touches a broker."""

    def __init__(self, config: dict | None = None):
        self.config = config or {}
        self.records: list[tuple[str, bytes, bytes]] = []
        self.poll_calls = 0
        self.flush_calls = 0

    def produce(self, topic, key, value):
        self.records.append((topic, key, value))

    def poll(self, timeout):
        self.poll_calls += 1

    def flush(self, timeout=5.0):
        self.flush_calls += 1
        return 0


class BoomProducer(StubProducer):
    """Raises on every ``produce`` to exercise the never-raises guarantee."""

    def produce(self, topic, key, value):
        raise RuntimeError("broker exploded")


def _settings(**overrides) -> Settings:
    base = {
        "kafka_bootstrap_servers": "localhost:9092",
        "kafka_auth_method": "PLAINTEXT",
        "kafka_activity_topic": "detectflow.activity",
        "job_id": "agent-job",
    }
    base.update(overrides)
    return Settings(**base)


def _make_reporter(**overrides) -> tuple[ActivityReporter, StubProducer]:
    stub = StubProducer()
    reporter = ActivityReporter(
        _settings(**overrides),
        entity_name=ENTITY_NAME_AGENT,
        producer_factory=lambda config: stub,
    )
    return reporter, stub


def _decode(stub: StubProducer) -> list[dict]:
    return [json.loads(value.decode("utf-8")) for _topic, _key, value in stub.records]


# --------------------------------------------------------------------------
# Wire contract
# --------------------------------------------------------------------------


def test_required_fields_present_and_typed():
    reporter, stub = _make_reporter()
    reporter.emit_started()

    (event,) = _decode(stub)
    for field in ("id", "timestamp", "action", "entity_type"):
        assert field in event and event[field] is not None
    assert isinstance(event["id"], str)
    assert isinstance(event["timestamp"], str)
    assert event["action"] == "status_change"
    assert event["entity_type"] == "flink"


def test_id_is_valid_uuid4():
    reporter, stub = _make_reporter()
    reporter.emit_started()
    (event,) = _decode(stub)
    parsed = UUID(event["id"])
    assert parsed.version == 4
    assert str(parsed) == event["id"]


def test_timestamp_parses_as_iso8601_tz_aware():
    reporter, stub = _make_reporter()
    reporter.emit_started()
    (event,) = _decode(stub)
    ts = datetime.fromisoformat(event["timestamp"])
    assert ts.tzinfo is not None  # tz-aware, not epoch / naive


def test_entity_and_source_fields_for_flink():
    stub = StubProducer()
    reporter = ActivityReporter(
        _settings(job_id="correlation-job"),
        entity_name=ENTITY_NAME_CORRELATION,
        producer_factory=lambda config: stub,
    )
    reporter.emit_started()
    (event,) = _decode(stub)
    assert event["entity_type"] == "flink"
    assert event["entity_id"] == "correlation-job"
    # The instance label decorates the human name so N pipelines are tellable
    # apart in the audit log; with no pipeline vars the label falls back to the
    # deployment name.
    assert event["entity_name"] == f"{ENTITY_NAME_CORRELATION} [correlation-job]"
    assert event["source"] == "flink"
    assert event["user_id"] is None
    assert event["user_email"] is None


def test_severity_always_explicitly_set():
    reporter, stub = _make_reporter()
    reporter.emit_started()
    reporter.heartbeat()
    reporter.emit_alert("llm_throttled")
    reporter.emit_error("llm_unavailable")
    severities = [e["severity"] for e in _decode(stub)]
    assert severities == ["info", "info", "warning", "error"]
    assert all(s in ("info", "warning", "error") for s in severities)


def test_kafka_key_is_id_utf8():
    reporter, stub = _make_reporter()
    reporter.emit_started()
    topic, key, value = stub.records[0]
    assert topic == "detectflow.activity"
    event = json.loads(value.decode("utf-8"))
    assert key == event["id"].encode("utf-8")


def test_extra_data_lands_in_changes_never_top_level():
    reporter, stub = _make_reporter()
    reporter.emit_alert(
        "parse_drift",
        changes={"subtask": 3, "version": "3.1", "raw_len": 4096},
    )
    (event,) = _decode(stub)
    # Non-standard keys are confined to the changes dict.
    assert event["changes"]["subtask"] == 3
    assert event["changes"]["version"] == "3.1"
    assert event["changes"]["raw_len"] == 4096
    assert event["changes"]["reason"] == "parse_drift"
    allowed_top = {
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
    assert set(event.keys()) == allowed_top


def test_started_changes_default():
    reporter, stub = _make_reporter()
    reporter.emit_started()
    (event,) = _decode(stub)
    assert event["changes"] == {"status": {"old": "starting", "new": "running"}}


def test_heartbeat_details():
    reporter, stub = _make_reporter()
    reporter.heartbeat()
    (event,) = _decode(stub)
    assert event["details"] == "heartbeat"


# --------------------------------------------------------------------------
# Per-instance identity (one job pair per correlation pipeline)
# --------------------------------------------------------------------------


def _pipeline_reporter(**overrides) -> tuple[ActivityReporter, StubProducer]:
    stub = StubProducer()
    base = {
        "job_id": DEPLOYMENT_NAME,
        "correlation_pipeline_id": PIPELINE_UUID,
        "correlation_pipeline_name": "customer-a",
    }
    base.update(overrides)
    reporter = ActivityReporter(
        _settings(**base),
        entity_name=ENTITY_NAME_CORRELATION,
        producer_factory=lambda config: stub,
    )
    return reporter, stub


def test_pipeline_dimension_present_on_started_and_alert():
    reporter, stub = _pipeline_reporter()
    reporter.emit_started()
    reporter.emit_alert("hos_rule_rejected")

    started, alert = _decode(stub)
    for event in (started, alert):
        assert event["changes"]["correlation_pipeline"] == {
            "id": PIPELINE_UUID,
            "name": "customer-a",
        }
    # Merged, never replacing the caller's own keys.
    assert started["changes"]["status"] == {"old": "starting", "new": "running"}
    assert alert["changes"]["reason"] == "hos_rule_rejected"


def test_pipeline_dimension_rides_inside_changes_never_top_level():
    """The backend's consumer is extra="ignore" — a new TOP-LEVEL key would be
    silently dropped, so the dimension must live inside `changes`."""
    reporter, stub = _pipeline_reporter()
    reporter.emit_started()
    (event,) = _decode(stub)
    assert set(event.keys()) == {
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
    assert "correlation_pipeline" not in event


def test_entity_id_is_the_deployment_name_not_the_pipeline_uuid():
    """`JOB_ID` is `corr-<uuid>`, NOT a UUID. The control plane correlates on
    `entity_id` but parses `correlation_pipeline.id` as a UUID — swapping the
    two makes it discard records."""
    reporter, stub = _pipeline_reporter()
    reporter.emit_started()
    (event,) = _decode(stub)

    assert event["entity_id"] == DEPLOYMENT_NAME
    assert event["changes"]["correlation_pipeline"]["id"] == PIPELINE_UUID
    assert event["entity_id"] != event["changes"]["correlation_pipeline"]["id"]
    assert UUID(event["changes"]["correlation_pipeline"]["id"])  # parses as a UUID


def test_entity_name_carries_the_instance_label():
    reporter, stub = _pipeline_reporter()
    reporter.emit_started()
    (event,) = _decode(stub)
    assert event["entity_name"] == f"{ENTITY_NAME_CORRELATION} [customer-a]"


def test_pipeline_dimension_absent_without_pipeline_vars():
    """The legacy single-instance deployment: no dimension, and a bare
    heartbeat keeps `changes` at None rather than gaining an empty dict."""
    reporter, stub = _make_reporter()
    reporter.heartbeat()
    reporter.emit_started()

    heartbeat, started = _decode(stub)
    assert heartbeat["changes"] is None
    assert started["changes"] == {"status": {"old": "starting", "new": "running"}}
    assert "correlation_pipeline" not in started["changes"]


def test_bare_heartbeat_carries_the_dimension_when_pipeline_scoped():
    reporter, stub = _pipeline_reporter()
    reporter.heartbeat()
    (event,) = _decode(stub)
    assert event["changes"] == {"correlation_pipeline": {"id": PIPELINE_UUID, "name": "customer-a"}}


def test_pipeline_id_alone_is_enough():
    """`CORRELATION_PIPELINE_NAME` is optional — the id alone must still stamp
    the dimension (name stays null) and label the entity."""
    reporter, stub = _pipeline_reporter(correlation_pipeline_name=None)
    reporter.emit_started()
    (event,) = _decode(stub)
    assert event["changes"]["correlation_pipeline"] == {"id": PIPELINE_UUID, "name": None}
    assert event["entity_name"] == f"{ENTITY_NAME_CORRELATION} [{PIPELINE_UUID}]"


# --------------------------------------------------------------------------
# Anti-flood gate
# --------------------------------------------------------------------------


def test_flood_gate_suppresses_within_cooldown():
    clock = {"t": 1000.0}
    gate = _FloodGate(300, clock=lambda: clock["t"])
    assert gate.should_emit("drop:no_hits") is True
    assert gate.should_emit("drop:no_hits") is False
    clock["t"] += 299.0
    assert gate.should_emit("drop:no_hits") is False
    clock["t"] += 1.0  # now 300s elapsed
    assert gate.should_emit("drop:no_hits") is True


def test_flood_gate_distinct_keys_independent():
    gate = _FloodGate(300)
    assert gate.should_emit("a") is True
    assert gate.should_emit("b") is True


def test_gated_alert_suppressed_after_first_within_cooldown():
    reporter, stub = _make_reporter(activity_flood_cooldown_seconds=300)
    for _ in range(50):
        reporter.emit_alert("missing_hostname", flood_key="drop:missing_hostname")
    assert len(stub.records) == 1


def test_ungated_alerts_always_emit():
    reporter, stub = _make_reporter()
    for _ in range(5):
        reporter.emit_alert("hos_rule_rejected")
    assert len(stub.records) == 5


# --------------------------------------------------------------------------
# Disabled mode
# --------------------------------------------------------------------------


def test_disabled_mode_no_producer_and_noop():
    opened = {"count": 0}

    def factory(config):
        opened["count"] += 1
        return StubProducer(config)

    reporter = ActivityReporter(
        _settings(kafka_activity_topic=""),
        producer_factory=factory,
    )
    assert reporter.enabled is False
    reporter.emit_started()
    reporter.heartbeat()
    reporter.emit_error("boom")
    assert opened["count"] == 0  # no producer ever built


def test_disabled_mode_default_real_producer_never_built():
    # No producer_factory and disabled topic — must not import/construct a
    # real confluent_kafka.Producer (no broker in CI).
    reporter = ActivityReporter(_settings(kafka_activity_topic=""))
    reporter.emit_started()
    assert reporter._producer is None  # noqa: SLF001


# --------------------------------------------------------------------------
# Never raises
# --------------------------------------------------------------------------


def test_emit_never_raises_when_produce_throws():
    boom = BoomProducer()
    reporter = ActivityReporter(
        _settings(),
        producer_factory=lambda config: boom,
    )
    # Each of these would raise inside produce(); reporter must swallow.
    reporter.emit_started()
    reporter.heartbeat()
    reporter.emit_alert("x", flood_key="k")
    reporter.emit_error("y")
    # No records captured (produce raised), but no exception propagated.
    assert boom.records == []


# --------------------------------------------------------------------------
# Lazy per-worker singleton
# --------------------------------------------------------------------------


def test_get_activity_reporter_is_idempotent_singleton(monkeypatch):
    reset_activity_reporter()
    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    monkeypatch.setenv("KAFKA_AUTH_METHOD", "PLAINTEXT")
    monkeypatch.setenv("KAFKA_ACTIVITY_TOPIC", "detectflow.activity")
    monkeypatch.setenv("JOB_ID", "agent-job")
    from app.config import settings as settings_mod

    settings_mod.reload_settings()
    try:
        r1 = get_activity_reporter("Attack Chains Agent Job")
        r2 = get_activity_reporter("ignored-second-name")
        assert r1 is r2
    finally:
        reset_activity_reporter()
        settings_mod.reload_settings()


@pytest.fixture(autouse=True)
def _reset_singleton():
    reset_activity_reporter()
    yield
    reset_activity_reporter()
