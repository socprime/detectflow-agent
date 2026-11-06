"""ChainAnalysisAgent orchestration tests.

Anchor test: round-trip APT28 chain_raw fixture + mocked successful
LlmResult → output ChainAnalysed shape matches chain_analysed_apt28_v1
fixture (modulo `analysed_at` timestamp + LLM-decision fields).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from flink_agents.api.events.event import InputEvent
from pydantic import SecretStr

import app.observability.activity as activity_mod
import app.operators.correlation_agent as correlation_agent_mod
from app.config.settings import Settings
from app.observability.activity import ActivityReporter, reset_activity_reporter
from app.observability.metrics import Metrics
from app.operators.agent_prompt import PROMPT_BUILDER_VERSION
from app.operators.chain_models import ChainAnalysed, ChainRaw, LlmVerdict
from app.operators.correlation_agent import (
    LLM_UNAVAILABLE_SUMMARY,
    ChainAnalysisAgent,
    analyse_chain_raw,
)
from app.operators.llm_client import LlmResult

FIXTURES_DIR = Path(__file__).parents[1] / "fixtures" / "attack-chains"


@pytest.fixture(autouse=True)
def _disabled_activity_reporter():
    """Pin a disabled (no-op) activity reporter for orchestration tests.

    ``analyse_chain_raw`` now emits job-health events through the per-process
    ``get_activity_reporter()`` singleton. These unit tests must stay hermetic
    (no real Kafka producer), so we install a disabled reporter (empty activity
    topic) and reset the singleton afterward.
    """
    reset_activity_reporter()
    disabled = ActivityReporter(
        Settings(
            kafka_bootstrap_servers="localhost:9092",
            kafka_auth_method="PLAINTEXT",
            kafka_activity_topic="",
        ),
        entity_name="Attack Chains Agent Job",
    )
    activity_mod._reporter = disabled
    yield
    reset_activity_reporter()


def _settings() -> Settings:
    return Settings(
        kafka_bootstrap_servers="localhost:9092",
        kafka_auth_method="PLAINTEXT",
        llm_api_key=SecretStr("test"),
        llm_prompt_char_budget=24_000,
        llm_calls_per_minute=60,
        llm_max_retries=3,
    )


def _chain_raw() -> ChainRaw:
    return ChainRaw.model_validate(
        json.loads((FIXTURES_DIR / "chain_raw_apt28_v1.json").read_text())
    )


def _mock_client(result: LlmResult) -> MagicMock:
    client = MagicMock()
    client.analyse.return_value = result
    return client


# ---------------------------------------------------------------------------
# Anchor — success path matches fixture-shape
# ---------------------------------------------------------------------------


def test_anchor_success_path_matches_fixture_shape():
    chain = _chain_raw()
    fixture_analysed = json.loads((FIXTURES_DIR / "chain_analysed_apt28_v1.json").read_text())

    llm_text = json.dumps(
        {
            "verdict": "TRUE",
            "confidence": fixture_analysed["llm_confidence"],
            "summary": fixture_analysed["ai_summary"],
            "review": fixture_analysed["llm_review"],
        }
    )
    metrics = Metrics()

    analysed = analyse_chain_raw(
        chain,
        llm_client=_mock_client(LlmResult.success(text=llm_text)),
        metrics=metrics,
        settings=_settings(),
    )

    # Identity fields propagate 1:1
    assert analysed.chain_id == fixture_analysed["chain_id"]
    assert analysed.revision == fixture_analysed["revision"]
    assert analysed.hostname == fixture_analysed["hostname"]
    assert analysed.window_start == fixture_analysed["window_start"]
    assert analysed.coverage == fixture_analysed["coverage"]
    # AT block inlined unchanged
    assert (
        analysed.active_threat.model_dump()
        == ChainAnalysed.model_validate(fixture_analysed).active_threat.model_dump()
    )
    # LLM enrichment matches fixture for the analyst-facing fields.
    assert analysed.llm_verdict is LlmVerdict.TRUE
    assert analysed.llm_confidence == fixture_analysed["llm_confidence"]
    assert analysed.ai_summary == fixture_analysed["ai_summary"]
    # llm_review carries the fixture's free-form fields *plus* prompt-builder audit
    # fields (aggregation_summary, prompt_builder_version,
    # aggregation_method, missing_context) — check subset, not equality.
    for k in ("reasoning", "indicators", "recommended_actions"):
        assert analysed.llm_review[k] == fixture_analysed["llm_review"][k]
    assert "aggregation_summary" in analysed.llm_review
    assert analysed.llm_review["prompt_builder_version"] == "3.2"
    assert analysed.llm_review["aggregation_method"] == "one_per_group_per_pipeline"
    assert analysed.llm_review["log_sources_capped"] == 0
    assert analysed.llm_review["missing_context"] == []
    # Timestamp set at emit time
    assert analysed.analysed_at.endswith("Z")
    assert metrics.get_counter("chains_emitted_total", verdict="TRUE") == 1


# ---------------------------------------------------------------------------
# All three LlmResult shapes round-trip into a valid ChainAnalysed
# ---------------------------------------------------------------------------


def test_throttled_result_emits_full_envelope_with_null_verdict():
    chain = _chain_raw()
    metrics = Metrics()

    analysed = analyse_chain_raw(
        chain,
        llm_client=_mock_client(LlmResult.throttled("local_rate_limit")),
        metrics=metrics,
        settings=_settings(),
    )

    # Full envelope shape — all chains-raw fields + null-verdict trio.
    assert analysed.chain_id == chain.chain_id
    assert analysed.revision == chain.revision
    assert analysed.events == chain.events
    assert analysed.llm_verdict is None
    assert analysed.llm_confidence is None
    assert analysed.ai_summary == LLM_UNAVAILABLE_SUMMARY
    assert analysed.llm_review["error"] == "local_rate_limit"
    assert analysed.llm_review["status"] == "throttled"
    assert analysed.analysed_at.endswith("Z")
    assert metrics.get_counter("chains_emitted_total", verdict="null", llm_status="throttled") == 1


def test_unavailable_result_emits_full_envelope_with_null_verdict():
    chain = _chain_raw()
    metrics = Metrics()

    analysed = analyse_chain_raw(
        chain,
        llm_client=_mock_client(
            LlmResult.unavailable("InternalServerError: 503", attempts=4, status="error")
        ),
        metrics=metrics,
        settings=_settings(),
    )

    assert analysed.llm_verdict is None
    assert analysed.llm_confidence is None
    assert analysed.ai_summary == LLM_UNAVAILABLE_SUMMARY
    assert "InternalServerError" in analysed.llm_review["error"]
    assert analysed.llm_review["attempts"] == 4
    assert analysed.llm_review["status"] == "error"
    assert metrics.get_counter("chains_emitted_total", verdict="null", llm_status="error") == 1


def test_success_with_drift_response_marks_parse_failed_in_review():
    """LLM returned bytes but they didn't parse — verdict still SUSPICIOUS
    (parser fallback), but the drift is flagged in review for triage."""
    chain = _chain_raw()
    metrics = Metrics()

    analysed = analyse_chain_raw(
        chain,
        llm_client=_mock_client(LlmResult.success(text="not json at all")),
        metrics=metrics,
        settings=_settings(),
    )

    assert analysed.llm_verdict is LlmVerdict.SUSPICIOUS
    assert analysed.ai_summary.startswith("LLM output unparsable")
    assert analysed.llm_review["parse_failed"] is True
    assert analysed.llm_review["fallback_reason"]
    assert metrics.get_counter("chains_emitted_total", verdict="parse_failed") == 1


# ---------------------------------------------------------------------------
# Identity preservation invariants
# ---------------------------------------------------------------------------


def test_chain_id_and_revision_propagate_unchanged():
    chain = _chain_raw()
    metrics = Metrics()

    success = analyse_chain_raw(
        chain,
        llm_client=_mock_client(
            LlmResult.success(
                text='{"verdict":"TRUE","confidence":0.5,"summary":"x","review":{"reasoning":"y"}}'
            )
        ),
        metrics=metrics,
        settings=_settings(),
    )
    throttled = analyse_chain_raw(
        chain,
        llm_client=_mock_client(LlmResult.throttled("x")),
        metrics=metrics,
        settings=_settings(),
    )
    unavailable = analyse_chain_raw(
        chain,
        llm_client=_mock_client(LlmResult.unavailable("x", attempts=3, status="timeout")),
        metrics=metrics,
        settings=_settings(),
    )

    for a in (success, throttled, unavailable):
        assert a.chain_id == chain.chain_id
        assert a.revision == chain.revision
        assert a.hos_rule_id == chain.hos_rule_id
        assert a.active_threat_id == chain.active_threat_id


def test_analysed_at_is_set_at_emit_time_not_parse_time():
    """analysed_at reflects the moment the LLM call returned, not
    chain construction. Two consecutive analyses produce monotonically
    non-decreasing timestamps."""
    chain = _chain_raw()
    metrics = Metrics()
    text = '{"verdict":"TRUE","confidence":0.5,"summary":"x","review":{"reasoning":"y"}}'

    a1 = analyse_chain_raw(
        chain,
        llm_client=_mock_client(LlmResult.success(text=text)),
        metrics=metrics,
        settings=_settings(),
    )
    a2 = analyse_chain_raw(
        chain,
        llm_client=_mock_client(LlmResult.success(text=text)),
        metrics=metrics,
        settings=_settings(),
    )
    assert a1.analysed_at <= a2.analysed_at
    # ISO 8601 UTC with Z suffix
    assert a1.analysed_at.endswith("Z")


# ---------------------------------------------------------------------------
# Output is fully serializable
# ---------------------------------------------------------------------------


def test_output_round_trips_through_json():
    """Anchor: the agent's output must be JSON-round-trippable so the
    SimpleStringSchema sink can serialize it."""
    chain = _chain_raw()
    metrics = Metrics()

    analysed = analyse_chain_raw(
        chain,
        llm_client=_mock_client(LlmResult.throttled("x")),
        metrics=metrics,
        settings=_settings(),
    )

    json_str = analysed.model_dump_json()
    reparsed = ChainAnalysed.model_validate_json(json_str)

    assert reparsed.chain_id == analysed.chain_id
    assert reparsed.llm_verdict is None
    assert reparsed.ai_summary == LLM_UNAVAILABLE_SUMMARY


# ---------------------------------------------------------------------------
# Prompt builder receives the configured budget
# ---------------------------------------------------------------------------


def test_llm_client_called_with_built_prompt():
    chain = _chain_raw()
    metrics = Metrics()
    client = MagicMock()
    client.analyse.return_value = LlmResult.success(
        text='{"verdict":"TRUE","confidence":0.5,"summary":"x","review":{"reasoning":"y"}}'
    )

    analyse_chain_raw(chain, llm_client=client, metrics=metrics, settings=_settings())

    client.analyse.assert_called_once()
    system, user = client.analyse.call_args.args
    assert "SOC analyst" in system
    assert "WKST-FIN-05" in user
    assert "APT28" in user


# ---------------------------------------------------------------------------
# Aggregation telemetry + INSUFFICIENT_CONTEXT verdict path
# ---------------------------------------------------------------------------


def _burst_chain() -> ChainRaw:
    return ChainRaw.model_validate(
        json.loads((FIXTURES_DIR / "chain_raw_burst_netloader.json").read_text())
    )


def test_llm_review_carries_aggregation_summary_and_version():
    """Every analysed chain — success or unavailable — must carry the
    aggregation audit fields so detectflow-backend can reproduce what the LLM saw."""
    chain = _burst_chain()
    metrics = Metrics()

    analysed = analyse_chain_raw(
        chain,
        llm_client=_mock_client(
            LlmResult.success(
                text='{"verdict":"TRUE","confidence":0.6,"summary":"x","review":{"reasoning":"y"}}'
            )
        ),
        metrics=metrics,
        settings=_settings(),
    )

    review = analysed.llm_review
    assert isinstance(review["aggregation_summary"], list)
    assert len(review["aggregation_summary"]) >= 1
    # NetLoader burst is 13 events on one (seq, rule_id); strict-collapse
    # depends on event.code variance — at minimum one group is present and
    # the cascade method is recorded.
    entry = review["aggregation_summary"][0]
    for k in (
        "seq",
        "sigma_rule_id",
        "pipeline_id",
        "event_count",
        "event_ids",
        "first_seen",
        "last_seen",
    ):
        assert k in entry
    # `collapsed_strict` is gone under the v2 single-mode renderer.
    assert "collapsed_strict" not in entry
    assert "source_topic" not in entry
    assert review["prompt_builder_version"] == PROMPT_BUILDER_VERSION
    assert review["aggregation_method"] == "one_per_group_per_pipeline"
    assert review["log_sources_capped"] == 0


def test_aggregation_audit_fields_present_on_unavailable_path():
    """Throttled/unavailable LLM still emits the audit shape — detectflow-backend
    must be able to inspect what the prompt would have looked like."""
    chain = _burst_chain()
    metrics = Metrics()

    analysed = analyse_chain_raw(
        chain,
        llm_client=_mock_client(LlmResult.throttled("local_rate_limit")),
        metrics=metrics,
        settings=_settings(),
    )

    assert analysed.llm_verdict is None
    assert analysed.llm_review["prompt_builder_version"] == PROMPT_BUILDER_VERSION
    assert "aggregation_summary" in analysed.llm_review
    assert analysed.llm_review["missing_context"] == []


def test_insufficient_context_verdict_flows_through():
    """LLM emits INSUFFICIENT_CONTEXT with missing_context — verdict
    propagates, missing_context lands in llm_review, counter bumps."""
    chain = _chain_raw()
    metrics = Metrics()

    llm_text = json.dumps(
        {
            "verdict": "INSUFFICIENT_CONTEXT",
            "confidence": 0.2,
            "summary": "Cannot decide — most events were aggregated.",
            "review": {
                "reasoning": "Without per-event destination IPs the chain is ambiguous.",
                "indicators": [],
                "recommended_actions": [],
                "missing_context": [
                    "destination IPs for events in group seq=1",
                    "full command_line for evt-002",
                ],
            },
        }
    )

    analysed = analyse_chain_raw(
        chain,
        llm_client=_mock_client(LlmResult.success(text=llm_text)),
        metrics=metrics,
        settings=_settings(),
    )

    assert analysed.llm_verdict is LlmVerdict.INSUFFICIENT_CONTEXT
    assert analysed.llm_review["missing_context"] == [
        "destination IPs for events in group seq=1",
        "full command_line for evt-002",
    ]
    assert metrics.get_counter("chains_emitted_total", verdict="INSUFFICIENT_CONTEXT") == 1


def test_insufficient_context_accepted_when_at_top_level():
    """LLM may put `missing_context` at the top level (sibling of `review`)
    instead of nesting it — both shapes round-trip through to llm_review."""
    chain = _chain_raw()
    metrics = Metrics()

    llm_text = json.dumps(
        {
            "verdict": "INSUFFICIENT_CONTEXT",
            "confidence": 0.25,
            "summary": "Cannot decide — burst was aggregated.",
            "review": {"reasoning": "Too aggregated."},
            "missing_context": ["raw process tree for evt-003"],
        }
    )

    analysed = analyse_chain_raw(
        chain,
        llm_client=_mock_client(LlmResult.success(text=llm_text)),
        metrics=metrics,
        settings=_settings(),
    )

    assert analysed.llm_verdict is LlmVerdict.INSUFFICIENT_CONTEXT
    assert analysed.llm_review["missing_context"] == ["raw process tree for evt-003"]


def test_aggregation_method_metric_emitted_per_chain():
    """Per-chain counter bumps regardless of LLM outcome. Only
    `method="one_per_group_per_pipeline"` ever fires; retired labels
    (`strict`, `loose`, `loose_capped`, `loose_dropped`,
    `one_per_group`, `one_per_group_per_source`) never bump."""
    chain = _chain_raw()
    metrics = Metrics()

    analyse_chain_raw(
        chain,
        llm_client=_mock_client(LlmResult.throttled("local_rate_limit")),
        metrics=metrics,
        settings=_settings(),
    )

    assert (
        metrics.get_counter("chain_aggregation_method_total", method="one_per_group_per_pipeline")
        == 1
    )
    for stale in (
        "strict",
        "loose",
        "loose_capped",
        "loose_dropped",
        "one_per_group",
        "one_per_group_per_source",
    ):
        assert metrics.get_counter("chain_aggregation_method_total", method=stale) == 0
    # The removed cascade-only counters never fire.
    assert metrics.get_counter("chain_events_per_group_capped_total") == 0
    assert metrics.get_counter("chain_groups_dropped_total") == 0
    # `chain_log_sources_capped_total` only fires when the cap kicks in;
    # the APT28 fixture has 5 distinct (seq, rule) groups each with
    # exactly one pipeline_id, so no cap.
    assert metrics.get_counter("chain_log_sources_capped_total") == 0


# ---------------------------------------------------------------------------
# Job-health activity wiring — degradation seams emit on detectflow.activity.
# These override the module-level disabled-reporter fixture with an enabled
# stub-backed reporter and assert the emitted ActivityEvent shape.
# ---------------------------------------------------------------------------


class _StubProducer:
    """Captures produced records in memory; never touches a broker."""

    def __init__(self, config: dict | None = None):
        self.records: list[tuple[str, bytes, bytes]] = []

    def produce(self, topic, key, value):
        self.records.append((topic, key, value))

    def poll(self, timeout):
        pass

    def flush(self, timeout=5.0):
        return 0


def _install_stub_reporter() -> _StubProducer:
    """Pin an *enabled* stub-backed activity reporter as the module singleton."""
    stub = _StubProducer()
    reporter = ActivityReporter(
        Settings(
            kafka_bootstrap_servers="localhost:9092",
            kafka_auth_method="PLAINTEXT",
            kafka_activity_topic="detectflow.activity",
            job_id="agent-job",
        ),
        entity_name="Attack Chains Agent Job",
        producer_factory=lambda config: stub,
    )
    activity_mod._reporter = reporter
    return stub


def _events(stub: _StubProducer) -> list[dict]:
    return [json.loads(value.decode("utf-8")) for _topic, _key, value in stub.records]


def test_throttled_emits_activity_alert():
    stub = _install_stub_reporter()
    chain = _chain_raw()

    analyse_chain_raw(
        chain,
        llm_client=_mock_client(LlmResult.throttled("local_rate_limit")),
        metrics=Metrics(),
        settings=_settings(),
    )

    events = _events(stub)
    assert len(events) == 1
    evt = events[0]
    assert evt["action"] == "alert"
    assert evt["severity"] == "warning"
    assert evt["entity_type"] == "flink"
    assert evt["changes"]["reason"] == "llm_throttled"
    assert evt["changes"]["chain_id"] == chain.chain_id
    assert evt["changes"]["status"] == "throttled"


def test_unavailable_emits_activity_error():
    stub = _install_stub_reporter()
    chain = _chain_raw()

    analyse_chain_raw(
        chain,
        llm_client=_mock_client(
            LlmResult.unavailable("InternalServerError: 503", attempts=4, status="error")
        ),
        metrics=Metrics(),
        settings=_settings(),
    )

    events = _events(stub)
    assert len(events) == 1
    evt = events[0]
    assert evt["action"] == "error"
    assert evt["severity"] == "error"
    assert evt["changes"]["reason"] == "llm_unavailable"
    assert evt["changes"]["chain_id"] == chain.chain_id
    assert evt["changes"]["status"] == "error"
    assert evt["changes"]["attempts"] == 4


def test_timeout_status_routes_to_error_seam():
    stub = _install_stub_reporter()
    chain = _chain_raw()

    analyse_chain_raw(
        chain,
        llm_client=_mock_client(LlmResult.unavailable("ReadTimeout", attempts=3, status="timeout")),
        metrics=Metrics(),
        settings=_settings(),
    )

    events = _events(stub)
    assert len(events) == 1
    assert events[0]["action"] == "error"
    assert events[0]["changes"]["status"] == "timeout"


def test_parse_drift_emits_activity_alert():
    stub = _install_stub_reporter()
    chain = _chain_raw()

    analyse_chain_raw(
        chain,
        llm_client=_mock_client(LlmResult.success(text="not json at all")),
        metrics=Metrics(),
        settings=_settings(),
    )

    events = _events(stub)
    assert len(events) == 1
    evt = events[0]
    assert evt["action"] == "alert"
    assert evt["severity"] == "warning"
    assert evt["changes"]["reason"] == "llm_parse_drift"
    assert evt["changes"]["chain_id"] == chain.chain_id
    assert evt["changes"]["fallback_reason"]
    # The existing parse_failed behaviour is unchanged.


def test_success_emits_no_activity_event():
    stub = _install_stub_reporter()
    chain = _chain_raw()

    analyse_chain_raw(
        chain,
        llm_client=_mock_client(
            LlmResult.success(
                text='{"verdict":"TRUE","confidence":0.5,"summary":"x","review":{"reasoning":"y"}}'
            )
        ),
        metrics=Metrics(),
        settings=_settings(),
    )

    assert _events(stub) == []


# ---------------------------------------------------------------------------
# ChainAnalysisAgent action — poison-pill tolerance of the input branches.
# flink-agents runs with error-handling-strategy=FAIL, so an exception
# escaping the @action restarts the job onto the same record forever.
# Malformed inputs must be dropped (logged + counted), never raised.
# ---------------------------------------------------------------------------


@pytest.fixture()
def _configured_agent(monkeypatch):
    """Wire module-level agent deps with stubs; restore pristine state after.

    ``_heartbeat_started`` is pinned True so the action does not spawn the
    per-worker heartbeat daemon thread inside a unit test.
    """
    monkeypatch.setattr(correlation_agent_mod, "_heartbeat_started", True)
    metrics = Metrics()
    client = _mock_client(
        LlmResult.success(
            text='{"verdict":"TRUE","confidence":0.5,"summary":"x","review":{"reasoning":"y"}}'
        )
    )
    correlation_agent_mod.configure(llm_client=client, metrics=metrics, settings=_settings())
    yield metrics, client
    monkeypatch.setattr(correlation_agent_mod, "_llm_client", None)
    monkeypatch.setattr(correlation_agent_mod, "_metrics", None)
    monkeypatch.setattr(correlation_agent_mod, "_settings", None)


def _run_action(raw_input) -> MagicMock:
    """Invoke the @action directly with a stub RunnerContext; return the ctx."""
    ctx = MagicMock()
    ChainAnalysisAgent.analyse_input(InputEvent(input=raw_input), ctx)
    return ctx


def test_agent_action_emits_for_valid_string_input(_configured_agent):
    """Positive control — a valid chains-raw JSON string flows through."""
    metrics, _client = _configured_agent
    ctx = _run_action(_chain_raw().model_dump_json())

    ctx.send_event.assert_called_once()
    assert metrics.get_counter("chains_dropped_invalid_input_total", reason="validation_error") == 0


@pytest.mark.parametrize(
    "malformed",
    [
        "not json at all",
        '{"_probe": "kafka-health-check"}',
        "{}",
    ],
)
def test_agent_action_drops_malformed_string_without_raising(_configured_agent, malformed):
    metrics, _client = _configured_agent
    ctx = _run_action(malformed)

    ctx.send_event.assert_not_called()
    assert metrics.get_counter("chains_dropped_invalid_input_total", reason="validation_error") == 1


def test_agent_action_drops_malformed_dict_without_raising(_configured_agent):
    metrics, _client = _configured_agent
    ctx = _run_action({"chain_id": "x"})  # valid dict, missing required fields

    ctx.send_event.assert_not_called()
    assert metrics.get_counter("chains_dropped_invalid_input_total", reason="validation_error") == 1


def test_agent_action_counts_unrecognised_input_type(_configured_agent):
    """Previously a silent drop — now logged + counted so a bridge-contract
    change upstream is observable."""
    metrics, _client = _configured_agent
    ctx = _run_action(12345)

    ctx.send_event.assert_not_called()
    assert (
        metrics.get_counter("chains_dropped_invalid_input_total", reason="unrecognised_type") == 1
    )
