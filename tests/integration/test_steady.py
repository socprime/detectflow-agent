"""E2E scenario (a) — steady state.

Drives the steady-state APT28 burst end-to-end through the live stack:
events → correlation-job → chains-raw → agent-job (LLM stub) → chains-analysed.
Asserts on the final analysed chain.

This is the smoke gate for the whole pipeline. If this test passes, the
real session-cluster path works end to end — the agent-job submission worked, flink-agents
ran, the LLM stub was reachable, and the chain came out the other side
with the canned verdict.

Run with:

    make integration-up
    uv run pytest -m integration tests/integration/test_steady.py -v
"""

from __future__ import annotations

import uuid

import pytest

from app.config.settings import Settings
from app.core.chain_id import build_chain_id
from tests.integration.conftest import KAFKA_BOOTSTRAP, consume_chains
from tests.integration.producer import (
    CORRELATION_PIPELINE_ID,
    _make_producer,
    scenario_steady,
    seed_meta,
)

pytestmark = pytest.mark.integration


HOS_ID = "40500000-0000-4000-8000-000000000028"
HOSTNAME = "WKST-FIN-05"
WINDOW_START_ISO = "2026-04-22T09:30:00Z"


def test_steady_state_emits_analysed_chain(stack_ready, chains_analysed_consumer):
    producer = _make_producer(KAFKA_BOOTSTRAP)
    seed_meta(producer, consume_window=8.0)
    scenario_steady(producer, pace=0.2)

    # Threshold=60% is crossed at event 4 (4/6=66.67%) and again at event 5
    # (5/6=83.33%) — matcher emits on each crossing, so we expect 2 records.
    # Allow a little headroom for EOS commit timing.
    chains = consume_chains(
        chains_analysed_consumer,
        expected=2,
        timeout=120.0,
        match=lambda c: c.get("hostname") == HOSTNAME,
    )
    mine = [c for c in chains if c.get("hostname") == HOSTNAME]
    assert len(mine) >= 1, f"no chain for {HOSTNAME} on chains-analysed within timeout"

    # Take the latest revision — that's the post-event-5 emission.
    final = max(mine, key=lambda c: c.get("revision", 0))

    # ---- chain envelope invariants ---------------------------------------
    expected_chain_id = build_chain_id(
        uuid.UUID(
            Settings(kafka_bootstrap_servers="x", kafka_auth_method="PLAINTEXT").chain_id_namespace
        ),
        HOS_ID,
        HOSTNAME,
        WINDOW_START_ISO,
        CORRELATION_PIPELINE_ID,
    )
    assert final["chain_id"] == expected_chain_id, "chain_id MUST be deterministic"
    # The chain names its owning correlation pipeline, and the id is
    # scoped by it (never by JOB_ID, which is a deployment name, not a UUID).
    assert final["correlation_pipeline_id"] == CORRELATION_PIPELINE_ID
    assert final["hos_rule_id"] == HOS_ID
    assert final["hostname"] == HOSTNAME
    assert final["window_start"] == WINDOW_START_ISO
    assert final["coverage"] == pytest.approx(83.33, abs=0.01)
    assert final["revision"] >= 1

    # ---- AT inlined ----------------------------------------------------
    at = final.get("active_threat") or {}
    assert at.get("name") == "APT28"
    assert "summary" in at
    # Operational fields must be excluded by the AT-inline whitelist.
    for forbidden in ("id", "enabled", "monitored_topics", "release_date"):
        assert forbidden not in at, f"AT field {forbidden!r} leaked into chain envelope"

    # ---- LLM enrichment (canned by stub) ---------------------------------
    assert final["llm_verdict"] == "TRUE"
    assert final["llm_confidence"] == pytest.approx(0.92, abs=0.01)
    assert final["ai_summary"].startswith("Stub:")
    assert "review" in final["llm_review"] or isinstance(final["llm_review"], dict)
    assert final.get("analysed_at"), "analysed_at must be populated"

    # ---- events list grew with each emission -----------------------------
    assert final.get("event_count", 0) >= 4
    # Retired field: destination-topic names are not chain identity. Per-flow
    # identity is the detection pipeline stamped on every event.
    assert "pipeline_names" not in final
    for ev in final["events"]:
        assert ev.get("pipeline_id"), "every chain event must carry its detection pipeline"
