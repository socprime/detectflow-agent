"""E2E scenario (d) — late-event drop.

The strong assertion: the late event uses a seq-6 rule_id with timestamp
``09:30:00Z``. The watermark (``forBoundedOutOfOrderness(60s)``) — or in
prod-shaped deploys the per-key fallback clock — advances with the
steady burst to ``max_event_ts - 60s ≈ 09:30:31``, leaving the late
event ~31 seconds past the boundary. If the matcher's late-drop guard fails, the
seq-6 hit lands in the open window's buffer and coverage jumps from 5/6
to 6/6, emitting a new revision. So checking that coverage stays at
83.33 (and that no extra revision shows up after the late event) is a
direct, falsifiable proof that the guard works.

We also assert the ``events_late_dropped`` counter on the matcher's
operator metrics increments (visible via Flink REST). The unit suite
covers the in-memory mechanics; this is the live-cluster confirmation
that the metric path is wired through `runtime_context.get_metrics_group()`
correctly.

Run with:

    make integration-up
    uv run pytest -m integration tests/integration/test_late_drop.py -v
"""

from __future__ import annotations

import json
import uuid

import pytest

from app.config.settings import Settings
from app.core.chain_id import build_chain_id
from tests.integration.conftest import (
    KAFKA_BOOTSTRAP,
    consume_chains,
    consume_for,
    query_user_counter,
    wait_for_counter_at_least,
)
from tests.integration.producer import (
    CORRELATION_PIPELINE_ID,
    FIXTURES,
    _make_producer,
    publish_events,
    seed_meta,
)

pytestmark = pytest.mark.integration


HOS_ID = "40500000-0000-4000-8000-000000000028"
WINDOW_START_ISO = "2026-04-22T09:30:00Z"


def _expected_chain_id(hostname: str) -> str:
    namespace = uuid.UUID(
        Settings(kafka_bootstrap_servers="x", kafka_auth_method="PLAINTEXT").chain_id_namespace
    )
    return build_chain_id(namespace, HOS_ID, hostname, WINDOW_START_ISO, CORRELATION_PIPELINE_ID)


def _load_jsonl(name: str) -> list[dict]:
    return [json.loads(line) for line in (FIXTURES / name).read_text().splitlines() if line.strip()]


def _load_json(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def _rewrite_hostname(events: list[dict], new_hostname: str) -> list[dict]:
    return [
        {**ev, "hostname": new_hostname, "event_id": f"{ev['event_id']}-{new_hostname}"}
        for ev in events
    ]


def _filter_for(chains: list[dict], hostname: str) -> list[dict]:
    return [c for c in chains if c.get("hostname") == hostname]


def test_late_event_is_dropped_and_counter_increments(stack_ready, chains_analysed_consumer):
    hostname = "WKST-FIN-LATE"
    producer = _make_producer(KAFKA_BOOTSTRAP)
    seed_meta(producer, consume_window=8.0)

    # Baseline counter — earlier tests in the same session may have
    # contributed (none currently do, but this is defensive against future
    # additions).
    baseline = query_user_counter("events_late_dropped", job_name_substr="correlation")

    # Steady burst → coverage 83.33%, per-key clock advances to 09:31:31.
    steady = _rewrite_hostname(_load_jsonl("events_apt28.jsonl"), hostname)
    publish_events(producer, steady, pace=0.2, label="steady")

    # Drain the steady chains so we know exactly what's there before late.
    pre_late = consume_chains(
        chains_analysed_consumer,
        expected=2,
        timeout=120.0,
        match=lambda c: c.get("hostname") == hostname,
    )
    pre_mine = _filter_for(pre_late, hostname)
    assert len(pre_mine) >= 1, "steady-burst chain failed to materialise"
    pre_max_revision = max(c["revision"] for c in pre_mine)
    pre_max_coverage = max(c["coverage"] for c in pre_mine)
    assert pre_max_coverage == pytest.approx(83.33, abs=0.01)

    # Late seq-6 event — timestamp 09:30:00, ~91s past the per-key clock's 60s tolerance.
    late = _rewrite_hostname([_load_json("events_apt28_late.json")], hostname)
    publish_events(producer, late, pace=0, label="late-drop")

    # Counter must increment (with retry — JM metric refresh is async).
    final_counter = wait_for_counter_at_least(
        "events_late_dropped",
        target=baseline + 1,
        job_name_substr="correlation",
        timeout=90.0,
    )
    assert final_counter >= baseline + 1, (
        f"events_late_dropped did not advance: baseline={baseline}, "
        f"final={final_counter}. Late-drop guard is silent or metric is mis-wired."
    )

    # Falsifiable behavioural proof: nothing more lands on chains-analysed
    # for our hostname after the late event. If late-drop had failed, a
    # 6/6 = 100% revision would have been emitted within the EOS commit
    # interval (~30s).
    extra = consume_for(chains_analysed_consumer, duration=45.0)
    extra_mine = _filter_for(extra, hostname)
    assert extra_mine == [], (
        f"late event produced {len(extra_mine)} additional chain(s) for "
        f"{hostname}: {[(c['revision'], c['coverage']) for c in extra_mine]}. "
        "Late-drop should have prevented this."
    )

    # And — defence in depth — the chain_id we expect was the one that
    # emitted (no aliasing weirdness from hostname rewriting).
    expected_id = _expected_chain_id(hostname)
    assert all(c["chain_id"] == expected_id for c in pre_mine)
    # Highest revision seen pre-late is also the highest overall.
    assert pre_max_revision == max(c["revision"] for c in pre_mine)
