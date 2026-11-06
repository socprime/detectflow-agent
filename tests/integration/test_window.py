"""E2E scenarios (b) window-update and (c) window-expiry.

Both reuse the steady APT28 burst but pin to a unique hostname per scenario
so the matcher's keyed state doesn't collide with `test_steady` (or with
each other) within the same session. Chain IDs are deterministic per
``(hos_id, hostname, window_start)``, so each scenario gets its own chain
trail on the analysed topic.

Run with:

    make integration-up
    uv run pytest -m integration tests/integration/test_window.py -v
"""

from __future__ import annotations

import json
import time
import uuid

import pytest

from app.config.settings import Settings
from app.core.chain_id import build_chain_id
from tests.integration.conftest import KAFKA_BOOTSTRAP, consume_chains
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
    """Pin events to a test-unique hostname, preserving timestamps + rule_ids
    so coverage and seq-matching behave identically. event_id is suffixed to
    keep records unique across tests / re-runs."""
    return [
        {**ev, "hostname": new_hostname, "event_id": f"{ev['event_id']}-{new_hostname}"}
        for ev in events
    ]


def _filter_for(chains: list[dict], hostname: str) -> list[dict]:
    return [c for c in chains if c.get("hostname") == hostname]


# ---------------------------------------------------------------------------
# Scenario (b) — window update
# ---------------------------------------------------------------------------


def test_window_update_emits_higher_revision_same_chain_id(stack_ready, chains_analysed_consumer):
    """Steady burst → seq-6 within the same window → revision bumps with the
    same deterministic chain_id, coverage rises to 6/6 = 100%."""
    hostname = "WKST-FIN-UPDATE"
    producer = _make_producer(KAFKA_BOOTSTRAP)
    seed_meta(producer, consume_window=8.0)

    steady = _rewrite_hostname(_load_jsonl("events_apt28.jsonl"), hostname)
    publish_events(producer, steady, pace=0.2, label="steady")
    # Small wall-clock gap so revision-1/2 land before the seq-6 event lifts
    # coverage to 100% — pure observability convenience for the harness.
    time.sleep(2.0)
    seq6 = _rewrite_hostname([_load_json("events_apt28_seq6.json")], hostname)
    publish_events(producer, seq6, pace=0, label="seq6")

    # Expect 3 emissions (rev1@66.67, rev2@83.33, rev3@100). Allow one less
    # in case the matcher batches a step at startup.
    chains = consume_chains(
        chains_analysed_consumer,
        expected=3,
        timeout=150.0,
        match=lambda c: c.get("hostname") == hostname,
    )
    mine = _filter_for(chains, hostname)
    assert len(mine) >= 2, f"expected >=2 emissions for {hostname}, got {len(mine)}"

    expected_id = _expected_chain_id(hostname)
    assert all(c["chain_id"] == expected_id for c in mine), (
        "every emission for the same window MUST share the same chain_id "
        "(drives idempotent upsert downstream)"
    )

    # Revision must be monotonic per chain.
    revisions = [c["revision"] for c in mine]
    assert revisions == sorted(revisions), f"revisions must increase monotonically, got {revisions}"

    final = max(mine, key=lambda c: c["revision"])
    assert final["coverage"] == pytest.approx(100.0, abs=0.01), (
        "seq-6 within window MUST close coverage to 100%"
    )
    # Events list grew across emissions.
    assert final["event_count"] >= 5
    # AT still inlined on the post-update emission (regression guard).
    assert final["active_threat"]["name"] == "APT28"


# ---------------------------------------------------------------------------
# Scenario (c) — window expiry
# ---------------------------------------------------------------------------


def test_window_expiry_advances_watermark_no_phantom_chain(stack_ready, chains_analysed_consumer):
    """Steady burst on hostname H → tick event past ``window_start +
    timeframe`` on a throwaway hostname with a rule_id outside the HoS index.

    Observable expectations on chains-analysed:
    - H sees its steady-burst chains as usual (final coverage 83.33).
    - The tick produces no chain (its rule_id isn't in the inverted index;
      `events_dropped_no_hits` increments instead).
    - No phantom revisions appear for H after the tick (the buffer was
      cleared by `on_timer`, and even if it weren't, the tick's timestamp
      lives in a different window bucket).

    Internal state cleanup (the `buffers_expired` counter on the matcher)
    is exercised by the unit suite (`test_on_timer_clears_expired_buffers`).
    The integration-level signal here is "the job survives expiry without
    emitting noise".
    """
    hostname = "WKST-FIN-EXPIRY"
    producer = _make_producer(KAFKA_BOOTSTRAP)
    seed_meta(producer, consume_window=8.0)

    steady = _rewrite_hostname(_load_jsonl("events_apt28.jsonl"), hostname)
    publish_events(producer, steady, pace=0.2, label="steady")
    time.sleep(2.0)

    # Tick keeps its OWN throwaway hostname (WMK-ADVANCER) and an unmapped
    # rule: it must produce no chain and must not disturb H's chain. Buffer
    # cleanup is processing-time driven and covered by the unit suite.
    tick = _load_json("events_apt28_expiry_tick.json")
    publish_events(producer, [tick], pace=0, label="expiry-tick")

    chains = consume_chains(
        chains_analysed_consumer,
        expected=2,
        timeout=120.0,
        match=lambda c: c.get("hostname") == hostname,
    )
    mine = _filter_for(chains, hostname)
    assert len(mine) >= 1, f"expected >=1 steady-burst emission for {hostname}"

    # Tick MUST NOT produce a chain — its rule_id isn't in the HoS index.
    tick_chains = _filter_for(chains, "WMK-ADVANCER")
    assert tick_chains == [], (
        f"tick event with HoS-foreign rule_id produced phantom chains: {tick_chains}"
    )

    # Coverage on the steady chain stayed at 83.33 — expiry did not flip
    # any state that would inflate or deflate coverage retroactively.
    final = max(mine, key=lambda c: c["revision"])
    assert final["coverage"] == pytest.approx(83.33, abs=0.01)
