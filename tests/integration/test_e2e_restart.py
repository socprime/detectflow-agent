"""E2E scenario: revision counter survives correlation-job restart-from-checkpoint.

Review #5 — locks the contract that ``ChainBuffer.emitted_revision`` is
persisted in keyed state and round-trips correctly through Flink's
checkpoint/restore cycle. A regression that drops the field from
``_serialize_buffer`` / ``_deserialize_buffer`` would cause the counter
to reset on restore, producing duplicate revision-1 emissions instead
of advancing to revision-2 — the detectflow-backend consumer would treat the
restored chain as new and clobber analyst-owned fields.

Approach (pragmatic, not purist):

1. Produce events that fire revision=1 on a unique hostname.
2. Wait for the chain on chains-analysed.
3. Sleep through one checkpoint barrier (interval=30s in compose) so the
   buffer state — including ``emitted_revision`` — is durable.
4. Restart the process-mode TaskManager via ``docker restart``. This
   simulates a TM crash; Flink's default restart strategy auto-restores
   the correlation-job from the latest checkpoint. Savepoint scripting
   would be cleaner conceptually but adds materially more orchestration
   for the same observable contract.
5. After the job is RUNNING again, push the 5th event (would be rev=2
   under steady semantics).
6. Assert: revision=2 lands. Counter did NOT reset (no second rev=1
   record). Counter did NOT advance past 2 (no rev=3+ phantom).

Skip if ``docker`` CLI is not on PATH.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
import urllib.error
import urllib.request
import uuid

import pytest

from app.config.settings import Settings
from app.core.chain_id import build_chain_id
from tests.integration.conftest import (
    FLINK_REST_CORRELATION,
    KAFKA_BOOTSTRAP,
    consume_chains,
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
HOSTNAME = "WKST-FIN-RESTART"
TM_CONTAINER = "detectflow-correlation-tm"
CHECKPOINT_WAIT_S = 35.0  # one full 30s checkpoint interval + slack


def _expected_chain_id() -> str:
    namespace = uuid.UUID(
        Settings(kafka_bootstrap_servers="x", kafka_auth_method="PLAINTEXT").chain_id_namespace
    )
    return build_chain_id(namespace, HOS_ID, HOSTNAME, WINDOW_START_ISO, CORRELATION_PIPELINE_ID)


def _load_jsonl(name: str) -> list[dict]:
    return [json.loads(line) for line in (FIXTURES / name).read_text().splitlines() if line.strip()]


def _load_json(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def _rewrite(events: list[dict]) -> list[dict]:
    return [
        {**ev, "hostname": HOSTNAME, "event_id": f"{ev['event_id']}-{HOSTNAME}"} for ev in events
    ]


def _wait_correlation_job_running(timeout: float = 90.0) -> None:
    """Poll Flink REST until the correlation-job is RUNNING again (after the
    TM restart triggered a job-level failover from the latest checkpoint)."""
    deadline = time.monotonic() + timeout
    last_states: list[tuple[str, str]] = []
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(
                f"{FLINK_REST_CORRELATION}/v1/jobs/overview", timeout=5
            ) as r:
                payload = json.loads(r.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            time.sleep(2.0)
            continue
        jobs = payload.get("jobs", [])
        last_states = [(j.get("name", ""), j.get("state", "")) for j in jobs]
        # We need the correlation-job specifically RUNNING, not just any.
        for name, state in last_states:
            if "correlation" in name.lower() and state == "RUNNING":
                return
        time.sleep(2.0)
    raise TimeoutError(
        f"correlation-job did not reach RUNNING within {timeout}s; last states: {last_states}"
    )


@pytest.fixture
def docker_available() -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker CLI not on PATH — required to restart TaskManager container")


def test_revision_counter_survives_correlation_job_restart(
    stack_ready, chains_analysed_consumer, docker_available
):
    producer = _make_producer(KAFKA_BOOTSTRAP)
    seed_meta(producer, consume_window=8.0)

    # Phase 1 — fire revision=1 with the first 4 steady events (4/6 = 66.67%).
    steady = _rewrite(_load_jsonl("events_apt28.jsonl"))
    publish_events(producer, steady[:4], pace=0.2, label="pre-restart")

    chains_pre = consume_chains(
        chains_analysed_consumer,
        expected=1,
        timeout=120.0,
        match=lambda c: c.get("hostname") == HOSTNAME,
    )
    mine_pre = [c for c in chains_pre if c.get("hostname") == HOSTNAME]
    assert len(mine_pre) >= 1, f"no pre-restart chain for {HOSTNAME}: got {chains_pre}"
    rev1 = mine_pre[0]
    assert rev1["revision"] == 1, f"expected revision=1 pre-restart, got {rev1['revision']}"
    assert rev1["chain_id"] == _expected_chain_id()

    # Phase 2 — give Flink one full checkpoint cycle so emitted_revision=1 is
    # durable in keyed state, then restart the process-mode TM.
    time.sleep(CHECKPOINT_WAIT_S)

    result = subprocess.run(
        ["docker", "restart", TM_CONTAINER],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"docker restart failed: {result.stderr}"

    _wait_correlation_job_running(timeout=120.0)

    # Phase 3 — push the 5th event. Under correct restore semantics this
    # bumps coverage to 5/6 = 83.33% and emits revision=2 with the SAME
    # chain_id. A regression that didn't persist emitted_revision through
    # the checkpoint would emit revision=1 here (counter reset) — that's
    # the exact failure mode this test exists to catch.
    publish_events(producer, steady[4:5], pace=0, label="post-restart")

    # Drain enough to reliably catch the rev=2 (and any phantom).
    chains_post = consume_chains(
        chains_analysed_consumer,
        expected=2,
        timeout=180.0,
        match=lambda c: c.get("hostname") == HOSTNAME,
    )
    mine_all = [c for c in chains_post if c.get("hostname") == HOSTNAME]
    revisions = sorted(c["revision"] for c in mine_all)

    # Must contain a revision=2 entry; counter advanced, not reset.
    assert 2 in revisions, (
        f"expected revision=2 after restart but got revisions={revisions}; "
        "regression: ChainBuffer.emitted_revision did not survive checkpoint/restore"
    )
    # No phantom revision=3+ — the 5th event must not double-count.
    assert max(revisions) == 2, (
        f"phantom revision beyond 2: {revisions} — restore re-fired buffered hits"
    )
    # All emissions share the deterministic chain_id (deterministic by design).
    assert all(c["chain_id"] == _expected_chain_id() for c in mine_all), (
        f"chain_id changed across restart: {[c['chain_id'] for c in mine_all]}"
    )

    final = max(mine_all, key=lambda c: c["revision"])
    assert final["coverage"] == pytest.approx(83.33, abs=0.01)
    assert final["active_threat"]["name"] == "APT28"
