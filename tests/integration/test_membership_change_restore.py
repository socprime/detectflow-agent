"""E2E drill: a correlation-pipeline MEMBERSHIP CHANGE must not destroy state.

This is the scenario the operator-uid work exists for. Under the per-customer
correlation-pipeline model a correlation job's `KAFKA_INPUT_TOPICS` is the list
of its member detection pipelines' tagged-events topics, and that list is edited
over the pipeline's life. Both jobs deploy with `upgradeMode: last-state`.

Before the fix the job built **one KafkaSource per input topic** and unioned
them, so the member count *was* the source-operator count: adding or removing a
member changed the topology, which changed every auto-generated operator id,
which made the restore either fail outright ("Cannot map checkpoint state for
operator <hash> to the new program") or — with `allowNonRestoredState` — come up
having silently dropped every keyed `ChainBuffer` while the main source resumed
at `latest`. After the fix there is one fixed-arity source with a pinned `uid()`,
and the member set is a change *inside* the source's split state.

The drill:

1. Produce 4 events for a unique hostname on `dest-windows-events-raw` → the
   chain emits revision 1 (4/6 seq coverage ≥ the 60% threshold).
2. Sleep past one checkpoint interval (30s in this compose) so the buffer —
   including `emitted_revision` — is durable.
3. Trigger a savepoint over the Flink REST API, poll for its path, cancel the job,
   and recycle the TaskManager — thread mode (Pemja) cannot initialise twice in
   one JVM, and production gets a fresh one from every `last-state` roll
   (`_recycle_taskmanager`).
4. **Resubmit with TWO input topics instead of three**, restoring from that
   savepoint. The membership change is the removal of `dest-cloudtrail-detections`.
5. Assert the job reaches RUNNING — a uid regression fails here.
6. Push the 5th event on the surviving topic and assert **revision 2**, not a
   second revision 1. A phantom revision 1 means the `ChainBuffer` did not
   survive the membership change.
7. **Governance probe (the flip side), and it FAILS — deliberately recorded.**
   A `KafkaSource` restores its assigned splits from the checkpoint, not from
   the freshly rendered `KAFKA_INPUT_TOPICS`, so the removed topic's partitions
   come back with the state. Publishing a full chain's worth of events on the
   **removed** topic for a fresh hostname still produces a chain.

   Measured on `flink-sql-connector-kafka-4.0.1-2.0` (Flink 2.2.0), twice, on
   2026-08-13:

     * `partition.discovery.interval.ms` resolves to **300000** — enabled by
       default; this repo never sets it;
     * the enumerator **does** notice: `Discovered removed partitions:
       [dest-cloudtrail-detections-0, dest-cloudtrail-detections-1]`, at job
       start and again on the periodic cycle;
     * and the reader **keeps consuming anyway** — the chain below was built from
       events produced ~2 minutes after that line. Not "consumed then filtered":
       consumed and correlated. There is no in-event destination-topic filter
       that could hide the leak; isolation is the Kafka subscription, and a
       restore keeps the departed split until a cold start recreates the reader.

   The cause is structural, not a missing setting: FLIP-27 gives a
   `SplitEnumerator` no way to take a split back from a live reader — the
   connector's own `unassignPartitions` only serves finished/empty splits — so
   discovery can record a removal but nothing acts on it until the reader is
   recreated.

   **Consequence:** a membership **removal** must be a
   cold start (stop → start, state wiped), never a `last-state` roll. Additions
   stay hot.

Step 6 proves state survives a membership change. Step 7 proves the change is
not *honoured* by a restore, which is why the data-governance promise
needs the cold-start rule rather than the restart it originally assumed.

Negative control (run by hand, recorded in the MR): `git stash` the fix, rebuild
with `make integration-build`, and re-run — step 5 or step 6 must fail.

Side effect: this test leaves the correlation cluster running a job it submitted
itself. The teardown best-effort resubmits the original three-topic job (cold,
no savepoint); if that fails, `make integration-clean && make integration-up`
restores the stack. It also asserts nothing about the agent job, which is
deliberately untouched — the contract under test is correlation's keyed state.

Skip if the ``docker`` CLI is not on PATH.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from confluent_kafka import Consumer

from app.config.settings import Settings
from app.core.chain_id import build_chain_id, format_window_start
from tests.integration.conftest import (
    CHAINS_RAW_TOPIC,
    FLINK_REST_CORRELATION,
    KAFKA_BOOTSTRAP,
    consume_chains,
    query_user_counter,
)
from tests.integration.producer import (
    FIXTURES,
    _make_producer,
    publish_events,
    seed_meta,
)

pytestmark = pytest.mark.integration


HOS_ID = "40500000-0000-4000-8000-000000000028"

# Both the hostname and the event time are per-run. Nothing wipes the destination
# topics or chains-raw between runs, so a second run in the same stack replaying
# the corpus's fixed 2026-04-22 timestamps is entirely late-dropped (the matcher's
# watermark is already past them), and a fixed hostname makes it count the
# previous run's records as its own. Anchoring to the CURRENT 300s window makes
# every run strictly newer than the last; the offsets keep the drill's five events
# and the phase-5 probe inside that one window, which is what the seeded config's
# 300s override defines.
RUN_BASE_EPOCH = (int(time.time()) // 300) * 300
WINDOW_START_ISO = format_window_start(RUN_BASE_EPOCH)
EVENT_OFFSETS_S = (11, 16, 21, 26, 31)  # the corpus's own 5s spacing
PROBE_OFFSET_S = 71  # after the drill's last event, same window
RUN_TAG = uuid.uuid4().hex[:8].upper()
HOSTNAME = f"WKST-FIN-MEMBERSHIP-{RUN_TAG}"
HOSTNAME_REMOVED = f"WKST-FIN-DEPARTED-{RUN_TAG}"
JM_CONTAINER = "detectflow-correlation-jm"
# The TM is replaced, not restarted, between submissions — by compose service
# name, through the same `-f` path `make integration-up` uses so it lands in the
# same compose project.
COMPOSE_FILE = Path(__file__).resolve().parent / "docker-compose.yml"
TM_SERVICE = "flink-correlation-tm"
JOB_ID = "integration-correlation"

# chain_id is `uuid5(NS, "{correlation_pipeline_id}|{hos_id}|{hostname}|{window_start}")`.
# Must match CORRELATION_PIPELINE_ID in docker-compose.yml and `correlation_pipeline_id` in the
# seeded chains_config.json. It survives the resubmission without being in SUBMIT_ENV: the matcher
# resolves it from the config envelope (with the TaskManager's own env as fallback), and the
# operator runs on the TM, not on the submitter.
CORRELATION_PIPELINE_ID = "3f2b8c14-9f6a-4c3d-8f21-2a7b5c9d1e04"

# The topic every event in this drill rides on — it must survive the membership
# change, otherwise a lost chain would be explained by the missing input rather
# than by lost state.
SURVIVING_TOPIC = "dest-windows-events-raw"
# The departing member's topic — dropped from KAFKA_INPUT_TOPICS by the restore,
# but still present in the restored source's assigned splits (see step 7).
REMOVED_TOPIC = "dest-cloudtrail-detections"
TOPICS_BEFORE = "dest-windows-events-raw,dest-powershell-logs-raw,dest-cloudtrail-detections"
TOPICS_AFTER = "dest-windows-events-raw,dest-powershell-logs-raw"

# Every drop reason the matcher can record. Sampled either side of the probe:
# any movement means the event WAS consumed off the removed topic, even if no
# chain came out of it.
EVENT_COUNTERS = (
    "events_dropped_no_hits",
    "events_dropped_missing_hostname",
    "events_dropped_bad_timestamp",
    "events_late_dropped",
    "events_dropped_at_missing",
    "events_dropped_at_excluded",
    "chains_emitted_total",
)
# Flink's built-in per-vertex counter. Nothing else is produced during the probe,
# so a delta here is a record read off the removed topic regardless of what the
# matcher then decided to do with it.
SOURCE_RECORDS_COUNTER = "numRecordsOut"
LEAK_OBSERVATION_S = 150.0

SAVEPOINT_DIR = "file:///tmp/flink-checkpoints/savepoints"
CHECKPOINT_WAIT_S = 35.0  # one full 30s checkpoint interval + slack

# Env the submitter needs to build the job graph (the JM service itself carries
# only FLINK_PROPERTIES; the one-shot `correlation-job` submitter carried these).
SUBMIT_ENV = {
    "KAFKA_BOOTSTRAP_SERVERS": "kafka:9092",
    "KAFKA_AUTH_METHOD": "PLAINTEXT",
    "KAFKA_STARTING_OFFSET": "earliest",
    "STATE_BACKEND": "memory",
    "CHECKPOINT_PATH": "file:///tmp/flink-checkpoints",
    "LOG_FORMAT": "json",
    "LOG_LEVEL": "INFO",
    "JOB_ID": JOB_ID,
}


# ---------------------------------------------------------------------------
# Flink REST helpers
# ---------------------------------------------------------------------------


def _get_json(path: str, timeout: float = 10.0) -> dict:
    with urllib.request.urlopen(f"{FLINK_REST_CORRELATION}{path}", timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _send_json(path: str, payload: dict | None, method: str, timeout: float = 30.0) -> dict:
    body = json.dumps(payload).encode("utf-8") if payload is not None else b""
    req = urllib.request.Request(
        f"{FLINK_REST_CORRELATION}{path}",
        data=body,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8")
    return json.loads(raw) if raw.strip() else {}


def _running_correlation_jid(exclude: str | None = None) -> str | None:
    """jid of a RUNNING correlation job, ignoring ``exclude`` (the pre-restart
    job, so we do not mistake it for the resubmitted one)."""
    try:
        payload = _get_json("/v1/jobs/overview", timeout=5)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None
    for job in payload.get("jobs", []):
        if job.get("state") != "RUNNING":
            continue
        if "correlation" not in job.get("name", "").lower():
            continue
        if exclude is not None and job.get("jid") == exclude:
            continue
        return job["jid"]
    return None


def _wait_for_running_job(*, exclude: str | None = None, timeout: float = 180.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        jid = _running_correlation_jid(exclude=exclude)
        if jid is not None:
            return jid
        time.sleep(2.0)
    try:
        states = [
            (j.get("name"), j.get("state")) for j in _get_json("/v1/jobs/overview").get("jobs", [])
        ]
    except Exception:  # noqa: BLE001 — diagnostics only
        states = []
    raise TimeoutError(
        f"no RUNNING correlation job within {timeout}s (excluding {exclude}); last states: {states}"
    )


def _cancel_live_correlation_jobs() -> None:
    """Cancel every correlation job that still holds slots. Never raises."""
    live = {"CREATED", "RUNNING", "RESTARTING", "FAILING", "CANCELLING", "INITIALIZING"}
    try:
        jobs = _get_json("/v1/jobs/overview", timeout=10).get("jobs", [])
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return
    for job in jobs:
        if job.get("state") not in live or "correlation" not in job.get("name", "").lower():
            continue
        try:
            _cancel_job(job["jid"])
        except Exception:  # noqa: BLE001 — teardown must not mask the real failure
            pass


def _recycle_taskmanager(*, timeout: float = 240.0) -> None:
    """Replace the TaskManager container between the cancel and the restore.

    Not cosmetic, and not a workaround for a product bug: correlation-job runs in
    **thread mode (Pemja)**, and Pemja cannot initialise twice in one JVM. A
    second Python job in the TM that already ran one dies in
    ``EmbeddedPythonProcessOperator.open`` with
    ``pemja.utils.CommonUtils.loadLibrary -> NoSuchFieldException:
    loadedLibraryNames`` — the reflective un-register trick it uses to reload its
    native library from a new classloader targets a ``ClassLoader`` field that
    Java 17 no longer has, and the correlation image is java17-based.

    Production never hits it: every correlation pipeline is its own **application
    cluster**, so a ``last-state`` roll replaces the JM and TM pods and the
    restored job always starts in a fresh JVM. This compose is a *session*
    cluster whose TM outlives the job, which is the artefact being corrected
    here.

    ``up --force-recreate``, not ``docker restart``: a restart reuses the
    container's writable layer, where each submission leaves a ~1.6 GB
    ``/tmp/flink-dist-cache-*`` copy of ``usrlib`` plus its blob directory. Three
    submissions of this drill filled a 59 GB Docker VM and the job then died on
    ``Mkdirs failed to create .../pyflink/fn_execution``. A replaced container
    starts empty. ``--no-deps`` keeps the JobManager (and the savepoint it just
    took) untouched.

    The savepoint is unaffected either way — it lives on the shared
    ``correlation-state`` volume, not in the container.
    """
    subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(COMPOSE_FILE),
            "up",
            "-d",
            "--force-recreate",
            "--no-deps",
            TM_SERVICE,
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            payload = _get_json("/v1/taskmanagers", timeout=5)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            time.sleep(2.0)
            continue
        if any(tm.get("slotsNumber", 0) > 0 for tm in payload.get("taskmanagers", [])):
            return
        time.sleep(2.0)
    raise TimeoutError(f"TaskManager did not re-register with the JobManager within {timeout}s")


def _trigger_savepoint(jid: str, *, timeout: float = 180.0) -> str:
    """Trigger a savepoint and poll the async operation until it reports a path."""
    trigger = _send_json(
        f"/v1/jobs/{jid}/savepoints",
        {"target-directory": SAVEPOINT_DIR, "cancel-job": False},
        method="POST",
    )
    trigger_id = trigger["request-id"]

    deadline = time.monotonic() + timeout
    last: dict = {}
    while time.monotonic() < deadline:
        last = _get_json(f"/v1/jobs/{jid}/savepoints/{trigger_id}")
        status = (last.get("status") or {}).get("id")
        if status == "COMPLETED":
            operation = last.get("operation") or {}
            if operation.get("failure-cause"):
                raise AssertionError(f"savepoint failed: {operation['failure-cause']}")
            location = operation.get("location")
            assert location, f"savepoint completed without a location: {last}"
            return location
        time.sleep(2.0)
    raise TimeoutError(f"savepoint did not complete within {timeout}s; last payload: {last}")


def _cancel_job(jid: str, *, timeout: float = 120.0) -> None:
    _send_json(f"/v1/jobs/{jid}?mode=cancel", None, method="PATCH")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            state = _get_json(f"/v1/jobs/{jid}").get("state")
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            return
        if state in ("CANCELED", "FAILED", "FINISHED"):
            return
        time.sleep(1.0)
    raise TimeoutError(f"job {jid} did not terminate within {timeout}s")


def _submit(input_topics: str, *, savepoint: str | None) -> subprocess.CompletedProcess[str]:
    """Submit the correlation job from inside the JM container.

    Mirrors the `correlation-job` submitter service in docker-compose.yml — same
    `-py` / `--pyFiles` / `--jarfile` arguments — plus `-s <savepoint>` when
    restoring. `--allowNonRestoredState` is deliberately NOT passed: an
    incompatible graph must fail loudly, which is the whole point of the drill.
    """
    env_flags: list[str] = []
    for key, value in SUBMIT_ENV.items():
        env_flags += ["-e", f"{key}={value}"]

    restore_flags = ["-s", savepoint] if savepoint else []

    return subprocess.run(
        [
            "docker",
            "exec",
            *env_flags,
            JM_CONTAINER,
            "/opt/flink/bin/flink",
            "run",
            "-d",
            "-m",
            "flink-correlation-jm:8081",
            *restore_flags,
            "-py",
            "/opt/flink/usrlib/app/jobs/correlation/__main__.py",
            "--pyFiles",
            "/opt/flink/usrlib",
            "--jarfile",
            "/opt/flink/lib/flink-sql-connector-kafka-4.0.1-2.0.jar",
            "--",
            "--input-topics",
            input_topics,
            "--job-id",
            JOB_ID,
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def docker_available() -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker CLI not on PATH — required to resubmit the correlation job")


@pytest.fixture
def chains_raw_consumer(stack_ready) -> Iterator[Consumer]:
    """Read chains-raw directly: the contract under test is correlation's keyed
    state, so the agent job (and the LLM stub's latency) stays out of the loop."""
    consumer = Consumer(
        {
            "bootstrap.servers": KAFKA_BOOTSTRAP,
            "group.id": f"membership-drill-{uuid.uuid4()}",
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
            "isolation.level": "read_committed",
        }
    )
    consumer.subscribe([CHAINS_RAW_TOPIC])
    yield consumer
    consumer.close()


@pytest.fixture
def restore_original_topology(docker_available) -> Iterator[None]:
    """Best-effort: leave the stack running the original three-topic job, and only
    that one, so a later ``pytest -m integration`` run is not silently degraded.

    Cancels EVERY live correlation job, not just the one it can see running. The
    TM has two slots; a job left over from a run that died mid-drill holds them,
    the next job sits in RESTARTING forever, and the failure it produces is
    unrelated to anything under test ("Checkpoint triggering task ... is not
    being executed at the moment"). Cancelling one and submitting one keeps that
    state alive forever, which is how it was found.
    """
    yield
    _cancel_live_correlation_jobs()
    try:
        # Same fresh-JVM requirement as the restore itself: without it the
        # resubmitted job crash-loops on Pemja's second init and the stack is
        # left red for the next test. It also drops this run's dist-cache copies
        # of `usrlib`, which is what keeps the TM from filling its filesystem.
        _recycle_taskmanager()
        _submit(TOPICS_BEFORE, savepoint=None)
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _expected_chain_id(hostname: str = HOSTNAME) -> str:
    namespace = uuid.UUID(
        Settings(kafka_bootstrap_servers="x", kafka_auth_method="PLAINTEXT").chain_id_namespace
    )
    return build_chain_id(
        namespace,
        HOS_ID,
        hostname,
        WINDOW_START_ISO,
        correlation_pipeline_id=CORRELATION_PIPELINE_ID,
    )


def _stamp(offset_s: int) -> str:
    """This run's window start + ``offset_s``, in the wire's ISO-8601 ``Z`` form."""
    return datetime.fromtimestamp(RUN_BASE_EPOCH + offset_s, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _corpus() -> list[dict]:
    return [
        json.loads(line)
        for line in (FIXTURES / "events_apt28.jsonl").read_text().splitlines()
        if line.strip()
    ]


def _events() -> list[dict]:
    """The APT28 corpus, re-homed onto one surviving topic, host and run window."""
    return [
        {
            **ev,
            "hostname": HOSTNAME,
            "event_id": f"{ev['event_id']}-{HOSTNAME}",
            "source_topic": SURVIVING_TOPIC,
            "timestamp": _stamp(EVENT_OFFSETS_S[index]),
        }
        for index, ev in enumerate(_corpus())
    ]


def _mine(chains: list[dict]) -> list[dict]:
    return [c for c in chains if c.get("hostname") == HOSTNAME]


def _departed_member_events() -> list[dict]:
    """A full chain's worth of events on the REMOVED topic, for a fresh hostname.

    Four distinct seq rules = 4/6 coverage = 66.7% ≥ the 60% threshold, so these
    would emit a chain on their own if the source still read that topic.

    They are timestamped AFTER the drill's last event and inside the same window:
    an event behind the watermark would be late-dropped, and "no chain because it
    was late" is not the answer this probe is asking for.
    """
    return [
        {
            **ev,
            "hostname": HOSTNAME_REMOVED,
            "event_id": f"{ev['event_id']}-{HOSTNAME_REMOVED}",
            "source_topic": REMOVED_TOPIC,
            "timestamp": _stamp(PROBE_OFFSET_S + 5 * index),
        }
        for index, ev in enumerate(_corpus()[:4])
    ]


def _counters(jid: str) -> dict[str, int]:
    """Every matcher drop/emit counter plus the source's record count, for ONE job."""
    snapshot = {
        name: query_user_counter(name, job_name_substr="correlation", jid=jid)
        for name in EVENT_COUNTERS
    }
    snapshot[SOURCE_RECORDS_COUNTER] = query_user_counter(
        SOURCE_RECORDS_COUNTER, job_name_substr="correlation", jid=jid
    )
    return snapshot


def _deltas(before: dict[str, int], after: dict[str, int]) -> dict[str, int]:
    return {name: after[name] - before[name] for name in before if after[name] != before[name]}


def _enumerator_log() -> str:
    """The JM's partition-discovery lines — did the enumerator notice the removal?"""
    try:
        out = subprocess.run(
            ["docker", "logs", JM_CONTAINER],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (subprocess.SubprocessError, OSError) as exc:  # pragma: no cover - diagnostics
        return f"(docker logs failed: {exc})"
    lines = [
        line
        for line in (out.stdout + out.stderr).splitlines()
        if "partition discovery" in line.lower()
        or "Discovered removed partitions" in line
        or "Discovered new partitions" in line
    ]
    return "\n".join(lines[-15:]) or "(no partition-discovery lines in the JM log)"


# ---------------------------------------------------------------------------
# The drill
# ---------------------------------------------------------------------------


def test_chain_state_survives_input_topic_membership_change(
    stack_ready, chains_raw_consumer, docker_available, restore_original_topology
):
    producer = _make_producer(KAFKA_BOOTSTRAP)
    seed_meta(producer, consume_window=8.0)

    events = _events()

    # Phase 1 — revision 1 (4 of 6 seqs = 66.67% ≥ the 60% threshold).
    publish_events(producer, events[:4], pace=0.2, label="pre-membership-change")

    pre = _mine(
        consume_chains(
            chains_raw_consumer,
            expected=1,
            timeout=120.0,
            match=lambda c: c.get("hostname") == HOSTNAME,
        )
    )
    assert pre, f"no pre-change chain for {HOSTNAME}"
    assert pre[0]["revision"] == 1, f"expected revision=1, got {pre[0]['revision']}"
    assert pre[0]["chain_id"] == _expected_chain_id()

    # Phase 2 — make the buffer durable, then savepoint + cancel.
    time.sleep(CHECKPOINT_WAIT_S)

    old_jid = _running_correlation_jid()
    assert old_jid, "correlation job is not RUNNING before the savepoint"
    savepoint_path = _trigger_savepoint(old_jid)
    _cancel_job(old_jid)
    # Fresh TM JVM, the way a `last-state` roll gives production one — see
    # `_recycle_taskmanager` for why thread mode makes this mandatory here.
    _recycle_taskmanager()

    # Phase 3 — THE membership change: resubmit with two input topics, not three.
    result = _submit(TOPICS_AFTER, savepoint=savepoint_path)
    assert result.returncode == 0, (
        "resubmission with a changed member set failed — this is the uid "
        f"regression this test guards.\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    new_jid = _wait_for_running_job(exclude=old_jid)
    assert new_jid != old_jid

    # Phase 4 — the 5th event on the surviving topic. Correct restore ⇒ coverage
    # 5/6 and revision 2. A phantom revision 1 means the ChainBuffer was dropped.
    publish_events(producer, events[4:5], pace=0, label="post-membership-change")

    # ONE record, not two: phase 1 already drained the only revision-1 emission
    # (four events produce a single emit), so a post-restore poll that waits for
    # two matches can only ever time out.
    post = _mine(
        consume_chains(
            chains_raw_consumer,
            expected=1,
            timeout=180.0,
            match=lambda c: c.get("hostname") == HOSTNAME,
        )
    )
    revisions = sorted(c["revision"] for c in post)

    assert 2 in revisions, (
        f"expected revision=2 after the membership change, got revisions={revisions} — "
        "the ChainBuffer did not survive the input-topic set change"
    )
    # Losing the buffer while the source replays its restored offsets rebuilds the
    # chain from scratch, which shows up as a FRESH revision 1 after the restore.
    # (Losing it without a replay emits nothing at all: one event is 1/6 coverage,
    # below the threshold — which is what the assertion above catches.)
    assert 1 not in revisions, (
        f"a fresh revision=1 was emitted after the restore ({revisions}) — keyed state was "
        "lost and the chain restarted from scratch"
    )
    assert max(revisions) == 2, f"phantom revision beyond 2: {revisions}"
    assert all(c["chain_id"] == _expected_chain_id() for c in post), (
        f"chain_id changed across the membership change: {[c['chain_id'] for c in post]}"
    )

    final = max(post, key=lambda c: c["revision"])
    assert final["coverage"] == pytest.approx(83.33, abs=0.01)

    # Phase 5 — the governance probe. CHARACTERISATION: it asserts what the
    # connector actually does, which is NOT what we want (see the module
    # docstring). Flip it the day a Flink release makes a removal propagate to
    # the readers — a failure here is good news, not a regression.
    before = _counters(new_jid)
    publish_events(producer, _departed_member_events(), pace=0.2, label="departed-member")

    leaked = [
        c
        for c in consume_chains(
            chains_raw_consumer,
            expected=1,
            timeout=LEAK_OBSERVATION_S,
            match=lambda c: c.get("hostname") == HOSTNAME_REMOVED,
        )
        if c.get("hostname") == HOSTNAME_REMOVED
    ]
    # Metric deltas are diagnostics only, never assertions: the JM refreshes user
    # counters asynchronously, and the leak assertion below returns as soon as the
    # chain lands — well inside that lag, so an empty delta here means nothing.
    moved = _deltas(before, _counters(new_jid))
    discovery = _enumerator_log()
    diagnostics = f"\ncounter deltas: {moved or 'none'}\nJM partition discovery:\n{discovery}"

    assert leaked, (
        "The removed topic was NOT consumed after the restore — the connector now propagates a "
        "removal to its readers. That is the behaviour we always wanted: delete this assertion, "
        "restore the `assert not leaked` it replaced, and lift the cold-start-on-removal rule."
        f"{diagnostics}"
    )
    assert "Discovered removed partitions" in discovery, (
        "The removed partitions were consumed AND the enumerator never noticed the removal — a "
        "different failure from the one this test characterises (there, discovery fires and only "
        f"the reader ignores it). Re-check `partition.discovery.interval.ms`.{diagnostics}"
    )
    print(
        f"\n[governance probe] CONFIRMED: {len(leaked)} chain(s) for {HOSTNAME_REMOVED} built from "
        f"{REMOVED_TOPIC} AFTER its removal. A membership REMOVAL therefore requires a cold start, "
        f"not a last-state roll.{diagnostics}"
    )
