"""Shared fixtures and helpers for the integration suite.

Tests assume the docker-compose stack from ``tests/integration/`` is already
up. The session-scoped ``stack_ready`` fixture polls Kafka + the Flink REST
API and short-circuits the run with a clear error if anything is missing —
so a developer running ``pytest -m integration`` without ``make integration-up``
gets actionable feedback instead of a 60-second timeout.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Iterator

import pytest
from confluent_kafka import Consumer, KafkaException
from confluent_kafka.admin import AdminClient

from tests.integration.producer import _make_producer  # noqa: F401  (re-exported)


def _http_get_json(url: str, timeout: float) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


KAFKA_BOOTSTRAP = "localhost:19092"
# Two separate Flink clusters (process- and thread-mode Python operators
# must not share a TM pool). Correlation runs on its own JM at
# :8081, agent on its own JM at :8082.
FLINK_REST_CORRELATION = "http://localhost:8081"
FLINK_REST_AGENT = "http://localhost:8082"
# Backwards-compat alias — points at the correlation cluster, which is
# what existing helpers/tests defaulted to before the split.
FLINK_REST = FLINK_REST_CORRELATION
LLM_STUB_HEALTH = "http://localhost:8001/healthz"

CHAINS_RAW_TOPIC = "detectflow.chains-raw"
CHAINS_ANALYSED_TOPIC = "detectflow.chains-analysed"


# ---------------------------------------------------------------------------
# Readiness checks
# ---------------------------------------------------------------------------


def _kafka_reachable(bootstrap: str) -> bool:
    try:
        admin = AdminClient({"bootstrap.servers": bootstrap, "socket.timeout.ms": 3000})
        admin.list_topics(timeout=3)
        return True
    except (KafkaException, Exception):
        return False


def _flink_job_running(rest: str) -> tuple[bool, list[dict]]:
    """At least one job on this cluster must be RUNNING. Each cluster is an
    application cluster running exactly one job.

    Returns (ok, jobs). Jobs is empty if the JM REST API is unreachable.
    """
    try:
        payload = _http_get_json(f"{rest}/v1/jobs/overview", timeout=3)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return False, []
    jobs = payload.get("jobs", [])
    running = [j for j in jobs if j.get("state") == "RUNNING"]
    return len(running) >= 1, jobs


def _wait_until(predicate, *, timeout: float, interval: float = 1.0, label: str):
    deadline = time.monotonic() + timeout
    last_state = None
    while time.monotonic() < deadline:
        ok, last_state = predicate()
        if ok:
            return last_state
        time.sleep(interval)
    raise TimeoutError(f"timed out after {timeout}s waiting for {label}; last state: {last_state}")


@pytest.fixture(scope="session")
def stack_ready() -> dict:
    """Verify Kafka, Flink (both clusters), and the LLM stub are reachable
    AND each cluster's job is RUNNING. Cached per session — every
    integration test depends on this."""
    if not _kafka_reachable(KAFKA_BOOTSTRAP):
        pytest.fail(f"Kafka not reachable at {KAFKA_BOOTSTRAP}. Run `make integration-up` first.")

    try:
        _http_get_json(LLM_STUB_HEALTH, timeout=3)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        pytest.fail(f"LLM stub not healthy at {LLM_STUB_HEALTH}: {exc}")

    def _both_clusters_running():
        ok_c, jobs_c = _flink_job_running(FLINK_REST_CORRELATION)
        ok_a, jobs_a = _flink_job_running(FLINK_REST_AGENT)
        states = {
            "correlation": [(j.get("name"), j.get("state")) for j in jobs_c],
            "agent": [(j.get("name"), j.get("state")) for j in jobs_a],
        }
        return ok_c and ok_a, states

    states = _wait_until(
        _both_clusters_running, timeout=180, interval=2.0, label="both Flink clusters RUNNING"
    )
    return {
        "kafka": KAFKA_BOOTSTRAP,
        "flink_rest_correlation": FLINK_REST_CORRELATION,
        "flink_rest_agent": FLINK_REST_AGENT,
        "jobs": states,
    }


# ---------------------------------------------------------------------------
# Chain consumer helper
# ---------------------------------------------------------------------------


@pytest.fixture
def chains_analysed_consumer(stack_ready) -> Iterator[Consumer]:
    """Fresh consumer group every test → reads from `earliest` and sees ALL
    records published this run, not whatever a previous test left committed.

    Test isolation strategy: tests rely on the producer publishing AFTER the
    consumer subscribes; the unique group_id guarantees we don't inherit any
    prior committed offsets. For cross-test-run isolation across the whole
    Kafka topic, run `make integration-clean && make integration-up` between
    suites.
    """
    consumer = Consumer(
        {
            "bootstrap.servers": KAFKA_BOOTSTRAP,
            "group.id": f"e2e-test-{uuid.uuid4()}",
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
            # Read EOS-committed records only — Flink writes via transactional
            # producer, so we must skip aborted/uncommitted txns to avoid
            # phantom messages mid-checkpoint.
            "isolation.level": "read_committed",
        }
    )
    consumer.subscribe([CHAINS_ANALYSED_TOPIC])
    yield consumer
    consumer.close()


def consume_for(consumer: Consumer, *, duration: float = 10.0) -> list[dict]:
    """Drain everything the consumer sees within ``duration`` seconds.
    Useful as a "did anything else show up?" probe after asserting the
    happy path."""
    deadline = time.monotonic() + duration
    out: list[dict] = []
    while time.monotonic() < deadline:
        msg = consumer.poll(0.5)
        if msg is None or msg.error():
            continue
        out.append(json.loads(msg.value()))
    return out


# ---------------------------------------------------------------------------
# Flink REST metrics helpers (for user-defined operator counters)
# ---------------------------------------------------------------------------


def query_user_counter(
    metric_suffix: str,
    *,
    job_name_substr: str,
    rest_url: str = FLINK_REST_CORRELATION,
    jid: str | None = None,
) -> int:
    """Sum a user-registered counter across every vertex/subtask of the
    matching job on the given Flink cluster. Returns 0 if the job or
    metric is not yet visible.

    ``rest_url`` defaults to the correlation cluster — the matcher is
    where most user counters live. Pass ``FLINK_REST_AGENT`` for
    agent-side metrics.

    ``jid`` pins the read to one job id and makes ``job_name_substr``
    advisory. Pass it in any test that resubmits the job:
    ``/jobs/overview`` keeps listing the CANCELED predecessor under the
    same name, so matching by name alone can return the dead job's frozen
    counters.

    Flink prefixes user metrics with the subtask index (and any
    ``add_group(label, value)`` chain), so we filter by suffix to catch
    every subtask that contributed."""
    if jid is not None:
        job_id = jid
    else:
        try:
            overview = _http_get_json(f"{rest_url}/v1/jobs/overview", timeout=5)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            return 0
        matching = [j for j in overview.get("jobs", []) if job_name_substr in j.get("name", "")]
        if not matching:
            return 0
        job_id = matching[0]["jid"]
    try:
        plan = _http_get_json(f"{rest_url}/v1/jobs/{job_id}", timeout=5)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return 0
    total = 0
    for vertex in plan.get("vertices", []):
        vid = vertex["id"]
        try:
            listing = _http_get_json(
                f"{rest_url}/v1/jobs/{job_id}/vertices/{vid}/metrics", timeout=5
            )
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            continue
        candidates = [m["id"] for m in listing if m["id"].endswith(metric_suffix)]
        if not candidates:
            continue
        try:
            values = _http_get_json(
                f"{rest_url}/v1/jobs/{job_id}/vertices/{vid}/metrics?get={','.join(candidates)}",
                timeout=5,
            )
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            continue
        for m in values:
            try:
                total += int(float(m.get("value", 0)))
            except (TypeError, ValueError):
                pass
    return total


def wait_for_counter_at_least(
    metric_suffix: str,
    target: int,
    *,
    job_name_substr: str,
    rest_url: str = FLINK_REST_CORRELATION,
    timeout: float = 60.0,
    interval: float = 2.0,
) -> int:
    """Poll Flink REST until a user counter reaches ``target`` or ``timeout``
    expires. Metric refresh on the JM side is asynchronous (a few seconds
    after the operator increments the counter), so we don't read once and
    give up. Returns the last value seen."""
    deadline = time.monotonic() + timeout
    last = 0
    while time.monotonic() < deadline:
        last = query_user_counter(metric_suffix, job_name_substr=job_name_substr, rest_url=rest_url)
        if last >= target:
            return last
        time.sleep(interval)
    return last


def consume_chains(
    consumer: Consumer,
    *,
    expected: int = 1,
    timeout: float = 90.0,
    match: callable | None = None,
) -> list[dict]:
    """Poll until at least ``expected`` chain records arrive (optionally
    filtered by ``match``) or ``timeout`` elapses. Returns every record
    the consumer saw — including non-matching ones — so callers can still
    cross-reference unrelated chains for negative assertions.

    Timeout is generous because EOS sinks only commit on checkpoint barriers
    (interval = 30s in the compose config), so even a fast pipeline takes
    ~30-60s wall-clock between event-publish and message-visibility on the
    consumer side.

    ``match`` is critical for test isolation: each test reuses the same
    `chains-analysed` topic, so a fresh consumer started with
    ``auto.offset.reset=earliest`` will replay chains emitted by prior
    tests in the same session. Without filtering, ``expected`` would be
    satisfied by stale records and the per-test hostname assertion would
    fire on an empty list. Pass ``match=lambda c: c["hostname"] == HOST``
    to count only this test's emissions toward the budget.
    """
    deadline = time.monotonic() + timeout
    out: list[dict] = []
    matched = 0
    while time.monotonic() < deadline and matched < expected:
        msg = consumer.poll(1.0)
        if msg is None:
            continue
        if msg.error():
            continue
        rec = json.loads(msg.value())
        out.append(rec)
        if match is None or match(rec):
            matched += 1
    return out
