"""Two isolated correlation pipelines, side by side.

Per-customer correlation pipelines promise a **negative** property:
one MSSP customer's tagged events never reach another customer's topics, and one
customer's chain can never be mistaken for another's. Unit tests pin each half;
this pins that the halves compose into two mutually blind runtimes.

Run against the two-tenant overlay (two session clusters, one per tenant):

    cd tests/integration
    docker compose -f docker-compose.yml -f docker-compose.two-tenant.yml up -d --build \\
        kafka topic-init topic-init-2t \\
        flink-corr-a-jm flink-corr-a-tm flink-corr-b-jm flink-corr-b-tm corr-job-a corr-job-b
    uv run pytest -m integration tests/integration/test_two_tenant_isolation.py -v

The module SKIPS (never fails) when that overlay is not up, so a single-tenant
`pytest -m integration` run is unaffected.

What each test pins, and why it is here rather than in a unit test:

1. cross-tenant blindness — counted on the wire, from the beginning of every one
   of tenant B's topics, not inferred from the absence of an error;
2. the chain stamp is a real UUID equal to the pipeline that owns the topic, and
   never the ``JOB_ID`` string: the control plane parses that field as a UUID, so
   a ``corr-<uuid>`` stamp is silently discarded and the chain lands unattributed;
3. the two Flink job names are distinct — naming every instance
   ``correlation-job`` would make two customers' jobs indistinguishable
   in the UI, in metrics and in an incident;
4. two customers owning a host of the same name, correlated by
   the same *catalogue* HoS rule in the same window, get DIFFERENT ``chain_id``s.
   An unscoped three-part seed collides exactly there and one customer's chain
   overwrites the other's in ``attack_chains``. This is the assertion most likely
   to be undone by a well-meaning refactor of ``chain_id.py``.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime

import pytest
from confluent_kafka import Consumer, TopicPartition

from app.config.settings import Settings
from app.core.chain_id import build_chain_id
from tests.integration.conftest import KAFKA_BOOTSTRAP
from tests.integration.producer import FIXTURES, _make_producer

pytestmark = pytest.mark.integration


# Fixed ids, real UUID shape — they also exercise the generated topic-name and
# DNS-1123 name lengths. Must match tests/integration/docker-compose.two-tenant.yml.
CORR_A = "aaaaaaaa-0000-5000-a000-00000000000a"
CORR_B = "bbbbbbbb-0000-5000-b000-00000000000b"
JOB_ID_A = f"corr-{CORR_A}"
JOB_ID_B = f"corr-{CORR_B}"

A1 = "a1000000-0000-5000-a000-000000000001"
A2 = "a1000000-0000-5000-a000-000000000002"
B1 = "b1000000-0000-5000-b000-000000000003"
B2 = "b1000000-0000-5000-b000-000000000004"

TAGGED = "detectflow.tagged-events.{}"
CONFIG = "detectflow.chains-config.{}"
RAW = "detectflow.chains-raw.{}"
ANALYSED = "detectflow.chains-analysed.{}"

# Every topic tenant B owns. The isolation proof reads all five from the
# beginning and counts tenant-A sentinels; "no error in the log" is not a proof.
B_TOPICS = (
    TAGGED.format(B1),
    TAGGED.format(B2),
    CONFIG.format(CORR_B),
    RAW.format(CORR_B),
    ANALYSED.format(CORR_B),
)

REST_A = "http://localhost:8091"
REST_B = "http://localhost:8092"

HOS_ID = "40500000-0000-4000-8000-000000000028"
CONFIG_KEY = "global"
WINDOW_S = 300


def _http_json(url: str, timeout: float = 5.0) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _running_job_names(rest: str) -> list[str]:
    try:
        payload = _http_json(f"{rest}/v1/jobs/overview")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return []
    return [j["name"] for j in payload.get("jobs", []) if j.get("state") == "RUNNING"]


def _load_json(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def _load_jsonl(name: str) -> list[dict]:
    return [json.loads(x) for x in (FIXTURES / name).read_text().splitlines() if x.strip()]


def _read_topic(topic: str, *, idle_s: float = 6.0, max_s: float = 90.0) -> list[bytes]:
    """Every record on a topic from offset 0, as raw bytes.

    Raw bytes on purpose: the isolation count must see the wire, including any
    record shape this test does not model.
    """
    consumer = Consumer(
        {
            "bootstrap.servers": KAFKA_BOOTSTRAP,
            "group.id": f"two-tenant-check-{uuid.uuid4()}",
            "enable.auto.commit": False,
            "auto.offset.reset": "earliest",
        }
    )
    try:
        meta = consumer.list_topics(topic, timeout=15)
        if topic not in meta.topics or meta.topics[topic].error:
            pytest.fail(f"topic missing from the two-tenant stack: {topic}")
        consumer.assign([TopicPartition(topic, p, 0) for p in meta.topics[topic].partitions])
        out: list[bytes] = []
        idle = 0.0
        deadline = time.monotonic() + max_s
        while idle < idle_s and time.monotonic() < deadline:
            msg = consumer.poll(0.5)
            if msg is None:
                idle += 0.5
                continue
            if msg.error():
                continue
            idle = 0.0
            if msg.value() is not None:
                out.append(msg.value())
        return out
    finally:
        consumer.close()


def _chains(topic: str, *, match=None, expected: int = 1, timeout: float = 120.0) -> list[dict]:
    """Poll a chains topic until ``expected`` matching chains arrive."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        records = [json.loads(v) for v in _read_topic(topic, idle_s=4.0)]
        hits = [c for c in records if match is None or match(c)]
        if len(hits) >= expected:
            return hits
        time.sleep(3.0)
    return []


def _rewrite(events: list[dict], *, hostname: str, pipeline_id: str) -> list[dict]:
    """Re-stamp the APT28 corpus for one tenant.

    Timestamps stay fixture-pinned so ``window_start`` is deterministic; only the
    tenant identity and the per-run hostname change. ``pipeline_id`` is the whole
    tenant identity on the envelope — destination topic names left the contract.
    """
    return [
        {
            **ev,
            "hostname": hostname,
            "pipeline_id": pipeline_id,
            "event_id": f"{ev['event_id']}-{hostname}",
        }
        for ev in events
    ]


def _chains_config(pipeline_id: str, name: str) -> dict:
    cfg = _load_json("chains_config.json")
    cfg.update(
        correlation_pipeline_id=pipeline_id,
        correlation_pipeline_name=name,
        correlation_window_seconds=WINDOW_S,
        # Deny-list: empty ≡ null ≡ absent ≡ every catalogue AT is monitored.
        excluded_active_threat_ids=[],
    )
    return cfg


def _namespace() -> uuid.UUID:
    return uuid.UUID(
        Settings(kafka_bootstrap_servers="x", kafka_auth_method="PLAINTEXT").chain_id_namespace
    )


def _expected_window_start(events: list[dict]) -> str:
    epoch = int(
        datetime.fromisoformat(events[0]["timestamp"].replace("Z", "+00:00"))
        .astimezone(UTC)
        .timestamp()
    )
    return datetime.fromtimestamp(epoch - epoch % WINDOW_S, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture(scope="module")
def two_tenant_run() -> dict:
    """Seed both tenants, then drive two bursts.

    Burst 1 is **tenant A only**, on a hostname carrying a tenant-A sentinel —
    that is what the isolation count looks for on tenant B's topics.
    Burst 2 uses ONE hostname produced to BOTH tenants, which is the D5 case:
    same host, same catalogue HoS rule, same window, two customers.
    """
    names_a, names_b = _running_job_names(REST_A), _running_job_names(REST_B)
    if not names_a or not names_b:
        pytest.skip(
            "two-tenant integration overlay is not up "
            "(docker-compose.two-tenant.yml; expected a RUNNING job on :8091 and :8092)"
        )

    run = uuid.uuid4().hex[:8]
    host_a_only = f"WKST-2T-{run}-tenant-a"
    host_shared = f"WKST-2T-{run}-shared"

    producer = _make_producer(KAFKA_BOOTSTRAP)
    at = _load_json("at_envelope_apt28.json")
    hos = _load_json("hos_envelope_apt28.json")

    def send(topic: str, key: str | None, value: dict) -> None:
        producer.produce(
            topic=topic,
            key=key.encode() if key else None,
            value=json.dumps(value, separators=(",", ":")).encode(),
        )
        producer.poll(0)

    # Vendor catalogs stay SHARED — both tenants read the same AT + HoS.
    send("detectflow.active-threats", at["id"], at)
    send("detectflow.hos-rules", hos["id"], hos)
    send(CONFIG.format(CORR_A), CONFIG_KEY, _chains_config(CORR_A, "tenant-a"))
    send(CONFIG.format(CORR_B), CONFIG_KEY, _chains_config(CORR_B, "tenant-b"))
    producer.flush(15)
    # Broadcast state must land before main-stream events, or the first events
    # are dropped as no_hits and the chain never forms.
    time.sleep(12)

    events = _load_jsonl("events_apt28.jsonl")

    for ev in _rewrite(events, hostname=host_a_only, pipeline_id=A1):
        send(TAGGED.format(A1), ev["hostname"], ev)
    producer.flush(15)

    for ev in _rewrite(events, hostname=host_shared, pipeline_id=A1):
        send(TAGGED.format(A1), ev["hostname"], ev)
    for ev in _rewrite(events, hostname=host_shared, pipeline_id=B1):
        send(TAGGED.format(B1), ev["hostname"], ev)
    producer.flush(30)

    return {
        "host_a_only": host_a_only,
        "host_shared": host_shared,
        "window_start": _expected_window_start(events),
        "job_names": {"a": names_a, "b": names_b},
    }


def test_tenant_a_events_never_appear_on_any_tenant_b_topic(two_tenant_run):
    """Isolation is proven negatively: count tenant-A sentinels on ALL of B's topics."""
    sentinel = two_tenant_run["host_a_only"].encode()
    # Wait for A's own chain first, so B has had at least as long to leak one.
    assert _chains(
        RAW.format(CORR_A),
        match=lambda c: c["hostname"] == two_tenant_run["host_a_only"],
        expected=1,
    ), "tenant A produced no chain — the isolation count would be vacuous"

    counts = {topic: sum(sentinel in v for v in _read_topic(topic)) for topic in B_TOPICS}
    assert counts == dict.fromkeys(B_TOPICS, 0), f"tenant-A data reached tenant B: {counts}"


def test_chain_stamp_is_a_uuid_that_matches_the_topic_it_arrived_on(two_tenant_run):
    """The stamp identifies the owning pipeline, and is never the JOB_ID string."""
    for pipeline_id, job_id in ((CORR_A, JOB_ID_A), (CORR_B, JOB_ID_B)):
        chains = _chains(
            RAW.format(pipeline_id),
            match=lambda c: c["hostname"] == two_tenant_run["host_shared"],
            expected=1,
        )
        assert chains, f"no chain on {RAW.format(pipeline_id)}"
        for chain in chains:
            stamp = chain.get("correlation_pipeline_id")
            assert stamp == pipeline_id, f"{stamp!r} on {pipeline_id}'s own topic"
            uuid.UUID(str(stamp))  # a non-UUID stamp is discarded by the control plane
            assert stamp != job_id, "the stamp fell back to JOB_ID, which is not a UUID"


def test_the_two_correlation_jobs_have_distinct_flink_job_names(two_tenant_run):
    """Both instances named `correlation-job` would be indistinguishable."""
    names = _running_job_names(REST_A) + _running_job_names(REST_B)
    assert len(names) == 2, f"expected one RUNNING job per tenant cluster, got {names}"
    assert len(set(names)) == 2, f"the two instances share a job name: {names}"
    assert "correlation-job" not in names, "an instance kept the bare base job name"


def test_same_host_and_hos_in_two_pipelines_yield_different_chain_ids(two_tenant_run):
    """The assertion an unscoped three-part chain_id seed fails."""
    host = two_tenant_run["host_shared"]
    window_start = two_tenant_run["window_start"]
    namespace = _namespace()

    ids: dict[str, str] = {}
    for pipeline_id in (CORR_A, CORR_B):
        chains = _chains(
            RAW.format(pipeline_id),
            match=lambda c: c["hostname"] == host and c["hos_rule_id"] == HOS_ID,
            expected=1,
        )
        assert chains, f"pipeline {pipeline_id} emitted no chain for the shared hostname"
        chain = chains[0]
        assert chain["window_start"] == window_start
        expected = build_chain_id(
            namespace, HOS_ID, host, window_start, correlation_pipeline_id=pipeline_id
        )
        assert chain["chain_id"] == expected, (
            f"chain_id for {pipeline_id} is not uuid5(NS, "
            f"'{{correlation_pipeline_id}}|{{hos_id}}|{{hostname}}|{{window_start}}')"
        )
        ids[pipeline_id] = chain["chain_id"]

    assert ids[CORR_A] != ids[CORR_B], (
        "two customers sharing a hostname and a catalogue HoS rule got the SAME chain_id — "
        "downstream their chains merge into one attack_chains row"
    )
    # And neither equals the unscoped three-part id.
    legacy = build_chain_id(namespace, HOS_ID, host, window_start)
    assert legacy not in ids.values(), "a pipeline mints the unscoped chain_id"
