"""Drive integration-test scenarios against the docker-compose stack.

Two phases per run:

1. **Seed broadcast meta topics** — AT, HoS, and chains-config envelopes from
   `tests/fixtures/attack-chains/`. Compacted topics keyed by id (AT/HoS) or
   the singleton `"global"` (config). After producing, we flush and pause for
   ``--consume-window`` seconds so correlation-job has a chance to consume
   the broadcast records before main-stream events arrive. Without this
   pause, early events race with broadcast state and get dropped as
   `events_dropped_no_hits`.

2. **Publish events** for the requested ``--scenario``. Event timestamps come
   from fixtures (pinned absolute) so watermark progression is deterministic
   across runs. ``--pace`` adds wall-clock spacing between events but does
   NOT touch event-time — the ``forBoundedOutOfOrderness(60s)`` strategy
   reads ``event.timestamp`` regardless.

Scenarios:

- ``steady``         5 APT28 events covering seqs 1-5 → revision-1 chain
- ``window-update``  steady + seq-6 event within window → revision-2 chain
- ``window-expiry``  steady + tick event past ``window_start + timeframe``
                     → cleanup timer fires, buffer cleared
- ``late``           steady + seq-6 on-time (advances WM) + seq-6 LATE
                     event (must drop, must NOT inflate coverage to 100%)

Usage (with the stack running and ports exposed on localhost):

    python -m tests.integration.producer --scenario steady
    python -m tests.integration.producer --scenario late --bootstrap kafka:9092
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

from confluent_kafka import Producer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [producer] %(message)s")
log = logging.getLogger("integration.producer")

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "attack-chains"

# Topic constants — match the names provisioned by topic-init/init.sh and
# the defaults baked into app/config/settings.py.
T_AT = "detectflow.active-threats"
T_HOS = "detectflow.hos-rules"
T_CONFIG = "detectflow.chains-config"

CONFIG_KEY = "global"

# Pipeline destination topics provisioned by topic-init/init.sh. The matcher
# subscribes to the union of these (--input-topics CLI flag).
T_DEST_TOPICS = (
    "dest-windows-events-raw",
    "dest-powershell-logs-raw",
    "dest-cloudtrail-detections",
)

# Watermark-warmup timestamp: anchor far in the past so even after
# `forBoundedOutOfOrderness(60s)` it produces a watermark that's well before
# every real event in the corpus. The warmup events use a rule_id that's
# guaranteed not to be in any HoS index, so they bump `events_dropped_no_hits`
# but never contribute to a chain.
WARMUP_TIMESTAMP = "2000-01-01T00:00:00Z"
WARMUP_RULE_ID = "00000000-0000-0000-0000-000000000000"


# ---------- helpers ----------------------------------------------------------


def _load_json(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


# The correlation pipeline this stack runs as. Read off the seeded config
# envelope so there is ONE source of truth: the same value is set as
# CORRELATION_PIPELINE_ID in docker-compose.yml (x-correlation-env), and it is
# the 5th input of the chain_id seed — tests that recompute an expected
# chain_id must pass it, or they only ever cover the legacy 3-part formula.
CORRELATION_PIPELINE_ID: str = _load_json("chains_config.json")["correlation_pipeline_id"]


def _load_jsonl(name: str) -> list[dict]:
    return [json.loads(line) for line in (FIXTURES / name).read_text().splitlines() if line.strip()]


def _make_producer(bootstrap: str) -> Producer:
    return Producer(
        {
            "bootstrap.servers": bootstrap,
            "client.id": "detectflow-integration-producer",
            "enable.idempotence": True,
            "acks": "all",
            "linger.ms": 10,
        }
    )


def _delivery(err, msg):
    if err is not None:
        log.error("delivery failed: %s", err)
    else:
        log.debug(
            "delivered key=%s topic=%s partition=%s offset=%s",
            msg.key(),
            msg.topic(),
            msg.partition(),
            msg.offset(),
        )


def _produce(producer: Producer, topic: str, key: str | None, value: dict) -> None:
    producer.produce(
        topic=topic,
        key=key.encode("utf-8") if key else None,
        value=json.dumps(value, separators=(",", ":")).encode("utf-8"),
        callback=_delivery,
    )
    producer.poll(0)


# ---------- phases -----------------------------------------------------------


def _warmup_pipeline_topics(producer: Producer) -> None:
    """Publish one ancient-timestamp / no-match event to EACH partition of
    each pipeline destination topic so every Kafka source split emits a
    real watermark on startup.

    Why: the matcher consumes the union of N destination topics. Per-job
    `ProcessFunction.current_watermark()` returns the MIN watermark across
    all source splits. A split that never receives an event keeps its
    watermark at Long.MIN, which freezes the matcher's effective
    watermark and silently disables late-drop. `with_idleness(10s)` on
    the source is the production fix, but Pyflink+KafkaSource v2 in our
    setup does not reliably propagate idleness from a split that has
    NEVER seen a record — without warmup the matcher's clock stays at
    Long.MIN whenever the test fixture only publishes to a subset of
    topics or partitions.

    Topics are provisioned with 2 partitions (matching matcher
    parallelism), so warmup publishes one event PER partition to make
    every source split warm. Bootstrap events use a rule_id that's not
    in any HoS index, so they bump `events_dropped_no_hits` but never
    contribute to a chain.
    """
    for topic in T_DEST_TOPICS:
        for partition in (0, 1):
            envelope = {
                "event_id": f"warmup-{topic}-p{partition}",
                "hostname": f"WARMUP-{topic}-p{partition}",
                "timestamp": WARMUP_TIMESTAMP,
                "source_topic": topic,
                "pipeline_id": "00000000-0000-0000-0000-000000000000",
                "detectflow": {"matches": [{"sigma_rule_uuid": WARMUP_RULE_ID}]},
                "parsed_event": {},
            }
            producer.produce(
                topic=topic,
                partition=partition,
                key=envelope["hostname"].encode("utf-8"),
                value=json.dumps(envelope, separators=(",", ":")).encode("utf-8"),
                callback=_delivery,
            )
            producer.poll(0)
    producer.flush(timeout=15)


def seed_meta(producer: Producer, *, consume_window: float) -> None:
    """Push AT + HoS + config to the broadcast topics, warm up every
    pipeline destination topic so all source watermarks advance off
    Long.MIN, flush, then sleep so correlation-job consumes them before
    any main-stream event arrives."""
    at = _load_json("at_envelope_apt28.json")
    hos = _load_json("hos_envelope_apt28.json")
    cfg = _load_json("chains_config.json")

    _produce(producer, T_AT, at["id"], at)
    _produce(producer, T_HOS, hos["id"], hos)
    _produce(producer, T_CONFIG, CONFIG_KEY, cfg)

    _warmup_pipeline_topics(producer)

    producer.flush(timeout=15)
    window_s = cfg.get("correlation_window_seconds")
    log.info(
        "seeded meta: AT=%s HoS=%s pipeline=%s config(threshold=%d, window=%s) "
        "+ watermark warmup on %d destination topics",
        at["id"],
        hos["id"],
        cfg.get("correlation_pipeline_id"),
        cfg["threshold_pct"],
        # A non-null window is an explicit OVERRIDE of the HoS rule's
        # detection.timeframe; null/absent inherits it.
        f"{window_s}s override" if window_s else "inherit HoS timeframe",
        len(T_DEST_TOPICS),
    )

    if consume_window > 0:
        log.info("waiting %.1fs for matcher to consume broadcast state", consume_window)
        time.sleep(consume_window)


def publish_events(producer: Producer, events: list[dict], *, pace: float, label: str) -> None:
    """Send each event to its `source_topic` keyed by hostname (matches
    `detectflow-matchnode`'s upstream contract)."""
    for ev in events:
        topic = ev["source_topic"]
        key = ev.get("hostname")
        _produce(producer, topic, key, ev)
        log.info(
            "[%s] %s @ %s → %s (rules=%s)",
            label,
            ev["event_id"],
            ev["timestamp"],
            topic,
            [m.get("sigma_rule_uuid") for m in (ev.get("detectflow") or {}).get("matches", [])],
        )
        producer.poll(0)
        if pace > 0:
            time.sleep(pace)
    producer.flush(timeout=15)


# ---------- scenarios --------------------------------------------------------


def scenario_steady(producer: Producer, *, pace: float) -> None:
    publish_events(producer, _load_jsonl("events_apt28.jsonl"), pace=pace, label="steady")


def scenario_window_update(producer: Producer, *, pace: float) -> None:
    """Steady burst → revision 1 emits at coverage 4/6 then 5/6 (2 emissions
    per the matcher's monotonic-revision rule). Then a single seq-6 event
    within the window → revision 3 at coverage 6/6 with the same chain_id."""
    publish_events(producer, _load_jsonl("events_apt28.jsonl"), pace=pace, label="steady")
    # Small gap so the revision-1/2 chain hits chains-raw before the seq-6
    # event lands. Pure observability convenience for the test harness; the
    # matcher itself is event-time-driven and would handle reordering.
    time.sleep(2.0)
    publish_events(producer, [_load_json("events_apt28_seq6.json")], pace=0, label="seq6")


def scenario_window_expiry(producer: Producer, *, pace: float) -> None:
    """Steady burst → wait → tick on a throwaway hostname with timestamp past
    ``window_start + timeframe``. Watermark advances → cleanup timer fires
    on WKST-FIN-05 buffer."""
    publish_events(producer, _load_jsonl("events_apt28.jsonl"), pace=pace, label="steady")
    time.sleep(2.0)
    publish_events(
        producer,
        [_load_json("events_apt28_expiry_tick.json")],
        pace=0,
        label="expiry-tick",
    )


def scenario_late(producer: Producer, *, pace: float) -> None:
    """Steady burst → on-time seq-6 (advances WM past 09:31:36) → LATE
    seq-6 event with timestamp at 09:30:00. The late event MUST be dropped:
    if it weren't, coverage would jump to 100% and a revision would be
    emitted, which the test asserts NOT to happen."""
    publish_events(producer, _load_jsonl("events_apt28.jsonl"), pace=pace, label="steady")
    time.sleep(2.0)
    publish_events(producer, [_load_json("events_apt28_seq6.json")], pace=0, label="seq6-on-time")
    # WM is now anchored on the seq-6 timestamp (09:31:36) - 60s = 09:30:36.
    # The late event at 09:30:00 is ~36s past the boundary → drop expected.
    time.sleep(2.0)
    publish_events(producer, [_load_json("events_apt28_late.json")], pace=0, label="late-drop")


SCENARIOS = {
    "steady": scenario_steady,
    "window-update": scenario_window_update,
    "window-expiry": scenario_window_expiry,
    "late": scenario_late,
}


# ---------- main -------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Drive Attack Chains integration-test scenarios.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--scenario", required=True, choices=sorted(SCENARIOS.keys()))
    parser.add_argument(
        "--bootstrap",
        default="localhost:19092",
        help="Kafka bootstrap servers (use kafka:9092 from inside the compose net).",
    )
    parser.add_argument(
        "--consume-window",
        type=float,
        default=8.0,
        help="Seconds to wait after seeding meta topics, so correlation-job "
        "consumes broadcast state before events arrive.",
    )
    parser.add_argument(
        "--pace",
        type=float,
        default=0.2,
        help="Wall-clock seconds between event publishes (event-time is "
        "fixture-pinned and unaffected).",
    )
    parser.add_argument(
        "--seed-only",
        action="store_true",
        help="Seed broadcast topics and exit; no events.",
    )
    args = parser.parse_args(argv)

    producer = _make_producer(args.bootstrap)
    log.info("scenario=%s bootstrap=%s", args.scenario, args.bootstrap)

    seed_meta(producer, consume_window=args.consume_window)

    if not args.seed_only:
        SCENARIOS[args.scenario](producer, pace=args.pace)

    producer.flush(timeout=30)
    log.info("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
