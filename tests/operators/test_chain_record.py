"""build_chain_record — envelope shape, AT inlining, snapshot vs. fixture."""

from __future__ import annotations

from datetime import datetime

from app.operators.chain_buffer import ChainBuffer
from app.operators.chain_record import build_chain_record

WINDOW_START_ISO = "2026-04-22T09:30:00Z"
WINDOW_START_EPOCH = 1776850200
CHAIN_ID = "6966fa87-8a76-5910-b216-61ffb99ec038"
HOSTNAME = "WKST-FIN-05"


def _ts_to_epoch(iso: str) -> int:
    return int(datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp())


def _seq_for_rule(hos: dict, rule_id: str) -> int:
    for s in hos["seqs"]:
        if rule_id in s["rule_ids"]:
            return int(s["seq"])
    raise AssertionError(f"rule_id {rule_id} not found in any seq of HoS {hos.get('id')}")


def _buffer_with_apt28_5_of_6(hos: dict, events: list[dict]) -> ChainBuffer:
    """Simulate matcher behaviour over the canonical 5-event APT28 fixture."""
    last_ts = max(_ts_to_epoch(e["timestamp"]) for e in events)
    buf = ChainBuffer.empty(
        WINDOW_START_EPOCH, _ts_to_epoch(events[0]["timestamp"]), timeframe_s=1800
    )
    buf.last_activity_epoch = last_ts
    for raw in events:
        rule_id = raw["detectflow"]["matches"][0]["sigma_rule_uuid"]
        seq = _seq_for_rule(hos, rule_id)
        buf.add_event(seq, rule_id, raw, _ts_to_epoch(raw["timestamp"]))
    return buf


def test_active_threat_is_inlined_without_operational_fields(hos_apt28, at_apt28, events_apt28):
    buf = _buffer_with_apt28_5_of_6(hos_apt28, events_apt28)
    record = build_chain_record(
        hos=hos_apt28,
        active_threat=at_apt28,
        hostname=HOSTNAME,
        buffer=buf,
        revision=1,
        chain_id=CHAIN_ID,
        window_start_iso=WINDOW_START_ISO,
    )

    inlined = record["active_threat"]
    # Human-facing fields present
    assert inlined["name"] == "APT28"
    assert inlined["severity"] == "CRITICAL"
    assert "summary" in inlined and "investigation" in inlined
    assert inlined["threat_actors"] == at_apt28["threat_actors"]
    # Operational fields stripped — detectflow-backend owns these, snapshot must not carry
    for excluded in ("id", "enabled", "monitored_topics", "release_date", "source", "updated_at"):
        assert excluded not in inlined, f"{excluded} leaked into inlined AT"
    # active_threat_id is the FK; lives at the top level, not inside the inlined object
    assert record["active_threat_id"] == at_apt28["id"]


def test_seqs_preserves_rule_seq_order_marks_misses_and_carries_rule_ids(
    hos_apt28, at_apt28, events_apt28
):
    buf = _buffer_with_apt28_5_of_6(hos_apt28, events_apt28)
    record = build_chain_record(
        hos=hos_apt28,
        active_threat=at_apt28,
        hostname=HOSTNAME,
        buffer=buf,
        revision=1,
        chain_id=CHAIN_ID,
        window_start_iso=WINDOW_START_ISO,
    )
    # Order = HoS YAML seq order. Every entry carries `rule_ids` — both hit
    # and miss — so the frontend can render a missed seq with its expected
    # sigma rules (rendered as greyed-out chips on the kill-chain ribbon).
    assert record["seqs"] == [
        {
            "seq": 1,
            "hit": True,
            "rule_ids": [
                "5e000002-0000-4000-8000-000000000002",
                "5e000003-0000-4000-8000-000000000003",
            ],
        },
        {
            "seq": 2,
            "hit": True,
            "rule_ids": [
                "5e000004-0000-4000-8000-000000000004",
                "5e000005-0000-4000-8000-000000000005",
            ],
        },
        {"seq": 3, "hit": True, "rule_ids": ["5e000006-0000-4000-8000-000000000006"]},
        {
            "seq": 4,
            "hit": True,
            "rule_ids": [
                "5e000007-0000-4000-8000-000000000007",
                "5e000008-0000-4000-8000-000000000008",
                "5e000009-0000-4000-8000-000000000009",
                "5e00000a-0000-4000-8000-00000000000a",
                "5e00000b-0000-4000-8000-00000000000b",
                "5e00000c-0000-4000-8000-00000000000c",
            ],
        },
        {
            "seq": 5,
            "hit": True,
            "rule_ids": [
                "5e00000d-0000-4000-8000-00000000000d",
                "5e00000e-0000-4000-8000-00000000000e",
                "5e00000f-0000-4000-8000-00000000000f",
            ],
        },
        # Missed seq still carries its declared rule_ids — UI uses these to
        # render the "expected rules" tooltip on greyed-out seqs.
        {"seq": 6, "hit": False, "rule_ids": ["5e000010-0000-4000-8000-000000000010"]},
    ]


def test_events_are_sorted_by_timestamp_and_carry_match_metadata(hos_apt28, at_apt28, events_apt28):
    buf = _buffer_with_apt28_5_of_6(hos_apt28, events_apt28)
    record = build_chain_record(
        hos=hos_apt28,
        active_threat=at_apt28,
        hostname=HOSTNAME,
        buffer=buf,
        revision=1,
        chain_id=CHAIN_ID,
        window_start_iso=WINDOW_START_ISO,
    )
    timestamps = [e["timestamp"] for e in record["events"]]
    assert timestamps == sorted(timestamps)
    # Match metadata enriched from detectflow.matches
    first = record["events"][0]
    assert first["seq"] == 1
    assert first["sigma_rule_id"] == "5e000002-0000-4000-8000-000000000002"
    assert first["sigma_rule_title"].startswith("Suspicious Execution From RAR Archive")
    assert first["technique_ids"] == ["T1204"]
    assert "process_name" in first["parsed_event"]


def test_match_metadata_resolves_by_uuid_not_rule_db_id(hos_apt28, at_apt28):
    """Enrichment keys on `sigma_rule_uuid`, NOT `_rule_id`.

    In production the matcher's `_rule_id` (control-plane `rules.id`) differs
    from the Sigma UUID; the inverted index and chain enrichment must both
    key on the UUID. Regression for the old `_find_detection(rule_id)` path
    that silently lost titles/techniques whenever `rules.id` != uuid.
    """
    uuid = "5e000002-0000-4000-8000-000000000002"  # seq-1 rule
    raw = {
        "event_id": "evt-divergent",
        "timestamp": "2026-04-22T09:31:11Z",
        "source_topic": "dest-windows-events-raw",
        "parsed_event": {"process_name": "WinRAR.exe"},
        "detectflow": {
            "matches": [
                {
                    "sigma_rule_uuid": uuid,
                    "_rule_id": "db-0001",  # deliberately != uuid
                    "rule_name": "Suspicious Execution From RAR Archive",
                    "severity": "high",
                    "mitre_techniques": ["T1204"],
                }
            ]
        },
    }
    buf = ChainBuffer.empty(WINDOW_START_EPOCH, _ts_to_epoch(raw["timestamp"]), timeframe_s=1800)
    buf.add_event(1, uuid, raw, _ts_to_epoch(raw["timestamp"]))
    record = build_chain_record(
        hos=hos_apt28,
        active_threat=at_apt28,
        hostname=HOSTNAME,
        buffer=buf,
        revision=1,
        chain_id=CHAIN_ID,
        window_start_iso=WINDOW_START_ISO,
    )
    ev = record["events"][0]
    assert ev["sigma_rule_id"] == uuid
    assert ev["rule_db_id"] == "db-0001"
    assert ev["sigma_rule_title"] == "Suspicious Execution From RAR Archive"
    assert ev["technique_ids"] == ["T1204"]


def test_counts_and_window_bounds(hos_apt28, at_apt28, events_apt28):
    buf = _buffer_with_apt28_5_of_6(hos_apt28, events_apt28)
    record = build_chain_record(
        hos=hos_apt28,
        active_threat=at_apt28,
        hostname=HOSTNAME,
        buffer=buf,
        revision=1,
        chain_id=CHAIN_ID,
        window_start_iso=WINDOW_START_ISO,
    )
    assert record["event_count"] == 5
    assert record["rule_count"] == 5
    assert record["coverage"] == 83.33
    assert record["first_seen"] == "2026-04-22T09:31:11Z"
    assert record["last_seen"] == "2026-04-22T09:31:31Z"
    assert record["chain_type"] == "HOS"
    assert record["username"] is None  # chains are keyed by hostname only


def test_revision_is_passed_through(hos_apt28, at_apt28, events_apt28):
    buf = _buffer_with_apt28_5_of_6(hos_apt28, events_apt28)
    for rev in (1, 2, 7):
        record = build_chain_record(
            hos=hos_apt28,
            active_threat=at_apt28,
            hostname=HOSTNAME,
            buffer=buf,
            revision=rev,
            chain_id=CHAIN_ID,
            window_start_iso=WINDOW_START_ISO,
        )
        assert record["revision"] == rev


def test_hos_tags_passes_through_envelope_tags(at_apt28):
    """`hos_tags` is a verbatim pass-through of the HoS envelope `tags[]`.

    Includes both `attack.Txxxx` ATT&CK markers and the `active_threat.<uuid>`
    back-pointer — the consumer (detectflow-backend) filters by prefix on read,
    correlation-job does no parsing. Falls back to `[]` when `tags` absent."""
    hos_with_tags = {
        "id": "hos-stub",
        "seqs": [],
        "tags": ["attack.T1203", "active_threat.x"],
    }
    buf = ChainBuffer.empty(WINDOW_START_EPOCH, WINDOW_START_EPOCH, timeframe_s=1800)
    record = build_chain_record(
        hos=hos_with_tags,
        active_threat=at_apt28,
        hostname=HOSTNAME,
        buffer=buf,
        revision=1,
        chain_id=CHAIN_ID,
        window_start_iso=WINDOW_START_ISO,
    )
    # Verbatim pass-through, order preserved
    assert record["hos_tags"] == ["attack.T1203", "active_threat.x"]

    # Default `[]` when `tags` absent — defensive, the matcher doesn't
    # require detectflow-backend to send `tags[]` (it's UI-facing).
    hos_no_tags = {"id": "hos-stub", "seqs": []}
    record2 = build_chain_record(
        hos=hos_no_tags,
        active_threat=at_apt28,
        hostname=HOSTNAME,
        buffer=buf,
        revision=1,
        chain_id=CHAIN_ID,
        window_start_iso=WINDOW_START_ISO,
    )
    assert record2["hos_tags"] == []


def test_zero_seq_hos_does_not_divide_by_zero(at_apt28):
    """Defensive: an empty/malformed HoS should produce coverage=0, not crash."""
    empty_hos = {"id": "empty", "seqs": []}
    buf = ChainBuffer.empty(WINDOW_START_EPOCH, WINDOW_START_EPOCH, timeframe_s=1800)
    record = build_chain_record(
        hos=empty_hos,
        active_threat=at_apt28,
        hostname=HOSTNAME,
        buffer=buf,
        revision=1,
        chain_id=CHAIN_ID,
        window_start_iso=WINDOW_START_ISO,
    )
    assert record["coverage"] == 0.0
    assert record["seqs"] == []
    assert record["events"] == []


def test_event_carries_pipeline_id_from_tagged_event(hos_apt28, at_apt28, events_apt28):
    """`ChainEvent.pipeline_id` is propagated verbatim from the tagged event."""
    events = [{**raw, "pipeline_id": f"pipe-{i}"} for i, raw in enumerate(events_apt28)]
    buf = _buffer_with_apt28_5_of_6(hos_apt28, events)
    record = build_chain_record(
        hos=hos_apt28,
        active_threat=at_apt28,
        hostname=HOSTNAME,
        buffer=buf,
        revision=1,
        chain_id=CHAIN_ID,
        window_start_iso=WINDOW_START_ISO,
    )
    by_id = {e["event_id"]: e for e in record["events"]}
    for i, raw in enumerate(events):
        assert by_id[raw["event_id"]]["pipeline_id"] == f"pipe-{i}"
        assert "source_topic" not in by_id[raw["event_id"]]


def test_event_pipeline_id_none_when_missing(hos_apt28, at_apt28, events_apt28):
    """When the tagged event lacks `pipeline_id`, the ChainEvent dict carries None."""
    events = [{k: v for k, v in raw.items() if k != "pipeline_id"} for raw in events_apt28]
    buf = _buffer_with_apt28_5_of_6(hos_apt28, events)
    record = build_chain_record(
        hos=hos_apt28,
        active_threat=at_apt28,
        hostname=HOSTNAME,
        buffer=buf,
        revision=1,
        chain_id=CHAIN_ID,
        window_start_iso=WINDOW_START_ISO,
    )
    for ev in record["events"]:
        assert ev["pipeline_id"] is None
        assert "source_topic" not in ev


def test_snapshot_against_fixture(hos_apt28, at_apt28, events_apt28, chain_raw_apt28):
    """Snapshot test: building the chain record from canonical fixture inputs
    must reproduce the canonical chain_raw_apt28_v1.json (modulo fields the
    operator does not own — see assertions below)."""
    buf = _buffer_with_apt28_5_of_6(hos_apt28, events_apt28)
    record = build_chain_record(
        hos=hos_apt28,
        active_threat=at_apt28,
        hostname=HOSTNAME,
        buffer=buf,
        revision=1,
        chain_id=CHAIN_ID,
        window_start_iso=WINDOW_START_ISO,
    )

    for field in (
        "chain_id",
        "hos_rule_id",
        "active_threat_id",
        "active_threat",
        "hos_tags",
        "chain_type",
        "hostname",
        "username",
        "window_start",
        "first_seen",
        "last_seen",
        "coverage",
        "seqs",
        "event_count",
        "rule_count",
        "revision",
    ):
        assert record[field] == chain_raw_apt28[field], f"mismatch on {field}"

    # Retired field: it carried destination-topic names, no consumer read it
    # back, and per-flow identity is `events[].pipeline_id`.
    assert "pipeline_names" not in record

    # events[]: same length and same per-event identity, but the fixture's
    # parsed_event field is a hand-trimmed subset for readability (not the
    # operator's responsibility — we pass parsed_event verbatim). Compare on
    # the structural fields the operator owns.
    assert len(record["events"]) == len(chain_raw_apt28["events"])
    for actual, expected in zip(record["events"], chain_raw_apt28["events"]):
        for f in (
            "event_id",
            "sigma_rule_id",
            "rule_db_id",
            "sigma_rule_title",
            "seq",
            "timestamp",
            "technique_ids",
            "pipeline_id",
        ):
            assert actual[f] == expected[f], f"events.{f} mismatch"


# ---------------------------------------------------------------------------
# events_dropped + emit-time per-seq shrink (record-size guard)
# ---------------------------------------------------------------------------


def _buffer_with_n_events(n: int, seq: int = 1) -> ChainBuffer:
    buf = ChainBuffer.empty(1776850200, 1776850200, 1800)
    for i in range(n):
        buf.add_event(
            seq,
            "5e000002-0000-4000-8000-000000000002",
            {
                "event_id": f"e{i:03d}",
                "timestamp": f"2026-04-22T13:30:{i:02d}Z",
                "source_topic": "windows-detections",
                "detectflow": {"matches": []},
                "parsed_event": {"i": i},
            },
            1776850200 + i,
        )
    return buf


def test_events_dropped_defaults_to_zero(hos_apt28, at_apt28, events_apt28):
    buf = ChainBuffer.empty(1776850200, 1776850200, 1800)
    buf.add_event(1, "5e000002-0000-4000-8000-000000000002", events_apt28[0], 1776850200)
    record = build_chain_record(
        hos=hos_apt28,
        active_threat=at_apt28,
        hostname="h",
        buffer=buf,
        revision=1,
        chain_id="c",
        window_start_iso="2026-04-22T13:30:00Z",
    )
    assert record["events_dropped"] == 0


def test_buffer_dropped_events_propagate_to_envelope(hos_apt28, at_apt28, events_apt28):
    buf = ChainBuffer.empty(1776850200, 1776850200, 1800)
    for _ in range(4):
        buf.add_event(
            1, "5e000002-0000-4000-8000-000000000002", events_apt28[0], 1776850200, max_per_seq=2
        )
    record = build_chain_record(
        hos=hos_apt28,
        active_threat=at_apt28,
        hostname="h",
        buffer=buf,
        revision=1,
        chain_id="c",
        window_start_iso="2026-04-22T13:30:00Z",
    )
    assert record["events_dropped"] == 2
    assert record["event_count"] == 2


def test_emit_time_shrink_keeps_chronologically_first(hos_apt28, at_apt28):
    buf = _buffer_with_n_events(10)
    record = build_chain_record(
        hos=hos_apt28,
        active_threat=at_apt28,
        hostname="h",
        buffer=buf,
        revision=1,
        chain_id="c",
        window_start_iso="2026-04-22T13:30:00Z",
        max_events_per_seq=3,
    )
    assert record["event_count"] == 3
    assert [e["event_id"] for e in record["events"]] == ["e000", "e001", "e002"]
    assert record["events_dropped"] == 7
    # Coverage unchanged by the shrink — seq 1 still hit.
    assert record["seqs"][0]["hit"] is True


# ---------------------------------------------------------------------------
# Correlation-pipeline stamp
# ---------------------------------------------------------------------------

PIPELINE_ID = "3f2b8c14-9f6a-4c3d-8f21-2a7b5c9d1e04"


def test_correlation_pipeline_id_and_name_are_stamped(hos_apt28, at_apt28, events_apt28):
    """The chain names its owning correlation pipeline, so the control plane
    can attribute it without parsing topic names — destination-topic names are
    NOT unique across detection pipelines."""
    buf = _buffer_with_apt28_5_of_6(hos_apt28, events_apt28)
    record = build_chain_record(
        hos=hos_apt28,
        active_threat=at_apt28,
        hostname=HOSTNAME,
        buffer=buf,
        revision=1,
        chain_id=CHAIN_ID,
        window_start_iso=WINDOW_START_ISO,
        correlation_pipeline_id=PIPELINE_ID,
        correlation_pipeline_name="Correlation Pipeline A",
    )
    assert record["correlation_pipeline_id"] == PIPELINE_ID
    assert record["correlation_pipeline_name"] == "Correlation Pipeline A"


def test_correlation_pipeline_fields_default_to_none_when_not_supplied(
    hos_apt28, at_apt28, events_apt28
):
    """Legacy single-instance deployment: no pipeline id anywhere. The keys are
    still present (stable envelope) and null — the consumer falls back to the
    topic name. `None`, never JOB_ID: the control plane parses this as a UUID."""
    buf = _buffer_with_apt28_5_of_6(hos_apt28, events_apt28)
    record = build_chain_record(
        hos=hos_apt28,
        active_threat=at_apt28,
        hostname=HOSTNAME,
        buffer=buf,
        revision=1,
        chain_id=CHAIN_ID,
        window_start_iso=WINDOW_START_ISO,
    )
    assert record["correlation_pipeline_id"] is None
    assert record["correlation_pipeline_name"] is None


def test_envelope_key_set_is_additive_only(hos_apt28, at_apt28, events_apt28, chain_raw_apt28):
    """Wire-contract guard: the envelope may only ever GROW. Pins the full
    top-level key set as the canonical fixture's keys + `events_dropped` +
    exactly the two pipeline-stamp fields. A rename or a drop is breaking for
    agent-job and the control plane and needs a coordinated four-repo change."""
    buf = _buffer_with_apt28_5_of_6(hos_apt28, events_apt28)
    record = build_chain_record(
        hos=hos_apt28,
        active_threat=at_apt28,
        hostname=HOSTNAME,
        buffer=buf,
        revision=1,
        chain_id=CHAIN_ID,
        window_start_iso=WINDOW_START_ISO,
    )
    expected = set(chain_raw_apt28) | {
        "events_dropped",
        "correlation_pipeline_id",
        "correlation_pipeline_name",
    }
    assert set(record) == expected
