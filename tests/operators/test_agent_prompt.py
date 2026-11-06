"""Prompt builder tests — single-mode (one representative per group).

Replaces the older
strict/loose/cap/drop cascade tests after the cascade was retired (in practice
most chains hit `loose_dropped` and emitted `INSUFFICIENT_CONTEXT`).
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from unittest.mock import MagicMock

from pydantic import SecretStr

from app.config.settings import Settings
from app.observability.metrics import Metrics
from app.operators.agent_prompt import (
    AGGREGATION_METHOD,
    PIPELINE_PER_GROUP_CAP,
    PROMPT_BUILDER_VERSION,
    SYSTEM_PROMPT,
    UNKNOWN_PIPELINE_ID,
    build_prompt,
    build_prompt_with_aggregation,
)
from app.operators.chain_models import ChainRaw
from app.operators.correlation_agent import analyse_chain_raw
from app.operators.llm_client import LlmResult

FIXTURES_DIR = Path(__file__).parents[1] / "fixtures" / "attack-chains"
SNAPSHOTS_DIR = Path(__file__).parent / "snapshots"


def _load_apt28() -> ChainRaw:
    return ChainRaw.model_validate(
        json.loads((FIXTURES_DIR / "chain_raw_apt28_v1.json").read_text())
    )


def _load_burst() -> ChainRaw:
    return ChainRaw.model_validate(
        json.loads((FIXTURES_DIR / "chain_raw_burst_netloader.json").read_text())
    )


def _apt28_dict() -> dict:
    return json.loads((FIXTURES_DIR / "chain_raw_apt28_v1.json").read_text())


def _settings() -> Settings:
    return Settings(
        kafka_bootstrap_servers="localhost:9092",
        kafka_auth_method="PLAINTEXT",
        llm_api_key=SecretStr("test"),
        llm_prompt_char_budget=24_000,
        llm_calls_per_minute=60,
        llm_max_retries=3,
    )


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------


def test_system_prompt_describes_v2_output_schema_with_insufficient_context():
    """System prompt enumerates all 4 verdicts (incl. INSUFFICIENT_CONTEXT)
    and the JSON envelope. Cascade-era phrases must be gone after the v2
    rewrite — none of the strings the old prompt used to anchor on
    (`common`, `per-event differences`, `abridged`, `groups dropped`,
    `aggregated from`) survive."""
    assert "TRUE" in SYSTEM_PROMPT
    assert "SUSPICIOUS" in SYSTEM_PROMPT
    assert "FALSE_POSITIVE" in SYSTEM_PROMPT
    assert "INSUFFICIENT_CONTEXT" in SYSTEM_PROMPT
    assert '"verdict"' in SYSTEM_PROMPT
    assert '"confidence"' in SYSTEM_PROMPT
    assert '"summary"' in SYSTEM_PROMPT
    assert '"review"' in SYSTEM_PROMPT
    assert "missing_context" in SYSTEM_PROMPT

    # Cascade-era anchors are gone.
    for stale in (
        "common (",
        "per-event differences",
        "abridged",
        "groups dropped",
        "aggregated from",
    ):
        assert stale not in SYSTEM_PROMPT, f"stale cascade anchor still present: {stale!r}"

    # New anchors are in.
    assert "representative" in SYSTEM_PROMPT
    assert "event_count" in SYSTEM_PROMPT


# ---------------------------------------------------------------------------
# Group rendering shape
# ---------------------------------------------------------------------------


def test_render_one_group_per_seq_rule_pair():
    """3 events with distinct `(seq, sigma_rule_id)` keys render as 3
    group blocks, in first-seen order of the keys in the input."""
    chain = _load_apt28()
    # APT28's first 3 events already have distinct (seq, sigma_rule_id).
    chain.events = chain.events[:3]
    result = build_prompt_with_aggregation(chain)

    assert len(result.aggregation_summary) == 3
    # Group block markers in first-seen order.
    for idx in (1, 2, 3):
        assert f"[{idx}] Group seq=" in result.user
    # Rule titles surface verbatim.
    assert "Suspicious Execution From RAR Archive" in result.user
    assert "MSHTA Execution" in result.user


def test_representative_is_chronologically_first_event():
    """Within a group, the representative is sorted by `(timestamp,
    event_id)` ascending — the chronologically earliest event."""
    chain_dict = _apt28_dict()
    base = deepcopy(chain_dict["events"][0])
    chain_dict["events"] = []
    # Two events on the same (seq, rule_id). Append the LATER timestamp
    # first to make sure the renderer's own sort (not input order)
    # picks the earlier one.
    for ts, eid, marker in (
        ("2026-04-22T09:31:45Z", "evt-late", "LATE-MARKER"),
        ("2026-04-22T09:31:11Z", "evt-early", "EARLY-MARKER"),
    ):
        ev = deepcopy(base)
        ev["event_id"] = eid
        ev["timestamp"] = ts
        ev["parsed_event"] = {"_marker_": marker}
        chain_dict["events"].append(ev)
    chain = ChainRaw.model_validate(chain_dict)

    result = build_prompt_with_aggregation(chain)

    assert len(result.aggregation_summary) == 1
    entry = result.aggregation_summary[0]
    assert entry["event_count"] == 2
    # representative event_id printed in the rendered block is the early one.
    assert "representative event_id: evt-early" in result.user
    # The early event's parsed_event content is rendered verbatim;
    # the late event's content does not appear at all (only the
    # representative is shown).
    assert "EARLY-MARKER" in result.user
    assert "LATE-MARKER" not in result.user


def test_event_count_and_first_last_correct():
    """Group of 5 events at distinct timestamps: header reports
    `event_count=5` plus earliest+latest `first_seen` / `last_seen`."""
    chain_dict = _apt28_dict()
    base = deepcopy(chain_dict["events"][0])
    chain_dict["events"] = []
    for i in range(5):
        ev = deepcopy(base)
        ev["event_id"] = f"evt-x-{i:03d}"
        ev["timestamp"] = f"2026-04-22T09:32:{i:02d}Z"
        chain_dict["events"].append(ev)
    chain = ChainRaw.model_validate(chain_dict)

    result = build_prompt_with_aggregation(chain)

    assert len(result.aggregation_summary) == 1
    entry = result.aggregation_summary[0]
    assert entry["event_count"] == 5
    assert entry["first_seen"] == "2026-04-22T09:32:00Z"
    assert entry["last_seen"] == "2026-04-22T09:32:04Z"
    assert (
        "event_count: 5, first_seen: 2026-04-22T09:32:00Z, last_seen: 2026-04-22T09:32:04Z"
    ) in result.user


def test_parsed_event_rendered_verbatim_no_truncation():
    """A 4 000-char value inside parsed_event survives end-to-end (sanity
    for "no value truncation" — hard constraint 3 of the v2 spec)."""
    chain_dict = _apt28_dict()
    long_field = "Z" * 4_000
    chain_dict["events"] = [deepcopy(chain_dict["events"][0])]
    chain_dict["events"][0]["parsed_event"] = {
        "process": {"name": "explorer.exe"},
        "command_line": long_field,
    }
    chain = ChainRaw.model_validate(chain_dict)

    _, user = build_prompt(chain)

    assert long_field in user
    # Sanity: not a partial — full value present, not truncated to N chars.
    assert user.count("Z" * 4_000) == 1


def test_empty_events_list_doesnt_crash():
    """`chain.events == []` is a real shape (a chain with seqs but no
    surviving events shouldn't crash the renderer)."""
    chain_dict = _apt28_dict()
    chain_dict["events"] = []
    chain = ChainRaw.model_validate(chain_dict)

    system, user = build_prompt(chain)

    assert system == SYSTEM_PROMPT
    # Header reports 0 groups; the events section is the placeholder dash.
    assert "# Events (0 of 0 shown)" in user
    assert "—" in user
    # aggregation_summary is empty (no groups).
    result = build_prompt_with_aggregation(chain)
    assert result.aggregation_summary == []


def test_singleton_group_renders_as_group_block():
    """A chain with a single event still goes through the group renderer
    — not a separately-rendered "singleton" branch (the old strict-mode
    `_render_singleton` path is gone)."""
    chain = _load_apt28()
    chain.events = chain.events[:1]

    _, user = build_prompt(chain)

    # The block reads `[1] Group seq=...`, not the legacy `[1] seq=...`
    # singleton format from the cascade era.
    assert "[1] Group seq=" in user
    assert "event_count: 1" in user
    # Representative parsed_event surfaces; no aggregation annotation.
    assert "representative parsed_event:" in user


def test_grouping_splits_by_pipeline_id():
    """Same `(seq, rule)` with two distinct `pipeline_id` values → two
    group blocks. Pipeline ids are grouping identity only and are not rendered."""
    chain_dict = _apt28_dict()
    base = deepcopy(chain_dict["events"][0])
    chain_dict["events"] = []
    for i, pid in enumerate(("pipe-aaa", "pipe-bbb")):
        ev = deepcopy(base)
        ev["event_id"] = f"evt-mixed-{i}"
        ev["timestamp"] = f"2026-04-22T09:31:{30 + i}Z"
        ev["pipeline_id"] = pid
        ev["parsed_event"] = {"_marker_": f"pipe-{i}"}
        chain_dict["events"].append(ev)
    chain = ChainRaw.model_validate(chain_dict)

    result = build_prompt_with_aggregation(chain)

    assert len(result.aggregation_summary) == 2
    pipelines = {entry["pipeline_id"] for entry in result.aggregation_summary}
    assert pipelines == {"pipe-aaa", "pipe-bbb"}
    assert "source_topic:" not in result.user
    assert "pipelines:" not in result.user
    assert "[1] Group seq=" in result.user
    assert "[2] Group seq=" in result.user
    assert "pipe-0" in result.user
    assert "pipe-1" in result.user
    assert result.log_sources_capped == 0


def test_grouping_unknown_pipeline_fallback():
    """`pipeline_id` is None/missing → bucket under `<unknown-pipeline>`
    so grouping stays deterministic. The sentinel is not rendered."""
    chain_dict = _apt28_dict()
    base = deepcopy(chain_dict["events"][0])
    chain_dict["events"] = []
    for i in range(2):
        ev = deepcopy(base)
        ev["event_id"] = f"evt-unk-{i}"
        ev["timestamp"] = f"2026-04-22T09:31:{40 + i}Z"
        ev["pipeline_id"] = None
        ev["parsed_event"] = {"_marker_": f"unk-{i}"}
        chain_dict["events"].append(ev)
    chain = ChainRaw.model_validate(chain_dict)

    result = build_prompt_with_aggregation(chain)

    assert len(result.aggregation_summary) == 1
    entry = result.aggregation_summary[0]
    assert entry["pipeline_id"] == UNKNOWN_PIPELINE_ID
    assert entry["event_count"] == 2
    assert UNKNOWN_PIPELINE_ID not in result.user
    assert "source_topic:" not in result.user


def test_log_sources_capped_when_more_than_5_pipelines_per_seq_rule():
    """10 distinct `pipeline_id` values on the same `(seq, rule)` →
    5 buckets kept (earliest-first), 5 dropped, `log_sources_capped == 5`."""
    chain_dict = _apt28_dict()
    base = deepcopy(chain_dict["events"][0])
    chain_dict["events"] = []
    for i in range(10):
        ev = deepcopy(base)
        ev["event_id"] = f"evt-cap-{i:02d}"
        ev["timestamp"] = f"2026-04-22T09:35:{i:02d}Z"
        ev["pipeline_id"] = f"pipe-{i:02d}"
        chain_dict["events"].append(ev)
    chain = ChainRaw.model_validate(chain_dict)

    result = build_prompt_with_aggregation(chain)

    assert len(result.aggregation_summary) == PIPELINE_PER_GROUP_CAP
    assert result.log_sources_capped == 10 - PIPELINE_PER_GROUP_CAP
    kept = {entry["pipeline_id"] for entry in result.aggregation_summary}
    assert kept == {f"pipe-{i:02d}" for i in range(5)}
    assert "[+5 pipeline group(s) dropped by cap]" in result.user


def test_no_cap_when_exactly_5_pipelines_per_seq_rule():
    """Boundary: exactly `PIPELINE_PER_GROUP_CAP` pipelines → all kept."""
    chain_dict = _apt28_dict()
    base = deepcopy(chain_dict["events"][0])
    chain_dict["events"] = []
    for i in range(PIPELINE_PER_GROUP_CAP):
        ev = deepcopy(base)
        ev["event_id"] = f"evt-boundary-{i}"
        ev["timestamp"] = f"2026-04-22T09:36:{i:02d}Z"
        ev["pipeline_id"] = f"pipe-{i}"
        chain_dict["events"].append(ev)
    chain = ChainRaw.model_validate(chain_dict)

    result = build_prompt_with_aggregation(chain)

    assert len(result.aggregation_summary) == PIPELINE_PER_GROUP_CAP
    assert result.log_sources_capped == 0
    assert "dropped by cap" not in result.user


def test_cap_independent_per_seq_rule_parent():
    """Cap counts distinct pipelines per `(seq, rule)` PARENT — two different
    parents with 6 pipelines each cap independently (drop 1 each → total 2)."""
    chain_dict = _apt28_dict()
    rule_a = chain_dict["events"][0]["sigma_rule_id"]
    rule_b = chain_dict["events"][1]["sigma_rule_id"]
    seq_a = chain_dict["events"][0]["seq"]
    seq_b = chain_dict["events"][1]["seq"]
    base = deepcopy(chain_dict["events"][0])
    chain_dict["events"] = []
    for parent_idx, (rule, seq) in enumerate(((rule_a, seq_a), (rule_b, seq_b))):
        for i in range(PIPELINE_PER_GROUP_CAP + 1):
            ev = deepcopy(base)
            ev["event_id"] = f"evt-{parent_idx}-{i}"
            ev["sigma_rule_id"] = rule
            ev["seq"] = seq
            ev["timestamp"] = f"2026-04-22T09:37:{parent_idx * 10 + i:02d}Z"
            ev["pipeline_id"] = f"parent{parent_idx}-pipe-{i}"
            chain_dict["events"].append(ev)
    chain = ChainRaw.model_validate(chain_dict)

    result = build_prompt_with_aggregation(chain)

    assert len(result.aggregation_summary) == 2 * PIPELINE_PER_GROUP_CAP
    assert result.log_sources_capped == 2


def test_aggregation_summary_carries_pipeline_id_field():
    """Every entry in `aggregation_summary` carries `pipeline_id` for audit.

    APT28 is five distinct `(seq, rule)` groups. Seq 4 is the powershell
    pipeline; the other four are windows — the summary must echo that,
    not collapse onto a single id.
    """
    chain = _load_apt28()
    result = build_prompt_with_aggregation(chain)

    assert len(result.aggregation_summary) == 5
    expected_ids = [ev.pipeline_id for ev in chain.events]
    actual_ids = [entry["pipeline_id"] for entry in result.aggregation_summary]
    assert actual_ids == expected_ids
    assert set(actual_ids) == {
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
    }
    for entry in result.aggregation_summary:
        assert "source_topic" not in entry


def test_apt28_fixture_unchanged_snapshot():
    """Snapshot test against `chain_raw_apt28_v1.json`. The expected
    user-message lives in `tests/operators/snapshots/apt28_user.expected.txt`
    and is committed alongside this test — drift requires intentional
    re-snapshotting."""
    chain = _load_apt28()
    _, user = build_prompt(chain)

    snapshot_path = SNAPSHOTS_DIR / "apt28_user.expected.txt"
    expected = snapshot_path.read_text()
    assert user == expected, (
        "APT28 prompt snapshot drift. If the new rendering is intentional, "
        f"overwrite {snapshot_path} with the new output."
    )
    assert "source_topic:" not in user
    assert "pipelines:" not in user


def test_prompt_size_well_under_budget_on_burst_fixture():
    """`chain_raw_burst_netloader.json` is 13 events on a single
    `(seq=1, rule_id=...)` group → renders as ONE group block with one
    representative event. The whole user prompt must fit well under
    8 K chars (~3-5 K is the empirical typical band)."""
    chain = _load_burst()
    _, user = build_prompt(chain)

    assert len(user) < 8_000
    # Sanity: only one group block (group_count == 1, raw == 13).
    assert "# Events (1 groups from 13 raw events)" in user
    assert "event_count: 13" in user


def test_determinism_same_chain_produces_byte_identical_prompt():
    """Two calls on equivalent input yield byte-identical output."""
    out1 = build_prompt(_load_apt28())
    out2 = build_prompt(_load_apt28())
    assert out1 == out2

    burst1 = build_prompt(_load_burst())
    burst2 = build_prompt(_load_burst())
    assert burst1 == burst2


def test_prompt_builder_version_is_3_2():
    assert PROMPT_BUILDER_VERSION == "3.2"


def test_aggregation_method_constant_is_one_per_group_per_pipeline():
    assert AGGREGATION_METHOD == "one_per_group_per_pipeline"


def test_aggregation_summary_shape_has_no_collapsed_strict_key():
    """`collapsed_strict` is removed from the summary entries under v2 —
    every group is "collapsed" regardless of event identity, so the flag
    is no longer meaningful."""
    chain = _load_apt28()
    result = build_prompt_with_aggregation(chain)

    assert len(result.aggregation_summary) >= 1
    for entry in result.aggregation_summary:
        assert "collapsed_strict" not in entry
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
            assert "source_topic" not in entry


def test_aggregation_summary_event_ids_capped_at_50():
    """`event_ids` is capped at 50 — large bursts can produce thousands
    of IDs; full audit lives in chains-raw anyway."""
    chain_dict = _apt28_dict()
    rule_id = chain_dict["events"][0]["sigma_rule_id"]
    base = deepcopy(chain_dict["events"][0])
    chain_dict["events"] = []
    for i in range(75):
        ev = deepcopy(base)
        ev["event_id"] = f"evt-cap-{i:03d}"
        ev["sigma_rule_id"] = rule_id
        ev["timestamp"] = f"2026-04-22T09:32:{i % 60:02d}Z"
        chain_dict["events"].append(ev)
    chain = ChainRaw.model_validate(chain_dict)

    result = build_prompt_with_aggregation(chain)

    assert len(result.aggregation_summary) == 1
    entry = result.aggregation_summary[0]
    assert entry["event_count"] == 75
    assert len(entry["event_ids"]) == 50


def test_events_with_none_sigma_rule_id_render_as_distinct_singletons():
    """Rule-less events (`sigma_rule_id is None`) opt out of grouping —
    each becomes its own singleton group even when their content is
    otherwise identical (rule-less detections never aggregate)."""
    chain_dict = _apt28_dict()
    base = deepcopy(chain_dict["events"][0])
    chain_dict["events"] = []
    for i in range(3):
        ev = deepcopy(base)
        ev["event_id"] = f"evt-ruleless-{i}"
        ev["sigma_rule_id"] = None
        ev["sigma_rule_title"] = None
        ev["timestamp"] = f"2026-04-22T09:31:{30 + i}Z"
        chain_dict["events"].append(ev)
    chain = ChainRaw.model_validate(chain_dict)

    result = build_prompt_with_aggregation(chain)

    assert len(result.aggregation_summary) == 3
    for entry in result.aggregation_summary:
        assert entry["event_count"] == 1
        assert entry["sigma_rule_id"] is None


def test_aggregation_method_is_one_per_group_per_pipeline_via_analyse_chain_raw():
    """End-to-end: `llm_review.aggregation_method ==
    "one_per_group_per_pipeline"` and `prompt_builder_version == "3.2"`
    land on the analysed envelope. Anti-leak assert that retired label
    values (`strict`, `loose`, `loose_capped`, `loose_dropped`,
    `one_per_group`, `one_per_group_per_source`) never fire."""
    chain = _load_apt28()
    metrics = Metrics()
    client = MagicMock()
    client.analyse.return_value = LlmResult.success(
        text='{"verdict":"TRUE","confidence":0.5,"summary":"x","review":{"reasoning":"y"}}'
    )

    analysed = analyse_chain_raw(chain, llm_client=client, metrics=metrics, settings=_settings())

    assert analysed.llm_review["aggregation_method"] == "one_per_group_per_pipeline"
    assert analysed.llm_review["prompt_builder_version"] == "3.2"
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


def test_dropped_metrics_no_longer_fire():
    """`chain_events_per_group_capped_total` and
    `chain_groups_dropped_total` are gone — the cascade phases that
    bumped them are gone."""
    chain = _load_burst()
    metrics = Metrics()
    client = MagicMock()
    client.analyse.return_value = LlmResult.throttled("local_rate_limit")

    analyse_chain_raw(chain, llm_client=client, metrics=metrics, settings=_settings())

    assert metrics.get_counter("chain_events_per_group_capped_total") == 0
    assert metrics.get_counter("chain_groups_dropped_total") == 0


# ---------------------------------------------------------------------------
# Sequence / meta passthrough still works (regression — no changes here)
# ---------------------------------------------------------------------------


def test_seqs_hit_and_missed_split_in_meta():
    chain = _load_apt28()
    _, user = build_prompt(chain)

    assert "seqs hit: 1, 2, 3, 4, 5" in user
    assert "seqs missed: 6" in user


def test_at_block_renders_unchanged():
    """AT block rendering (industries, geographies, summary, threat actors)
    is unchanged from cascade era — sanity that the v2 rewrite did not
    regress the AT serialisation."""
    chain = _load_apt28()
    _, user = build_prompt(chain)

    assert "APT28" in user
    assert "CRITICAL" in user
    assert "Government, Defense, Energy" in user
    assert "Russian GRU-linked" in user
