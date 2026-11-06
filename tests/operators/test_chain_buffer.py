"""ChainBuffer accumulation, coverage, and tumbling-window arithmetic."""

import pytest

from app.operators.chain_buffer import ChainBuffer, bucket_window_start

# Fixture-aligned epoch — 2026-04-22T09:30:00Z
WINDOW_START = 1776850200
TS_09_31_11 = 1776850271
TS_09_31_31 = 1776850291


def make_event(eid: str, ts: int) -> dict:
    return {"event_id": eid, "timestamp": ts}


def test_empty_factory():
    buf = ChainBuffer.empty(window_start_epoch=WINDOW_START, ts_epoch=TS_09_31_11, timeframe_s=1800)
    assert buf.window_start_epoch == WINDOW_START
    assert buf.window_end_epoch == WINDOW_START + 1800
    assert buf.last_activity_epoch == TS_09_31_11
    assert buf.seqs_hit == {}
    assert buf.emitted_revision == 0


def test_add_event_records_seq_and_advances_last_activity():
    buf = ChainBuffer.empty(WINDOW_START, TS_09_31_11, timeframe_s=1800)
    buf.add_event(1, "rule-a", make_event("e1", TS_09_31_11), TS_09_31_11)
    buf.add_event(2, "rule-b", make_event("e2", TS_09_31_31), TS_09_31_31)
    assert set(buf.seqs_hit) == {1, 2}
    assert buf.last_activity_epoch == TS_09_31_31


def test_last_activity_is_monotonic():
    buf = ChainBuffer.empty(WINDOW_START, TS_09_31_31, timeframe_s=1800)
    buf.add_event(1, "rule-a", make_event("late", TS_09_31_31), TS_09_31_31)
    buf.add_event(2, "rule-b", make_event("earlier", TS_09_31_11), TS_09_31_11)
    assert buf.last_activity_epoch == TS_09_31_31


def test_duplicate_seq_does_not_increase_coverage():
    """Coverage = distinct seqs / total. Duplicate hits in the same seq must
    NOT inflate it (distinct seqs hit only)."""
    buf = ChainBuffer.empty(WINDOW_START, TS_09_31_11, timeframe_s=1800)
    buf.add_event(1, "rule-a", make_event("a", TS_09_31_11), TS_09_31_11)
    buf.add_event(1, "rule-a", make_event("b", TS_09_31_11), TS_09_31_11)
    buf.add_event(1, "rule-a", make_event("c", TS_09_31_11), TS_09_31_11)
    assert len(buf.seqs_hit[1]) == 3  # raw events preserved
    assert buf.coverage_pct(total_seqs=6) == pytest.approx(16.67)


def test_coverage_matches_fixture_5_of_6():
    """5/6 hits (the canonical APT28 fixture scenario) → 83.33."""
    buf = ChainBuffer.empty(WINDOW_START, TS_09_31_11, timeframe_s=1800)
    for seq in (1, 2, 3, 4, 5):
        buf.add_event(seq, f"rule-{seq}", make_event(f"e{seq}", TS_09_31_11), TS_09_31_11)
    assert buf.coverage_pct(total_seqs=6) == 83.33


def test_coverage_handles_zero_total_seqs():
    buf = ChainBuffer.empty(WINDOW_START, TS_09_31_11, timeframe_s=1800)
    assert buf.coverage_pct(total_seqs=0) == 0.0


def test_coverage_clamped_to_100_when_seq_count_shrinks_mid_window():
    """If a live HoS edit shrinks the rule's seq count below the distinct seqs
    already hit, coverage is clamped to 100% rather than reported as >100%."""
    buf = ChainBuffer.empty(WINDOW_START, TS_09_31_11, timeframe_s=1800)
    for seq in (1, 2, 3, 4, 5):
        buf.add_event(seq, f"rule-{seq}", make_event(f"e{seq}", TS_09_31_11), TS_09_31_11)
    # Rule now declares only 4 seqs while 5 distinct seqs are already hit.
    assert buf.coverage_pct(total_seqs=4) == 100.0


def test_window_end_epoch_is_persisted_field():
    """`window_end_epoch` must be stored on the buffer so on_timer can identify
    expired buffers without re-reading the HoS rule (review #1: prevents a
    fast-window timer from wiping co-tenant slow-window buffers)."""
    buf = ChainBuffer.empty(WINDOW_START, TS_09_31_11, timeframe_s=1800)
    assert buf.window_end_epoch == WINDOW_START + 1800
    buf2 = ChainBuffer.empty(WINDOW_START, TS_09_31_11, timeframe_s=300)
    assert buf2.window_end_epoch == WINDOW_START + 300


def test_empty_rejects_non_positive_timeframe():
    with pytest.raises(ValueError):
        ChainBuffer.empty(WINDOW_START, TS_09_31_11, timeframe_s=0)
    with pytest.raises(ValueError):
        ChainBuffer.empty(WINDOW_START, TS_09_31_11, timeframe_s=-1)


# ------------------------------------------------------------
# Tumbling-window bucketing
# ------------------------------------------------------------


def test_bucket_window_start_aligns_to_fixture():
    """09:31:11 with 1800s timeframe must bucket to 09:30:00."""
    assert bucket_window_start(TS_09_31_11, 1800) == WINDOW_START


def test_bucket_window_start_is_idempotent_within_window():
    """All 5 fixture events span 09:31:11 → 09:31:31 inside 30-min window
    starting at 09:30:00 — every event must bucket to the same start."""
    for ts in (TS_09_31_11, 1776850276, 1776850281, 1776850286, TS_09_31_31):
        assert bucket_window_start(ts, 1800) == WINDOW_START


def test_bucket_window_start_boundary_events_split_into_distinct_windows():
    """ts=09:59:59 and ts=10:00:00 (1 second apart, across the window edge)
    MUST land in different buckets. This is the documented semantics —
    deterministic chain_id requires aligned tumbling windows. If a future
    engineer flips this to sliding, this test fails loudly."""
    edge = WINDOW_START + 1800  # 10:00:00
    just_before = edge - 1  # 09:59:59
    assert bucket_window_start(just_before, 1800) == WINDOW_START
    assert bucket_window_start(edge, 1800) == edge
    assert bucket_window_start(just_before, 1800) != bucket_window_start(edge, 1800)


def test_bucket_window_start_rejects_non_positive_timeframe():
    with pytest.raises(ValueError):
        bucket_window_start(TS_09_31_11, 0)
    with pytest.raises(ValueError):
        bucket_window_start(TS_09_31_11, -60)


# ---------------------------------------------------------------------------
# Per-seq cap (unbounded buffers → >1MiB records
# → RecordTooLargeException → sink-failure restart loop)
# ---------------------------------------------------------------------------


def test_add_event_cap_retains_first_n_and_counts_dropped():
    buf = ChainBuffer.empty(1000, 1000, 300)
    for i in range(5):
        retained = buf.add_event(1, "r", {"event_id": f"e{i}"}, 1000 + i, max_per_seq=3)
        assert retained == (i < 3)
    assert [e.event["event_id"] for e in buf.seqs_hit[1]] == ["e0", "e1", "e2"]
    assert buf.dropped_events == 2
    # Cap never affects coverage — the seq stays hit.
    assert buf.coverage_pct(1) == 100.0
    # last_activity still advances on dropped events.
    assert buf.last_activity_epoch == 1004


def test_add_event_cap_is_per_seq_not_global():
    buf = ChainBuffer.empty(1000, 1000, 300)
    for seq in (1, 2):
        for i in range(3):
            buf.add_event(seq, "r", {"event_id": f"s{seq}e{i}"}, 1000, max_per_seq=2)
    assert len(buf.seqs_hit[1]) == 2
    assert len(buf.seqs_hit[2]) == 2
    assert buf.dropped_events == 2


def test_add_event_without_cap_is_unbounded():
    buf = ChainBuffer.empty(1000, 1000, 300)
    for i in range(100):
        assert buf.add_event(1, "r", {"event_id": f"e{i}"}, 1000) is True
    assert len(buf.seqs_hit[1]) == 100
    assert buf.dropped_events == 0


# ---------------------------------------------------------------------------
# Window override — bucketing consequences
# ---------------------------------------------------------------------------


def test_bucket_window_start_changes_when_timeframe_changes():
    """A pipeline window override re-buckets events, so the same timestamp
    lands in a different window_start — which feeds `chain_id`. Changing the
    window at runtime therefore MINTS NEW chain_ids for subsequent events; the
    same attack seen either side of the change reaches the control plane as two
    chains. Inherent to a deterministic id, documented, not a bug."""
    ts = WINDOW_START + 1234
    assert bucket_window_start(ts, 1800) != bucket_window_start(ts, 900)
    assert bucket_window_start(ts, 900) % 900 == 0


def test_buffer_window_end_uses_creating_timeframe_not_current_config():
    """`window_end_epoch` is PERSISTED at creation, not derived from whatever
    the config says later. That is what makes in-flight buffers DRAIN on their
    original expiry when the window changes mid-window, instead of being
    stranded (or reclaimed early) by the new timeframe."""
    buf = ChainBuffer.empty(WINDOW_START, TS_09_31_11, timeframe_s=1800)
    assert buf.window_end_epoch == WINDOW_START + 1800
    # A later, shorter config window cannot retro-shrink an existing buffer:
    # nothing recomputes window_end from the current timeframe.
    fresh = ChainBuffer.empty(WINDOW_START, TS_09_31_11, timeframe_s=900)
    assert fresh.window_end_epoch == WINDOW_START + 900
    assert buf.window_end_epoch == WINDOW_START + 1800
