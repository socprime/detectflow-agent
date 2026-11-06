"""Anchor tests for SIGMA_TO_HOS_INDEX maintenance.

These tests pin down the single most architecturally critical invariant in
correlation-job: the inverted index, derived from HoS broadcast state, is
the ONLY way `process_element` discovers HoS rules per event. If add /
update / tombstone semantics regress here, the correlation-job either
silently double-fires chains or drops events for live HoS rules.
"""

from __future__ import annotations

import pytest

from app.operators.sigma_index import IndexEntry, apply_hos_tombstone, apply_hos_upsert, lookup


def _hos(hos_id: str, seqs: list[tuple[int, list[str]]]) -> dict:
    return {
        "id": hos_id,
        "seqs": [{"seq": seq, "rule_ids": rule_ids} for seq, rule_ids in seqs],
    }


# ----- upsert (insert) ---------------------------------------------------


def test_upsert_creates_one_entry_per_seq_per_rule():
    idx: dict = {}
    apply_hos_upsert(idx, _hos("hos-1", [(1, ["r-a", "r-b"]), (2, ["r-c"])]))
    assert lookup(idx, "r-a") == [IndexEntry("hos-1", 1)]
    assert lookup(idx, "r-b") == [IndexEntry("hos-1", 1)]
    assert lookup(idx, "r-c") == [IndexEntry("hos-1", 2)]
    assert lookup(idx, "unknown") == []


def test_upsert_one_rule_in_multiple_seqs_creates_multiple_entries():
    """A sigma rule that legitimately appears in seq 1 AND seq 4 must be
    discoverable via both pointers — single events can hit multiple seqs of
    the same HoS."""
    idx: dict = {}
    apply_hos_upsert(idx, _hos("hos-1", [(1, ["shared"]), (4, ["shared"])]))
    assert set(lookup(idx, "shared")) == {IndexEntry("hos-1", 1), IndexEntry("hos-1", 4)}


def test_upsert_two_hos_rules_share_a_sigma_rule():
    """When HoS-A and HoS-B both reference the same sigma rule, the rule's
    entry list carries pointers to both — neither tombstone may collapse
    the other."""
    idx: dict = {}
    apply_hos_upsert(idx, _hos("hos-a", [(1, ["r-shared", "r-only-a"])]))
    apply_hos_upsert(idx, _hos("hos-b", [(2, ["r-shared", "r-only-b"])]))
    assert set(lookup(idx, "r-shared")) == {IndexEntry("hos-a", 1), IndexEntry("hos-b", 2)}
    assert lookup(idx, "r-only-a") == [IndexEntry("hos-a", 1)]
    assert lookup(idx, "r-only-b") == [IndexEntry("hos-b", 2)]


def test_upsert_is_idempotent():
    """Replaying the same HoS envelope must not duplicate entries — Kafka
    compaction means correlation-job will see the same record again on
    restart / rebalance."""
    idx: dict = {}
    hos = _hos("hos-1", [(1, ["r-a"]), (2, ["r-b"])])
    apply_hos_upsert(idx, hos)
    apply_hos_upsert(idx, hos)
    apply_hos_upsert(idx, hos)
    assert lookup(idx, "r-a") == [IndexEntry("hos-1", 1)]
    assert lookup(idx, "r-b") == [IndexEntry("hos-1", 2)]


def test_upsert_rejects_envelope_without_id():
    with pytest.raises(ValueError):
        apply_hos_upsert({}, {"seqs": [{"seq": 1, "rule_ids": ["r"]}]})


# ----- update (upsert with mutated body) ---------------------------------


def test_update_replaces_old_seqs_cleanly():
    """Editing a HoS in detectflow-backend: old rule_ids disappear, new ones
    appear. Stale pointers MUST not linger — they would cause the matcher
    to attribute hits to seqs that no longer exist."""
    idx: dict = {}
    apply_hos_upsert(idx, _hos("hos-1", [(1, ["old-rule"]), (2, ["common"])]))
    apply_hos_upsert(idx, _hos("hos-1", [(1, ["new-rule"]), (2, ["common"])]))

    assert lookup(idx, "old-rule") == []  # stale pointer dropped
    assert lookup(idx, "new-rule") == [IndexEntry("hos-1", 1)]
    assert lookup(idx, "common") == [IndexEntry("hos-1", 2)]


def test_update_preserves_other_hos_rules():
    """Updating HoS-A must not touch HoS-B's entries, even where they share
    a sigma rule."""
    idx: dict = {}
    apply_hos_upsert(idx, _hos("hos-a", [(1, ["r-shared"])]))
    apply_hos_upsert(idx, _hos("hos-b", [(2, ["r-shared"])]))
    apply_hos_upsert(idx, _hos("hos-a", [(3, ["r-shared"])]))  # change seq

    assert set(lookup(idx, "r-shared")) == {IndexEntry("hos-a", 3), IndexEntry("hos-b", 2)}


# ----- tombstone ---------------------------------------------------------


def test_tombstone_removes_entries_for_target_hos_only():
    idx: dict = {}
    apply_hos_upsert(idx, _hos("hos-a", [(1, ["r-shared", "r-only-a"])]))
    apply_hos_upsert(idx, _hos("hos-b", [(2, ["r-shared"])]))

    apply_hos_tombstone(idx, "hos-a")

    assert lookup(idx, "r-only-a") == []
    assert lookup(idx, "r-shared") == [IndexEntry("hos-b", 2)]


def test_tombstone_drops_rule_keys_with_empty_entry_lists():
    """Per-event lookups short-circuit on `rule_id in index`. After deleting
    the only HoS pointing at a rule, the rule must vanish from the index
    entirely — not be left as `rule_id -> []` (would be a slow miss)."""
    idx: dict = {}
    apply_hos_upsert(idx, _hos("hos-a", [(1, ["lonely"])]))
    apply_hos_tombstone(idx, "hos-a")
    assert "lonely" not in idx


def test_tombstone_for_unknown_hos_is_a_noop():
    idx: dict = {}
    apply_hos_upsert(idx, _hos("hos-a", [(1, ["r-a"])]))
    snapshot = {k: list(v) for k, v in idx.items()}
    apply_hos_tombstone(idx, "hos-never-existed")
    assert {k: list(v) for k, v in idx.items()} == snapshot


def test_tombstone_then_re_upsert_restores_entries():
    """The backend may delete + recreate — index must accept the second
    upsert without lingering ghost state."""
    idx: dict = {}
    apply_hos_upsert(idx, _hos("hos-a", [(1, ["r-a"])]))
    apply_hos_tombstone(idx, "hos-a")
    apply_hos_upsert(idx, _hos("hos-a", [(1, ["r-a"])]))
    assert lookup(idx, "r-a") == [IndexEntry("hos-a", 1)]


# ----- realistic shape ---------------------------------------------------


def test_apt28_fixture_indexes_all_seqs(hos_apt28):
    """Sanity: feeding the canonical APT28 HoS envelope produces an index
    where every fixture event's sigma_rule_id resolves to (apt28, expected
    seq). 6 seqs, 15 rule_ids in total."""
    idx: dict = {}
    apply_hos_upsert(idx, hos_apt28)

    total_rule_ids = sum(len(s["rule_ids"]) for s in hos_apt28["seqs"])
    assert sum(len(v) for v in idx.values()) == total_rule_ids

    expected_pairs = {
        ("5e000002-0000-4000-8000-000000000002", 1),
        ("5e000004-0000-4000-8000-000000000004", 2),
        ("5e000006-0000-4000-8000-000000000006", 3),
        ("5e000009-0000-4000-8000-000000000009", 4),
        ("5e00000d-0000-4000-8000-00000000000d", 5),
        ("5e000010-0000-4000-8000-000000000010", 6),
    }
    for rule_id, seq in expected_pairs:
        entries = lookup(idx, rule_id)
        assert IndexEntry(hos_apt28["id"], seq) in entries
