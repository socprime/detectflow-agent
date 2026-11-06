"""Inverted sigma_rule_id → [(hos_id, seq_num)] index.

This is the load-bearing piece of correlation-job: per-event match cost is
O(event.detectflow.matches), independent of total HoS rule count. Every code path
that reads HoS rules during `process_element` MUST go through this index —
iterating the full HoS broadcast state per event would re-introduce the
quadratic blow-up the architecture is designed to avoid.

The index is **derived** from `HOS_RULES_STATE` and lives in its own
broadcast state descriptor. Mutations happen exclusively in
`process_broadcast_element` on `hos-rules` topic envelopes (upserts and
tombstones); `process_element` is read-only.

Index shape: `dict[sigma_rule_id, list[IndexEntry]]`. Multiple entries per
sigma_rule_id are valid: one rule can belong to several HoS rules, or to
several seqs within the same HoS.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class IndexEntry:
    """A single inverted-index pointer: which HoS+seq does this rule belong to."""

    hos_id: str
    seq: int


def entries_by_rule(hos: dict) -> dict[str, list[IndexEntry]]:
    """Derive the index wiring of ONE HoS body: ``rule_id -> [IndexEntry]``.

    This is the per-rule view the broadcast handler needs for *incremental*
    state maintenance: a HoS upsert/tombstone only touches the index keys
    present in the old body and/or the new body — never the whole index.
    Iterating the full broadcast index per record is O(N) gRPC round trips in
    process mode and quadratic over a cold-start replay (see
    HosCorrelationFunction._apply_hos_message).
    """
    hos_id = hos.get("id")
    if not hos_id:
        raise ValueError(f"HoS envelope missing 'id': {hos!r}")
    out: dict[str, list[IndexEntry]] = {}
    for s in hos.get("seqs", []) or []:
        seq_num = int(s.get("seq"))
        for rule_id in s.get("rule_ids", []) or []:
            out.setdefault(rule_id, []).append(IndexEntry(hos_id=hos_id, seq=seq_num))
    return out


def apply_hos_upsert(index: dict[str, list[IndexEntry]], hos: dict) -> None:
    """Apply a HoS envelope upsert: replace all entries for `hos.id` with
    fresh ones derived from `hos.seqs[].rule_ids`.

    Idempotent — calling it twice with the same envelope leaves the index
    unchanged. Calling it with an updated envelope (different seqs/rule_ids)
    cleanly removes the old wiring and adds the new one in a single pass.
    """
    by_rule = entries_by_rule(hos)

    apply_hos_tombstone(index, hos["id"])

    for rule_id, entries in by_rule.items():
        index.setdefault(rule_id, []).extend(entries)


def apply_hos_tombstone(index: dict[str, list[IndexEntry]], hos_id: str) -> None:
    """Remove every index pointer that targets `hos_id`. Other HoS rules with
    overlapping sigma rule UUIDs are untouched. Sigma rules left with empty
    pointer lists are dropped from the index entirely so per-event lookups
    can short-circuit on `if rule_id in index`.
    """
    if not hos_id:
        return
    empty_keys: list[str] = []
    for rule_id, entries in index.items():
        kept = [e for e in entries if e.hos_id != hos_id]
        if not kept:
            empty_keys.append(rule_id)
        else:
            index[rule_id] = kept
    for k in empty_keys:
        index.pop(k, None)


def lookup(index: dict[str, list[IndexEntry]], rule_id: str) -> list[IndexEntry]:
    """Read-only accessor; returns [] if `rule_id` is unknown."""
    return index.get(rule_id, [])
