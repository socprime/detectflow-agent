"""Per-(hos_id, hostname, window) state held in keyed Flink state.

Tumbling-window bucketing: every event's `window_start_epoch` is
`floor(ts_epoch / timeframe_s) * timeframe_s`. Boundary events 1 second apart
across a window edge land in different chains — that is by design (chain_id
requires deterministic windows; sliding windows would break that
contract). Forward-compat: change `bucket_window_start` if the product ever
needs sliding semantics.
"""

from __future__ import annotations

from dataclasses import dataclass, field


def bucket_window_start(ts_epoch: int, timeframe_s: int) -> int:
    """Floor an event timestamp to its tumbling-window start (epoch seconds)."""
    if timeframe_s <= 0:
        raise ValueError(f"timeframe_s must be > 0, got {timeframe_s}")
    return (ts_epoch // timeframe_s) * timeframe_s


@dataclass
class BufferEntry:
    """A single accumulated hit: which sigma rule matched + the raw event.

    `rule_id` is a Sigma rule UUID, resolved by the inverted-index lookup;
    carrying it alongside the raw event saves `build_chain_record` from
    re-deriving it from `event.detectflow.matches[].sigma_rule_uuid ∩
    hos.seq.rule_ids`.
    """

    rule_id: str
    event: dict


@dataclass
class ChainBuffer:
    """Aggregated hits for a single `(hos_id, hostname, window)` triple.

    `seqs_hit` is `seq_num -> list[BufferEntry]`; only distinct seq counts
    matter for coverage, but per-rule entries are kept so `build_chain_record`
    can materialize the chain envelope at emit time.

    `window_end_epoch` is persisted (not derived) so `on_timer` can identify
    expired buffers without re-reading the HoS rule. This matters when a
    hostname has multiple HoS rules with different `timeframe_seconds` —
    a fast-window timer must not wipe co-tenant slow-window buffers.
    """

    window_start_epoch: int
    window_end_epoch: int
    last_activity_epoch: int
    seqs_hit: dict[int, list[BufferEntry]] = field(default_factory=dict)
    emitted_revision: int = 0
    # Events that matched but were NOT retained because the per-seq cap was
    # reached (see `Settings.chain_max_events_per_seq`). Surfaced as
    # `events_dropped` on the chain envelope so consumers can tell a capped
    # chain from a complete one.
    dropped_events: int = 0
    # --- re-emit debounce bookkeeping (`Settings.chain_reemit_debounce_seconds`) ---
    # Processing-time epoch (seconds) of the last emitted revision. 0 = never
    # emitted — also the backward-compat default when an old serialized buffer
    # (pre-debounce) is restored from checkpointed state, which makes the first
    # post-restore re-emit always pass the debounce gate (safe: at worst one
    # extra revision).
    last_emit_epoch: int = 0
    # True when post-threshold changes were suppressed by the debounce window
    # and still await a flush. The window-cleanup timer emits one final
    # revision for a dirty buffer before deleting it, so the last revision
    # consumed by detectflow-backend always reflects the complete buffer.
    pending_dirty: bool = False

    @classmethod
    def empty(cls, window_start_epoch: int, ts_epoch: int, timeframe_s: int) -> ChainBuffer:
        """Create a fresh buffer for a new ``(hos_id, hostname, window)`` triple."""
        if timeframe_s <= 0:
            raise ValueError(f"timeframe_s must be > 0, got {timeframe_s}")
        return cls(
            window_start_epoch=window_start_epoch,
            window_end_epoch=window_start_epoch + timeframe_s,
            last_activity_epoch=ts_epoch,
            seqs_hit={},
            emitted_revision=0,
        )

    def add_event(
        self,
        seq: int,
        rule_id: str,
        event: dict,
        ts_epoch: int,
        max_per_seq: int | None = None,
    ) -> bool:
        """Append a matched event to ``seqs_hit[seq]`` and advance ``last_activity_epoch``.

        When ``max_per_seq`` is set and ``seqs_hit[seq]`` is already full, the
        event is counted in ``dropped_events`` instead of retained — the seq
        stays hit (coverage unchanged) but keyed state and the emitted record
        stay bounded. Returns ``True`` if the event was retained.
        """
        entries = self.seqs_hit.setdefault(seq, [])
        retained = max_per_seq is None or len(entries) < max_per_seq
        if retained:
            entries.append(BufferEntry(rule_id=rule_id, event=event))
        else:
            self.dropped_events += 1
        if ts_epoch > self.last_activity_epoch:
            self.last_activity_epoch = ts_epoch
        return retained

    def coverage_pct(self, total_seqs: int) -> float:
        """Distinct seqs hit / total_seqs * 100, rounded to 2 dp, clamped to 100.

        Compared against `chains-config.threshold_pct` (int) — float >= int is
        well-defined; no normalization needed on either side. The clamp guards
        the edge where a HoS rule's seq count shrinks mid-window (a live rule
        edit): `seqs_hit` may then hold more distinct seqs than the rule now
        declares, which would otherwise report >100% coverage.
        """
        if total_seqs <= 0:
            return 0.0
        return min(round(len(self.seqs_hit) / total_seqs * 100, 2), 100.0)
