"""Correlation matcher — KeyedBroadcastProcessFunction.

KeyBy hostname → maintain per-(hos_id, window) ChainBuffers in keyed state.
Broadcast state holds HOS rules, Active Threats, Configure dialog, and the
DERIVED inverted sigma → HoS index. Per-event match cost is
O(event.detectflow.matches) — the matcher MUST never iterate HOS_RULES_STATE
on the hot path.

Wire contract for broadcast records:
- `_topic` marker is injected upstream (`TagWithTopic` map per source)
  before union+broadcast. Three values:
  - `<active_threats topic>`     → AT_STATE
  - `<hos_rules topic>`          → HOS_RULES_STATE + SIGMA_INDEX_STATE
  - `<chains_config topic>`      → CONFIG_STATE (singleton key="global")
- Logical-delete envelope (Phase 1 of the cross-repo two-phase delete
  pattern): `{"id": "...", "deleted": true}` on the broadcast topic.
  The matcher reads `id` and removes the entry from broadcast state and
  (for hos-rules) from the derived inverted index. The Phase 2 Kafka
  null-value tombstone — emitted by detectflow-backend right after the logical
  envelope — is for log compaction only and is dropped at the
  deserializer (see `app/connectors/broadcast_filter.py`). This mirrors
  the convention already in production for parser/filter envelopes in
  `detectflow-matchnode` (`sigma_broadcast.py`), where logical delete is a
  `deleted: true` flag on the envelope.

Main-stream record contract (already enforced upstream by detectflow-matchnode):
event JSON with `event_id`, `hostname`, `timestamp` (ISO-8601 Z), `pipeline_id`
(the detection pipeline that produced the tagged event), `parsed_event{}`, and a
`detectflow{}` block carrying `matches[]` (each with `sigma_rule_uuid`, `_rule_id`,
`rule_name`, `severity`, `mitre_techniques`). Isolation is the Kafka subscription
(`KAFKA_INPUT_TOPICS` = the member detection pipelines' tagged-events topics);
there is no in-event destination-topic filter.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from pyflink.common.typeinfo import Types
from pyflink.datastream import TimeDomain
from pyflink.datastream.functions import KeyedBroadcastProcessFunction
from pyflink.datastream.state import MapStateDescriptor, ValueStateDescriptor

from app.config.logging import get_logger
from app.config.settings import Settings
from app.core.chain_id import build_chain_id, format_window_start
from app.observability.activity import ENTITY_NAME_CORRELATION, get_activity_reporter
from app.observability.metrics import Metrics
from app.operators.chain_buffer import BufferEntry, ChainBuffer, bucket_window_start
from app.operators.chain_record import build_chain_record
from app.operators.hos_yaml import HosYamlError, hos_body_from_envelope
from app.operators.sigma_index import IndexEntry, entries_by_rule

logger = get_logger(__name__)


# ---------- broadcast state descriptors --------------------------------------

# Values are JSON-encoded strings — Flink's broadcast state needs serializable
# types and PyFlink's first-class JSON support is not yet plumbed through the
# Python state API in 2.2.
HOS_RULES_STATE = MapStateDescriptor("hos_rules", Types.STRING(), Types.STRING())
AT_STATE = MapStateDescriptor("active_threats", Types.STRING(), Types.STRING())
CONFIG_STATE = MapStateDescriptor("chains_config", Types.STRING(), Types.STRING())
SIGMA_INDEX_STATE = MapStateDescriptor("sigma_to_hos_index", Types.STRING(), Types.STRING())

ALL_BROADCAST_DESCRIPTORS = (
    HOS_RULES_STATE,
    AT_STATE,
    CONFIG_STATE,
    SIGMA_INDEX_STATE,
)

CONFIG_KEY = "global"
TOPIC_MARKER = "_topic"
TOMBSTONE_MARKER = "deleted"

# Human label for the job-health activity channel (detectflow.activity). Obtained
# per-worker via get_activity_reporter() so the reporter is rebuilt inside the
# Beam process worker rather than carried from the driver. Re-exported from
# app.observability.activity so the driver and every worker agree on one string
# (the reporter is first-call-wins on entity_name).
ACTIVITY_ENTITY_NAME = ENTITY_NAME_CORRELATION


# ---------- helpers ----------------------------------------------------------


def _parse_iso_to_epoch(ts_iso: str) -> int:
    """Parse an ISO-8601 timestamp to epoch seconds.

    A trailing ``Z`` is normalized to ``+00:00``. A timezone-less (naive)
    timestamp is interpreted as **UTC**, not the worker's local time — otherwise
    the window bucket and the deterministic ``chain_id`` would differ across
    hosts in different timezones. (The container also sets ``TZ=UTC`` as a
    backstop.)
    """
    dt = datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return int(dt.timestamp())


def _positive_int_or_none(raw: Any) -> int | None:
    """Coerce a chains-config window override to a positive int, else ``None``.

    A zero/negative/garbage value MUST NOT reach ``bucket_window_start`` — it
    raises ``ValueError``, which escapes ``process_element``, fails the job and
    crash-loops on Kafka redelivery of the same record. Garbage degrades to
    "no override" (inherit the HoS rule's timeframe), never to a crash.
    ``bool`` is rejected explicitly (it is an ``int`` subclass).
    """
    if raw is None or isinstance(raw, bool):
        return None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def _at_globally_blocked(at: dict) -> bool:
    """Is this Active Threat blocked platform-wide?

    The AT catalogue topic is shared vendor data. The control plane's flag is
    ``is_blocked`` (``is_blocked = NOT enabled``); older envelopes carry only
    ``enabled``. Read whichever is present so neither repo has to land first.
    This is the FIRST of the two monitoring gates — the per-pipeline
    ``excluded_active_threat_ids`` deny-list is the second.
    """
    if "is_blocked" in at:
        return bool(at["is_blocked"])
    return not at.get("enabled", True)


def _entries_to_json(entries: list[IndexEntry]) -> str:
    return json.dumps([[e.hos_id, e.seq] for e in entries], separators=(",", ":"))


def _entries_from_json(raw: str) -> list[IndexEntry]:
    return [IndexEntry(hos_id=h, seq=int(s)) for h, s in json.loads(raw)]


def _event_rule_uuids(event: dict) -> list[str]:
    """Sigma rule UUIDs that matched this event, from the matcher's
    ``detectflow.matches[]`` envelope.

    These are the inverted-index keys: HoS ``seqs[].rule_ids`` declare Sigma
    UUIDs verbatim, so correlation keys on ``match.sigma_rule_uuid`` (NOT
    ``_rule_id``, the control-plane ``rules.id``, which is distinct in production).
    """
    matches = (event.get("detectflow") or {}).get("matches") or []
    return [m["sigma_rule_uuid"] for m in matches if m.get("sigma_rule_uuid")]


def _serialize_buffer(buf: ChainBuffer) -> str:
    return json.dumps(
        {
            "window_start_epoch": buf.window_start_epoch,
            "window_end_epoch": buf.window_end_epoch,
            "last_activity_epoch": buf.last_activity_epoch,
            "emitted_revision": buf.emitted_revision,
            "dropped_events": buf.dropped_events,
            "last_emit_epoch": buf.last_emit_epoch,
            "pending_dirty": buf.pending_dirty,
            "seqs_hit": {
                str(seq): [{"rule_id": e.rule_id, "event": e.event} for e in entries]
                for seq, entries in buf.seqs_hit.items()
            },
        },
        separators=(",", ":"),
    )


def _deserialize_buffer(raw: str) -> ChainBuffer:
    # Debounce fields (`last_emit_epoch`, `pending_dirty`) are read with
    # defaults so buffers serialized by a pre-debounce build restore cleanly
    # from checkpointed state — same `.get(...)` convention as
    # `emitted_revision` / `dropped_events` before them.
    obj = json.loads(raw)
    seqs_hit = {
        int(seq): [BufferEntry(rule_id=e["rule_id"], event=e["event"]) for e in entries]
        for seq, entries in obj.get("seqs_hit", {}).items()
    }
    return ChainBuffer(
        window_start_epoch=int(obj["window_start_epoch"]),
        window_end_epoch=int(obj["window_end_epoch"]),
        last_activity_epoch=int(obj["last_activity_epoch"]),
        seqs_hit=seqs_hit,
        emitted_revision=int(obj.get("emitted_revision", 0)),
        dropped_events=int(obj.get("dropped_events", 0)),
        last_emit_epoch=int(obj.get("last_emit_epoch", 0)),
        pending_dirty=bool(obj.get("pending_dirty", False)),
    )


def _buffer_key(hos_id: str, window_start_epoch: int) -> str:
    return f"{hos_id}|{window_start_epoch}"


# NOTE: broadcast MapState is NOT iterated anywhere on the hot path. Besides the
# O(N²) replay cost in process mode, `broadcast_state.keys()/.items()/.values()`
# is unavailable in THREAD mode (Pemja): `get_broadcast_state(...)` hands back a
# raw `pemja.PyJObject` Java proxy with no `.keys()`, so any scan throws
# `AttributeError` and crash-loops the matcher. Only `.get()/.put()/.remove()`
# are safe in both modes. The per-task gauges therefore seed from 0 and track
# deltas — they measure load since this subtask started, not an absolute count
# (acceptable: gauges are observability, not correctness).


# ---------- the operator -----------------------------------------------------


class HosCorrelationFunction(KeyedBroadcastProcessFunction):
    """KeyBy hostname → match against HoS rules via inverted index → emit chains.

    Constructor takes a `Settings` snapshot so the operator stays self-contained
    when the pipeline is built (avoids reaching for `get_settings()` from inside
    Flink workers, which may not have the `.env` file mounted).
    """

    def __init__(
        self,
        settings: Settings,
        active_threats_topic: str,
        hos_rules_topic: str,
        chains_config_topic: str,
    ):
        self._chain_id_namespace = uuid.UUID(settings.chain_id_namespace)
        self._default_threshold_pct = int(settings.chain_coverage_threshold_pct)
        self._default_window_s = int(settings.chain_default_window_seconds)
        self._max_events_per_seq = int(settings.chain_max_events_per_seq)
        self._max_record_bytes = int(settings.chain_max_record_kb) * 1024
        self._at_topic = active_threats_topic
        self._hos_topic = hos_rules_topic
        self._config_topic = chains_config_topic
        self._heartbeat_interval_ms = max(1, int(settings.activity_heartbeat_seconds)) * 1000
        # Grace added to a buffer's window end before processing-time cleanup
        # reclaims it (see _cleanup_expired_buffers). >= source out-of-orderness.
        self._cleanup_grace_s = int(settings.chain_buffer_cleanup_grace_seconds)
        # Min processing-time seconds between post-threshold re-emits of the
        # same buffer (0 disables — every matching event re-emits, the
        # pre-debounce behavior). See _handle_hos_hit for the full semantics.
        self._reemit_debounce_s = int(settings.chain_reemit_debounce_seconds)
        # Boot-time identity: the CORRELATION_PIPELINE_ID env var. NEVER
        # job_id — JOB_ID is the K8s deployment name (`corr-<uuid>`), not a
        # UUID, and the control-plane consumer validates the chain envelope's
        # correlation_pipeline_id as a UUID and would discard the whole record.
        # None = legacy single-instance deployment. Copied off Settings here
        # because open() has no Settings in scope and this class deliberately
        # never stores the object. Never used to build topic names.
        self._settings_pipeline_id = settings.correlation_pipeline_id
        self._settings_pipeline_name = settings.correlation_pipeline_name
        # Resolved identity: the broadcast config wins, these are the fallback
        # for a config-less cold start. Re-derived in _read_config.
        self._pipeline_id: str | None = settings.correlation_pipeline_id
        self._pipeline_name: str | None = settings.correlation_pipeline_name
        # "none" (not "") keeps the identity metric's label cardinality at
        # exactly 1 for the legacy single-instance deployment.
        self._pipeline_id_label = settings.correlation_pipeline_id or "none"
        # --- derived hot-path views over the chains-config blob -------------
        # Owned exclusively by _read_config, which recomputes them whenever the
        # config cache reloads. _apply_config_message only invalidates the
        # cache; it never writes these (one refresh path, not two).
        self._window_override_s: int | None = None
        self._excluded_at_ids: frozenset[str] = frozenset()
        # Window-transition bookkeeping, owned exclusively by
        # _apply_config_message (see _note_window_transition).
        self._applied_window_override_s: int | None = None
        self._window_override_applied = False
        # Per-instance cache of the parsed chains-config blob. The config is
        # read on EVERY main-stream event; without the cache that is a
        # broadcast-state .get + json.loads per record. Invalidated in
        # _apply_config_message — safe because the same subtask applies all
        # broadcast updates, so the cache can never go stale silently. The
        # loaded flag (not `cache is None`) distinguishes "no config published"
        # from "not read since restore": both lazy-load on first use.
        self._config_cache: dict | None = None
        self._config_cache_loaded = False
        self._buffers_state = None
        self._key_max_ts_state = None
        self._metrics: Metrics | None = None
        self._activity = None
        self._subtask_index = 0
        # Per-task (per-subtask) wall-clock guard. The operator object is one
        # instance per parallel subtask (keyed state is what's scoped per key —
        # not this Python object), so a plain attribute collapses the keyed
        # processing-time timer fan-out to one heartbeat per task per interval.
        self._last_heartbeat_ms = 0
        # Lazily-seeded per-task gauge counters (None = not seeded yet). The
        # gauges used to be recomputed with a full broadcast-state key scan per
        # record — O(N) gRPC round trips in process mode and O(N²) over a
        # cold-start replay, which stalled the dev job (see
        # _apply_hos_message). Seed once per worker lifetime, then track
        # deltas from the per-record existence checks we already make.
        # Per-task gauge counters — seed 0, track deltas (NOT iterated from
        # broadcast state: thread-mode Pemja exposes broadcast state as a raw
        # Java proxy without .keys(); see the module-level note above).
        self._hos_loaded = 0
        self._at_loaded = 0
        self._index_size = 0

    # ---- lifecycle ----

    def open(self, runtime_context):
        # Per-key MapState: buffer_key -> serialized ChainBuffer.
        descriptor = MapStateDescriptor("chain_buffers", Types.STRING(), Types.STRING())
        self._buffers_state = runtime_context.get_map_state(descriptor)
        # Per-key fallback event-time clock — used by the late-drop guard when
        # Flink's operator watermark is unusable (see process_element).
        key_max_descriptor = ValueStateDescriptor("key_max_event_ts_ms", Types.LONG())
        self._key_max_ts_state = runtime_context.get_state(key_max_descriptor)
        self._metrics = Metrics(runtime_context)
        # The ONE identity metric (see app/observability/metrics.py's module
        # docstring for why a pipeline label is not added to every metric).
        # Registered in open(), not in the _apply_* broadcast handlers — those
        # run per broadcast message and would re-register it on every one.
        #
        # A COUNTER, not a gauge, and that is load-bearing: a PyFlink gauge
        # registers a *Python callable* that Flink's metrics thread invokes
        # through Pemja, and in thread mode that callback outlives its
        # interpreter when a job is cancelled — the TaskManager JVM then
        # SIGSEGVs in PyEval_AcquireThread.
        # A counter is push-only: the value lives in a JVM Counter and nothing
        # calls back into Python. Incremented once, so the series reads 1.
        self._metrics.inc(
            "correlation_pipeline_info",
            1,
            pipeline_id=self._pipeline_id_label,
        )
        # Build the activity reporter inside the worker (per-process lazy
        # singleton) — a driver-built reporter does not cross the Beam boundary.
        self._activity = get_activity_reporter(ACTIVITY_ENTITY_NAME)
        try:
            self._subtask_index = runtime_context.get_index_of_this_subtask()
        except Exception:  # noqa: BLE001 — stub contexts in unit tests lack this; default 0
            self._subtask_index = 0

    # ---- broadcast side ----

    def process_broadcast_element(self, value, ctx):
        msg = self._parse_json(value)
        if msg is None:
            return
        topic = msg.pop(TOPIC_MARKER, None)
        is_tombstone = bool(msg.get(TOMBSTONE_MARKER))
        entity_id = msg.get("id")

        if topic == self._hos_topic:
            self._apply_hos_message(ctx, msg, is_tombstone, entity_id)
        elif topic == self._at_topic:
            self._apply_at_message(ctx, msg, is_tombstone, entity_id)
        elif topic == self._config_topic:
            self._apply_config_message(ctx, msg, is_tombstone)
        else:
            logger.warning("broadcast message with unknown topic", topic=topic)

    def _apply_hos_message(self, ctx, msg, is_tombstone, hos_id):
        if not hos_id:
            logger.warning("hos message without id, dropping", keys=sorted(msg.keys()))
            return

        body: dict | None = None
        if not is_tombstone:
            # Wire envelope carries `yaml_text`; parse + merge metadata into
            # the matcher's in-state body shape (id, active_threat_id, seqs,
            # timeframe_seconds, condition, ...). Structural rejection at
            # this boundary keeps malformed rules out of HOS_RULES_STATE and
            # SIGMA_INDEX_STATE entirely (the parser also enforces timeframe > 0).
            try:
                body = hos_body_from_envelope(msg)
            except HosYamlError as exc:
                logger.warning(
                    "hos envelope rejected, dropping",
                    hos_id=hos_id,
                    reason=exc.reason,
                    detail=str(exc),
                )
                if self._metrics is not None:
                    self._metrics.inc("hos_rules_rejected_total", reason=exc.reason)
                # Soft-degradation alert on the job-health channel. Gated per
                # reason so a burst of identically-broken rules cannot flood
                # detectflow.activity; rule edits are low-frequency so the first of
                # each reason always surfaces.
                self._emit_activity_alert(
                    "hos_rule_rejected",
                    details=f"HoS rule rejected ({exc.reason}): {exc}",
                    changes={"hos_id": hos_id, "reason_code": exc.reason},
                    flood_key=f"correlation_hos_reject_{exc.reason}",
                )
                return

        hos_state = ctx.get_broadcast_state(HOS_RULES_STATE)
        index_state = ctx.get_broadcast_state(SIGMA_INDEX_STATE)

        # Incremental index maintenance — O(affected rule_ids), NOT O(index).
        # The old body (already in HOS_RULES_STATE) says exactly which index
        # keys this hos_id wired before; the new body says which it must wire
        # now. Only that union of keys is touched. The previous implementation
        # materialized the FULL index per record (one gRPC round trip per
        # entry in process mode) — O(N²) over a cold-start replay of the
        # compacted hos-rules topic (~1 record/min in practice): the
        # keyed stream stalled behind backpressure, sources could not ack, and
        # every checkpoint expired into a restart loop.
        old_raw = hos_state.get(hos_id)
        old_keys = entries_by_rule(json.loads(old_raw)).keys() if old_raw is not None else ()

        if is_tombstone:
            new_by_rule: dict[str, list[IndexEntry]] = {}
            hos_state.remove(hos_id)
        else:
            assert body is not None  # parser succeeded above
            new_by_rule = entries_by_rule(body)
            hos_state.put(hos_id, json.dumps(body, separators=(",", ":")))

        index_delta = 0
        for rule_id in {*old_keys, *new_by_rule}:
            raw = index_state.get(rule_id)
            kept = (
                [e for e in _entries_from_json(raw) if e.hos_id != hos_id]
                if raw is not None
                else []
            )
            kept.extend(new_by_rule.get(rule_id, ()))
            if kept:
                index_state.put(rule_id, _entries_to_json(kept))
                index_delta += raw is None
            elif raw is not None:
                index_state.remove(rule_id)
                index_delta -= 1

        if self._metrics is not None:
            self._hos_loaded += (not is_tombstone and old_raw is None) - (
                is_tombstone and old_raw is not None
            )
            self._index_size += index_delta
            self._metrics.set_gauge("hos_rules_loaded", self._hos_loaded)
            self._metrics.set_gauge("sigma_index_size", self._index_size)

    def _apply_at_message(self, ctx, msg, is_tombstone, at_id):
        if not at_id:
            logger.warning("at message without id, dropping", keys=sorted(msg.keys()))
            return
        at_state = ctx.get_broadcast_state(AT_STATE)
        # One O(1) existence probe for the gauge delta — never a full key scan
        # per record (that was O(N²) over the broadcast replay; see
        # _apply_hos_message).
        existed = at_state.get(at_id) is not None
        if is_tombstone:
            at_state.remove(at_id)
        else:
            at_state.put(at_id, json.dumps(msg, separators=(",", ":")))
        if self._metrics is not None:
            self._at_loaded += (not is_tombstone and not existed) - (is_tombstone and existed)
            self._metrics.set_gauge("active_threats_loaded", self._at_loaded)

    def _apply_config_message(self, ctx, msg, is_tombstone):
        cfg_state = ctx.get_broadcast_state(CONFIG_STATE)
        # Invalidate (don't eagerly re-parse): the next _read_config lazy-loads
        # from broadcast state AND re-derives the hot-path views, so the cache
        # and the state can never diverge.
        self._config_cache_loaded = False
        self._config_cache = None
        if is_tombstone:
            cfg_state.remove(CONFIG_KEY)
            self._note_window_transition(None)
        else:
            cfg_state.put(CONFIG_KEY, json.dumps(msg, separators=(",", ":")))
            self._note_window_transition(
                _positive_int_or_none(msg.get("correlation_window_seconds"))
            )
            if self._metrics is not None:
                threshold = int(msg.get("threshold_pct", self._default_threshold_pct))
                self._metrics.set_gauge("config_threshold_pct", threshold)

    def _note_window_transition(self, new_window_s: int | None) -> None:
        """Log + count a change of the effective chains-config window override.

        Changing the window at runtime re-buckets every subsequent event and
        therefore MINTS DIFFERENT ``chain_id``s (``window_start`` is
        ``floor(ts / timeframe_s) * timeframe_s`` and feeds the id) — the same
        attack, seen either side of the change, reaches the control plane as
        two chains. Inherent to a deterministic id, not a bug; loud enough here
        that an operator can correlate the split with their own config edit.

        The previous value is remembered on the operator instance rather than
        re-read from broadcast state: an extra ``cfg_state.get(CONFIG_KEY)``
        here would add a broadcast-state read per config message, which is the
        very thing the config cache exists to avoid (pinned by
        ``test_chains_config_is_parsed_once_per_update_not_per_event``). The
        first config message an instance sees (cold start or restore) has no
        known predecessor, so it records the value without claiming a change.
        """
        prev_known = self._window_override_applied
        prev = self._applied_window_override_s
        self._applied_window_override_s = new_window_s
        self._window_override_applied = True
        if self._metrics is not None:
            self._metrics.set_gauge("config_correlation_window_seconds", int(new_window_s or 0))
        if not prev_known or new_window_s == prev:
            return
        logger.warning(
            "chains-config correlation window changed — subsequent events re-bucket "
            "and mint new chain_ids; in-flight buffers drain on their own window_end",
            old_window_s=prev,
            new_window_s=new_window_s,
        )
        if self._metrics is not None:
            self._metrics.inc("chain_window_config_changes_total")

    # ---- main side ----

    def process_element(self, value, ctx):
        t0 = time.monotonic()
        event = self._parse_json(value)
        if event is None:
            return

        # Register a self-aligned processing-time maintenance timer. It drives
        # two things in on_timer: the per-task job-health heartbeat AND the
        # keyed-buffer GC (event-time timers are not used at all — the operator
        # watermark is pinned at Long.MIN, so they could never fire and their
        # registrations leaked as immortal checkpointed keyed state; removed).
        # Aligning to the interval
        # boundary collapses the many keyed timers onto the same wall-clock
        # tick; the per-task _last_heartbeat_ms guard then emits at most one
        # heartbeat per task per interval despite the keyed fan-out.
        self._register_maintenance_timer(ctx)

        hostname = event.get("hostname")
        if not hostname:
            self._metrics.inc("events_dropped_missing_hostname")
            self._emit_drop_alert("missing_hostname")
            return

        # `pipeline_id` is matcher-pre-parsed meta and the only per-flow
        # dimension left on the envelope: it lands on `events[].pipeline_id`
        # and is the agent prompt's `(seq, rule, pipeline_id)` grouping key.
        # Counter only — it is NOT a correlation input (isolation is the Kafka
        # subscription), so a missing value must never cost us a chain. But it
        # degrades silently and expensively: every group collapses into the
        # single `<unknown-pipeline>` bucket, one representative survives per
        # (seq, rule), and the LLM regresses to INSUFFICIENT_CONTEXT — the
        # exact failure per-flow splitting was introduced to fix. Watch
        # this counter, not the verdict distribution, to catch it.
        if not event.get("pipeline_id"):
            self._metrics.inc("events_missing_pipeline_id")

        config = self._read_config(ctx)
        threshold_pct = int((config or {}).get("threshold_pct", self._default_threshold_pct))

        # Inverted-index lookup. Per-event work is O(event.detectflow.matches).
        index_state = ctx.get_broadcast_state(SIGMA_INDEX_STATE)
        event_hits: dict[str, set[int]] = {}
        for rule_id in _event_rule_uuids(event):
            raw = index_state.get(rule_id)
            if raw is None:
                continue
            for entry in _entries_from_json(raw):
                event_hits.setdefault(entry.hos_id, set()).add(entry.seq)

        if not event_hits:
            # Counter only — matching no HoS rule is the NORMAL fate of the
            # overwhelming majority of tagged events, not a degradation. The
            # old gated alert here re-fired every cooldown forever and
            # desensitized detectflow.activity.
            self._metrics.inc("events_dropped_no_hits")
            return

        ts_iso = event.get("timestamp")
        if not ts_iso:
            return
        # Poison-pill guard: the upstream contract says ISO-8601 Z, but an
        # unparseable value here would otherwise raise out of process_element,
        # fail the job, and crash-loop on Kafka offset redelivery of the same
        # record. Garbage strings raise ValueError; a JSON number raises
        # AttributeError (no .replace). Drop with a counter + gated alert —
        # this IS a contract violation, unlike no_hits/topic_filtered above.
        try:
            ts_epoch = _parse_iso_to_epoch(ts_iso)
        except (ValueError, TypeError, AttributeError):
            self._metrics.inc("events_dropped_bad_timestamp")
            self._emit_drop_alert("bad_timestamp")
            return

        # Late-drop. Events whose event-time has fallen more than 60s behind
        # the per-key clock (the fallback's own out-of-orderness allowance,
        # hardcoded below) MUST be dropped so they cannot retroactively flip a
        # chain's coverage. Without this gate, a late seq-6 event arriving
        # after the chain's cleanup timer would resurrect the buffer or skew a
        # still-open one.
        #
        # KeyedBroadcastProcessFunction.current_watermark() returns
        # min(keyed_input, broadcast_inputs). ALL sources here use
        # `WatermarkStrategy.no_watermarks()` (the main source's event-time
        # lives in the JSON payload, the broadcast meta sources have no
        # event-time semantics at all), so the operator watermark stays pinned
        # at Long.MIN and the primary `watermark_ms > 0` check never fires —
        # it is kept only for forward-compat should a watermark ever appear.
        # The ACTIVE mechanism is the per-key max-event-ts clock with its own
        # 60s out-of-orderness allowance (hardcoded below) — keyed by hostname
        # via Flink state, correctly scoped without retaining values across keys.
        ts_ms = ts_epoch * 1000
        watermark_ms = ctx.timer_service().current_watermark()
        key_max = self._key_max_ts_state.value() or 0

        if watermark_ms > 0:
            if ts_ms < watermark_ms:
                self._metrics.inc("events_late_dropped")
                return
        else:
            if key_max > 0 and ts_ms < key_max - 60_000:
                self._metrics.inc("events_late_dropped")
                return

        if ts_ms > key_max:
            self._key_max_ts_state.update(ts_ms)

        hos_state = ctx.get_broadcast_state(HOS_RULES_STATE)
        at_state = ctx.get_broadcast_state(AT_STATE)

        # Per-event memo: decode each unique HoS body once and each unique
        # AT body once. Multiple HoS rules can be linked to the same AT
        # (N:1 relationship), so without the AT cache we'd
        # re-deserialize the same JSON for every hit on this event.
        hos_cache: dict[str, dict] = {}
        at_cache: dict[str, dict] = {}

        for hos_id, hit_seqs in event_hits.items():
            hos = hos_cache.get(hos_id)
            if hos is None:
                hos_raw = hos_state.get(hos_id)
                if hos_raw is None:
                    continue  # index entry without HoS body — racy update, skip
                hos = json.loads(hos_raw)
                hos_cache[hos_id] = hos

            at_id = hos.get("active_threat_id")
            if not at_id:
                # HoS references no AT — the rule can never produce a chain.
                # Surface it; otherwise this fails completely silently.
                self._metrics.inc("events_dropped_at_missing")
                self._emit_at_missing_alert("hos_without_active_threat_id")
                continue
            # Threat monitoring is opt-OUT. A threat is
            # monitored in this pipeline unless it is globally blocked (checked
            # in _handle_hos_hit, once the body is loaded) or explicitly
            # excluded here. Gated BEFORE the AT body is read from broadcast
            # state — an excluded threat costs no state lookup. Absent/empty
            # list ⇒ nothing excluded, so no branch can mean "correlate
            # nothing".
            if at_id in self._excluded_at_ids:
                # Counter only, no activity alert — an analyst-configured
                # steady state (opt-out monitoring), not a contract violation.
                self._metrics.inc("events_dropped_at_excluded")
                continue
            at = at_cache.get(at_id)
            if at is None:
                at_raw = at_state.get(at_id)
                if at_raw is None:
                    # The AT this HoS points at is absent from broadcast state
                    # (not yet replayed, or never published). The rule silently
                    # never matches — the single hardest field failure to
                    # diagnose — so emit a counter + gated alert. Subsequent
                    # events retry once the AT loads.
                    self._metrics.inc("events_dropped_at_missing")
                    self._emit_at_missing_alert("active_threat_absent")
                    continue
                at = json.loads(at_raw)
                at_cache[at_id] = at

            yield from self._handle_hos_hit(
                ctx=ctx,
                hostname=hostname,
                event=event,
                ts_epoch=ts_epoch,
                hos_id=hos_id,
                hit_seqs=hit_seqs,
                threshold_pct=threshold_pct,
                window_override_s=self._window_override_s,
                hos=hos,
                at=at,
            )

        self._metrics.record("event_processing_latency_ms", (time.monotonic() - t0) * 1000.0)

    def _handle_hos_hit(
        self,
        *,
        ctx,
        hostname: str,
        event: dict,
        ts_epoch: int,
        hos_id: str,
        hit_seqs: set[int],
        threshold_pct: int,
        window_override_s: int | None,
        hos: dict,
        at: dict,
    ):
        """Accumulate this hit into its window buffer and emit when covered.

        Two monitoring gates, in this order (opt-OUT):

        | globally blocked | ``at_id`` in ``excluded_active_threat_ids`` | Outcome |
        |---|---|---|
        | no | no (or list absent/empty) | **match** — the default for every threat |
        | no | yes | drop, ``events_dropped_at_excluded`` (caller's gate) |
        | yes | any | drop (counterless return) |

        ``window_override_s`` is the pipeline's explicit
        ``correlation_window_seconds``; ``None`` inherits the
        rule's ``detection.timeframe``. Changing it at runtime re-buckets
        subsequent events and MINTS NEW ``chain_id``s — the same attack, seen
        either side of the change, reaches the control plane as two chains.
        That is inherent to a deterministic id (``window_start`` is part of the
        seed) and is not a bug to work around; in-flight buffers are NOT
        discarded, they drain (see below).
        """
        if _at_globally_blocked(at):
            return

        # A non-null chains-config
        # `correlation_window_seconds` is an EXPLICIT OVERRIDE that wins over
        # the rule's `detection.timeframe`; null inherits the rule.
        # `self._default_window_s` stays unreachable — hos_yaml makes
        # `detection.timeframe` mandatory and > 0.
        rule_timeframe_s = int(hos.get("timeframe_seconds", self._default_window_s))
        timeframe_s = rule_timeframe_s if window_override_s is None else window_override_s
        if window_override_s is not None and window_override_s != rule_timeframe_s:
            self._metrics.inc("chain_window_overridden_total", hos_id=hos_id)
        # In-flight buffers created under the previous window DRAIN, they are
        # not discarded — and NO CODE IS NEEDED for that, so do not "fix" it
        # later. A buffer persists its own `window_end_epoch` at creation
        # (chain_buffer.py), so old-window buffers keep their original expiry
        # and are reclaimed by the processing-time GC, which flushes one final
        # revision for any still marked `pending_dirty`. Discarding was
        # rejected: it would leave the control plane holding a chain whose last
        # revision does not reflect the complete buffer (breaking the "last
        # revision is complete" promise), and the
        # broadcast side cannot reach keyed state anyway.
        window_start_epoch = bucket_window_start(ts_epoch, timeframe_s)
        key = _buffer_key(hos_id, window_start_epoch)

        buf_raw = self._buffers_state.get(key)
        buffer = (
            _deserialize_buffer(buf_raw)
            if buf_raw
            else ChainBuffer.empty(window_start_epoch, ts_epoch, timeframe_s)
        )

        # Material-change tracking for the re-emit debounce: a hit that only
        # bumps `dropped_events` on an already-capped seq leaves the emitted
        # events[] (and coverage) unchanged — re-emitting the chain for it
        # would be a pure revision bump with no analytical value.
        materially_changed = False
        for seq in hit_seqs:
            rule_id = self._pick_rule_id_for_seq(hos, event, seq)
            if rule_id is None:
                continue
            retained = buffer.add_event(
                seq, rule_id, event, ts_epoch, max_per_seq=self._max_events_per_seq
            )
            if retained:
                materially_changed = True
            else:
                self._metrics.inc("chain_events_capped_total")
            self._metrics.inc("seqs_hit_total", seq_num=seq)

        total_seqs = len(hos.get("seqs", []) or [])
        coverage = buffer.coverage_pct(total_seqs)

        if coverage >= threshold_pct:
            # Revision re-emit debounce. Pre-debounce, EVERY matching event
            # after the threshold re-emitted the full chain with a bumped
            # revision — a hot window turned N events into ~N near-identical
            # revisions, each an LLM call downstream. Semantics:
            # - the first threshold-crossing emit is never delayed;
            # - re-emits inside the debounce window are suppressed (the buffer
            #   is marked dirty; the window-cleanup timer flushes one final
            #   revision so detectflow-backend always ends on the complete buffer);
            # - re-emits that changed nothing material are suppressed outright;
            # - debounce=0 reproduces the old behavior exactly, INCLUDING
            #   re-emits for non-material changes (strict compat — the
            #   no-material-change suppression is gated behind debounce>0).
            now_s = self._processing_now_s(ctx)
            first_emit = buffer.emitted_revision == 0
            if first_emit or self._reemit_debounce_s <= 0:
                suppress = None
            elif not materially_changed:
                suppress = "no_material_change"
            elif now_s - buffer.last_emit_epoch < self._reemit_debounce_s:
                suppress = "debounce"
            else:
                suppress = None

            if suppress is None:
                payload = self._emit_revision(
                    hos_id=hos_id,
                    hos=hos,
                    at=at,
                    hostname=hostname,
                    buffer=buffer,
                    window_start_epoch=window_start_epoch,
                    now_s=now_s,
                )
                if payload is not None:
                    yield payload
            else:
                if suppress == "debounce":
                    buffer.pending_dirty = True
                self._metrics.inc("chain_reemits_suppressed_total", reason=suppress)

        # Always persist (we either emitted a revision or just accumulated hits).
        self._buffers_state.put(key, _serialize_buffer(buffer))

        # NB: no event-time cleanup timer here. The operator watermark is
        # pinned at Long.MIN (all sources are no_watermarks()), so event-time
        # timers could never fire — yet each registration was checkpointed
        # keyed state: one immortal timer per (hostname, window_end), i.e.
        # monotonic checkpoint growth. Buffer GC rides the processing-time
        # maintenance timer instead (see _cleanup_expired_buffers).

    def _emit_revision(
        self,
        *,
        hos_id: str,
        hos: dict,
        at: dict,
        hostname: str,
        buffer: ChainBuffer,
        window_start_epoch: int,
        now_s: int,
    ) -> str | None:
        """Bump the buffer's revision and render the chains-raw payload.

        Returns the serialized record, or ``None`` when the record cannot be
        made to fit ``chain_max_record_kb`` — the caller must NOT emit in that
        case (an oversized record fails the Kafka sink with
        RecordTooLargeException, and the restart re-emits the same oversized
        chain: a permanent crash loop).

        Mutates the buffer's debounce bookkeeping (``last_emit_epoch``,
        ``pending_dirty``) — the caller persists the buffer (or deletes it, on
        the final cleanup flush).

        ``self._pipeline_id`` / ``self._pipeline_name`` are never cold here:
        every path into this method loads the config first (``process_element``
        before matching, ``_flush_pending_revision`` on the timer path).
        """
        buffer.emitted_revision += 1
        buffer.last_emit_epoch = now_s
        buffer.pending_dirty = False
        window_iso = format_window_start(window_start_epoch)
        chain_id = build_chain_id(
            self._chain_id_namespace,
            hos_id,
            hostname,
            window_iso,
            correlation_pipeline_id=self._pipeline_id,
        )
        build_kwargs = {
            "hos": hos,
            "active_threat": at,
            "hostname": hostname,
            "buffer": buffer,
            "revision": buffer.emitted_revision,
            "chain_id": chain_id,
            "window_start_iso": window_iso,
            # The broadcast config wins (it also carries the human name); the
            # CORRELATION_PIPELINE_ID env var is the boot-time fallback for a
            # config-less cold start. There is NO job_id fallback: JOB_ID is
            # the K8s deployment name (`corr-<uuid>`), not a UUID, and the
            # control-plane consumer validates this field as a UUID — stamping
            # JOB_ID would make it discard the record. None is correct and
            # expected on the legacy single-instance deployment; the consumer
            # then falls back to the topic name.
            "correlation_pipeline_id": self._pipeline_id,
            "correlation_pipeline_name": self._pipeline_name,
        }
        record = build_chain_record(**build_kwargs)
        payload = json.dumps(record, separators=(",", ":"))
        # Record-size guard, tier 1: progressively halve the per-seq inlined
        # events (floor 1) until the payload fits; the shrink is emit-time
        # only, keyed state is untouched.
        shrink = self._max_events_per_seq
        while len(payload.encode("utf-8")) > self._max_record_bytes and shrink > 1:
            shrink = max(1, shrink // 2)
            record = build_chain_record(**build_kwargs, max_events_per_seq=shrink)
            payload = json.dumps(record, separators=(",", ":"))
            self._metrics.inc("chain_record_shrunk_total")
        # Tier 2: with many seqs × 1 large parsed_event each, the floor-of-1
        # shrink can still exceed the cap. Strip the parsed_event bodies (the
        # match metadata — rule ids, seqs, timestamps, techniques — survives;
        # `parsed_event: {}` is a valid envelope value) and re-serialize.
        if len(payload.encode("utf-8")) > self._max_record_bytes:
            for ev in record["events"]:
                ev["parsed_event"] = {}
            payload = json.dumps(record, separators=(",", ":"))
            self._metrics.inc("chain_record_stripped_total")
        # Tier 3: still too big (pathologically fat metadata) — never hand the
        # sink a record it will reject. Count + gated alert, drop the emit.
        if len(payload.encode("utf-8")) > self._max_record_bytes:
            self._metrics.inc("chains_dropped_oversized_total")
            self._emit_activity_alert(
                "chain_dropped_oversized",
                details=(
                    "Chain record exceeds chain_max_record_kb even after "
                    "per-seq shrink and parsed_event stripping — dropped "
                    "before the sink to avoid a RecordTooLargeException "
                    "restart loop"
                ),
                changes={"hos_id": hos_id, "chain_id": chain_id},
                flood_key="correlation_chain_oversized",
            )
            return None
        self._metrics.inc("chains_emitted_total", hos_id=hos_id)
        return payload

    @staticmethod
    def _processing_now_s(ctx) -> int:
        """Current processing time in epoch seconds, off the keyed timer service.

        Falls back to the wall clock if the timer service is unavailable
        (debounce bookkeeping must never break the data path)."""
        try:
            return int(ctx.timer_service().current_processing_time()) // 1000
        except Exception:  # noqa: BLE001
            return int(time.time())

    @staticmethod
    def _pick_rule_id_for_seq(hos: dict, event: dict, seq: int) -> str | None:
        """Of the event's matched UUIDs, return the first one belonging to `seq`."""
        seq_rules = next(
            (
                s.get("rule_ids", []) or []
                for s in hos.get("seqs", []) or []
                if int(s.get("seq")) == seq
            ),
            [],
        )
        for rule_id in _event_rule_uuids(event):
            if rule_id in seq_rules:
                return rule_id
        return None

    # ---- timer ----

    def on_timer(self, timestamp, ctx):
        """Processing-time maintenance: job-health heartbeat + keyed-buffer GC.

        Only **processing-time** timers are ever registered (per event in
        ``process_element``, plus the GC's self-perpetuating follow-up). They
        fan out across keys, so a per-task wall-clock guard collapses the
        heartbeat to ~one per subtask per ``activity_heartbeat_seconds``; the
        GC reclaims expired buffers and flushes a final revision for any that
        still carry debounce-suppressed changes (the flushed records are this
        callback's return value, which PyFlink yields downstream).

        Event-time timers were REMOVED: behind the Long.MIN-pinned operator
        watermark they could never fire, yet each registration persisted as
        immortal checkpointed keyed state (monotonic checkpoint growth). A
        stray event-time firing can only come from pre-fix restored state —
        ignore it.

        Returns an iterable on EVERY path. PyFlink 2.2 process mode
        ``yield from``s the timer callback's return value WITHOUT the ``or []``
        guard the element path has (``input_handler._on_processing_time``) —
        a bare ``return``/``None`` kills the Beam bundle with ``TypeError:
        'NoneType' object is not iterable`` and fails the job on the first
        firing timer.
        """
        if self._is_processing_time_timer(ctx):
            self._maybe_heartbeat(ctx)
            return self._cleanup_expired_buffers(ctx, timestamp // 1000)
        return []

    # ---- job-health activity (detectflow.activity side channel) ----

    def _register_maintenance_timer(self, ctx) -> None:
        """Register a processing-time timer aligned to the next interval boundary.

        Drives BOTH the per-task heartbeat (gated in :meth:`_maybe_heartbeat`)
        and the keyed-buffer GC (:meth:`_cleanup_expired_buffers`). Registered
        unconditionally — even when the activity reporter is disabled, the
        cleanup must still run, otherwise the (hos_id, hostname, window) keyed
        state would grow without bound (event-time timers are not used at all —
        dead behind the Long.MIN watermark). Aligning the firing time to
        ``activity_heartbeat_seconds`` boundaries coalesces the per-key timers
        onto the same wall-clock instant; Flink dedups same-(key, timestamp)
        registrations, so re-registering every event is cheap.
        """
        try:
            now_ms = ctx.timer_service().current_processing_time()
            interval = self._heartbeat_interval_ms
            next_fire = ((now_ms // interval) + 1) * interval
            ctx.timer_service().register_processing_time_timer(next_fire)
        except Exception as exc:  # noqa: BLE001 — maintenance never breaks the data path
            logger.warning("maintenance timer registration failed", error=str(exc))

    def _cleanup_expired_buffers(self, ctx, now_epoch_s: int) -> list[str]:
        """Garbage-collect keyed ChainBuffers whose window has closed.

        A buffer is reclaimed once wall-clock time has passed its
        ``window_end_epoch`` plus ``chain_buffer_cleanup_grace_seconds``. NB: this
        compares wall-clock time with event-time windows, so it assumes
        near-real-time ingestion: an event that arrives more than the grace
        period after its window closed (ingestion lag, backlog after a
        restart) finds its buffer gone and starts a fresh one at revision 1.
        Before deletion, a buffer still carrying debounce-
        suppressed changes (``pending_dirty``) gets ONE final revision flushed
        — the returned payloads are emitted by ``on_timer`` — so the last
        revision detectflow-backend consumes always reflects the complete buffer.
        Otherwise this is pure state hygiene that bounds the per-
        (hos_id, hostname, window) keyed state. ``self._buffers_state`` is
        keyed MapState (``.keys()`` is safe in both thread and process mode —
        unlike broadcast state). If non-expired buffers remain after this pass,
        a follow-up timer is registered at their earliest expiry so a hostname
        that goes silent still gets fully cleaned without new events. When NO
        live buffer remains, the per-key fallback clock
        (``_key_max_ts_state``) is cleared too — it was otherwise a
        per-hostname ValueState retained forever. A later event simply reseeds
        it.
        """
        if self._buffers_state is None:
            return []
        cutoff = now_epoch_s - self._cleanup_grace_s
        expired: list[tuple[str, ChainBuffer]] = []
        earliest_live_end: int | None = None
        live = 0
        for key in self._buffers_state.keys():
            buf = _deserialize_buffer(self._buffers_state.get(key))
            if buf.window_end_epoch <= cutoff:
                expired.append((key, buf))
            else:
                live += 1
                if earliest_live_end is None or buf.window_end_epoch < earliest_live_end:
                    earliest_live_end = buf.window_end_epoch
        flushed: list[str] = []
        for key, buf in expired:
            payload = self._flush_pending_revision(ctx, key, buf, now_epoch_s)
            if payload is not None:
                flushed.append(payload)
            self._buffers_state.remove(key)
        if live == 0 and self._key_max_ts_state is not None:
            self._key_max_ts_state.clear()
        # Self-perpetuate cleanup for a hostname that may receive no further
        # events: schedule a timer at the earliest remaining buffer's expiry.
        if earliest_live_end is not None:
            try:
                ctx.timer_service().register_processing_time_timer(
                    (earliest_live_end + self._cleanup_grace_s + 1) * 1000
                )
            except Exception as exc:  # noqa: BLE001 — cleanup never breaks the data path
                logger.warning("cleanup follow-up timer registration failed", error=str(exc))
        if self._metrics is not None:
            if expired:
                self._metrics.inc("buffers_expired", value=len(expired))
            # Approximate live-buffer gauge (per-subtask, last-key-wins) — a
            # growth signal so the state leak can be caught before OOM.
            self._metrics.set_gauge("chain_buffers_live", live)
        return flushed

    def _flush_pending_revision(self, ctx, key: str, buf: ChainBuffer, now_s: int) -> str | None:
        """Render the final revision for an expiring dirty buffer, if possible.

        ``pending_dirty`` is only ever set after the first threshold emit, so a
        clean (or never-emitted) buffer flushes nothing. The HoS body and its
        Active Threat are re-read from broadcast state (read-only access on the
        on-timer context); if either was deleted mid-window there is no valid
        envelope to build — skip silently, exactly like the per-event path
        would.

        BOTH monitoring gates apply here too: a threat
        excluded from this pipeline (or blocked platform-wide) after the buffer
        went dirty gets no final revision. Without that, an exclusion would
        still be followed by one last chain for the threat it just switched
        off. This matches the behaviour for an AT disabled
        mid-window — deliberately the same rule for both gates.
        """
        if not buf.pending_dirty or buf.emitted_revision <= 0:
            return None
        # Timer path: no element may have been processed since a restore, so
        # the derived config views (deny-list, pipeline identity) can still be
        # cold. get_broadcast_state is available read-only on this context.
        self._read_config(ctx)
        hos_id, _, _window = key.partition("|")
        hos_raw = ctx.get_broadcast_state(HOS_RULES_STATE).get(hos_id)
        if hos_raw is None:
            return None  # rule deleted mid-window — nothing to flush against
        hos = json.loads(hos_raw)
        at_id = hos.get("active_threat_id")
        if not at_id:
            return None  # HoS references no AT — nothing to build an envelope from
        if at_id in self._excluded_at_ids:
            return None  # excluded from this pipeline — same gate as the emit path
        at_raw = ctx.get_broadcast_state(AT_STATE).get(at_id)
        if at_raw is None:
            return None
        at = json.loads(at_raw)
        if _at_globally_blocked(at):
            return None  # blocked platform-wide mid-window — same gate as the emit path
        # The keyed timer fires under the buffer's own hostname key.
        hostname = ctx.get_current_key()
        return self._emit_revision(
            hos_id=hos_id,
            hos=hos,
            at=at,
            hostname=hostname,
            buffer=buf,
            window_start_epoch=buf.window_start_epoch,
            now_s=now_s,
        )

    def _maybe_heartbeat(self, ctx) -> None:
        """Emit a heartbeat at most once per task per heartbeat interval.

        The per-task ``_last_heartbeat_ms`` guard collapses the keyed
        processing-time timer fan-out (one fire per active hostname) down to a
        single emit per subtask per interval.
        """
        if self._activity is None or not self._activity.enabled:
            return
        try:
            now_ms = ctx.timer_service().current_processing_time()
        except Exception:  # noqa: BLE001 — fall back to a coarse monotonic clock
            now_ms = int(time.monotonic() * 1000)
        if now_ms - self._last_heartbeat_ms < self._heartbeat_interval_ms:
            return
        self._last_heartbeat_ms = now_ms
        self._activity.heartbeat(changes={"subtask_index": self._subtask_index})

    def _emit_drop_alert(self, reason: str) -> None:
        """Emit a gated soft-degradation alert for a high-volume record drop.

        Reserved for genuine upstream-contract violations (missing_hostname,
        bad_timestamp) — NOT for normal-operation drops like no_hits, which
        are counter-only (a perpetual gated alert for the steady state
        desensitizes detectflow.activity).

        Always gated by ``flood_key=correlation_drop_<reason>`` — this fires on
        the hot path (once per dropped record), so the reporter's anti-flood
        gate suppresses repeats within ``activity_flood_cooldown_seconds``.
        Never emit one event per dropped record.
        """
        if self._activity is None:
            return
        self._activity.emit_alert(
            "records_dropped",
            details=f"High-volume record drops: {reason}",
            changes={"drop_reason": reason, "subtask_index": self._subtask_index},
            flood_key=f"correlation_drop_{reason}",
        )

    def _emit_at_missing_alert(self, reason: str) -> None:
        """Gated alert: a HoS hit could not resolve its Active Threat.

        Either the HoS carries no ``active_threat_id`` or the referenced AT is
        absent from broadcast state — in both cases the rule silently never
        emits a chain, which is the hardest field failure to diagnose. Gated
        per reason (``flood_key``) so a steady stream of unresolved hits cannot
        flood detectflow.activity.
        """
        if self._activity is None:
            return
        self._activity.emit_alert(
            "hos_active_threat_unresolved",
            details=f"HoS hit dropped — Active Threat unresolved ({reason})",
            changes={"reason_code": reason, "subtask_index": self._subtask_index},
            flood_key=f"correlation_at_missing_{reason}",
        )

    def _emit_activity_alert(
        self,
        reason: str,
        *,
        details: str,
        changes: dict,
        flood_key: str | None,
    ) -> None:
        """Forward a soft-degradation alert to the activity reporter (no-op if disabled)."""
        if self._activity is None:
            return
        self._activity.emit_alert(reason, details=details, changes=changes, flood_key=flood_key)

    @staticmethod
    def _is_processing_time_timer(ctx) -> bool:
        """``True`` when the firing timer is a processing-time timer (heartbeat).

        Defensive against stub on-timer contexts in unit tests that do not
        implement ``time_domain()`` — those exercise the event-time cleanup
        path, so default to event-time.
        """
        time_domain = getattr(ctx, "time_domain", None)
        if time_domain is None:
            return False
        try:
            return time_domain() == TimeDomain.PROCESSING_TIME
        except Exception:  # noqa: BLE001
            return False

    # ---- internals ----

    @staticmethod
    def _parse_json(value: Any) -> dict | None:
        if value is None:
            return None
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            value = value.strip()
            if not value:
                return None
            try:
                return json.loads(value)
            except json.JSONDecodeError as exc:
                logger.warning("invalid json on stream", error=str(exc))
                return None
        if isinstance(value, dict):
            return value
        return None

    def _read_config(self, ctx) -> dict | None:
        """Parsed chains-config blob + derived views, cached on the operator.

        The config gates EVERY main-stream event; re-doing the broadcast-state
        ``.get`` + ``json.loads`` per record is pure hot-path waste. The cache
        is invalidated in ``_apply_config_message`` (the same subtask applies
        all broadcast updates, so it cannot go stale) and lazily re-loaded from
        broadcast state on the first read — including the first read after a
        restore, when the instance attribute starts cold but the state does not.

        The derived views (window override, AT deny-list, resolved pipeline
        identity) are computed HERE, once per config change, never per record —
        broadcast state must not be scanned or re-parsed on the hot path, and
        in thread mode it cannot be iterated at all (see the module-level note).
        """
        if not self._config_cache_loaded:
            cfg_state = ctx.get_broadcast_state(CONFIG_STATE)
            raw = cfg_state.get(CONFIG_KEY)
            self._config_cache = json.loads(raw) if raw else None
            cfg = self._config_cache or {}
            # A non-null window is an EXPLICIT OVERRIDE that
            # wins over the HoS rule's `detection.timeframe`; null inherits it.
            override_raw = cfg.get("correlation_window_seconds")
            self._window_override_s = _positive_int_or_none(override_raw)
            if (
                override_raw is not None
                and self._window_override_s is None
                and self._metrics is not None
            ):
                self._metrics.inc("config_window_override_invalid_total")
            # Deny-list: absent/null/[] all mean "nothing
            # excluded". No None sentinel — the empty-means-nothing trap cannot
            # exist here by construction.
            excluded = cfg.get("excluded_active_threat_ids")
            self._excluded_at_ids = frozenset(str(i) for i in excluded) if excluded else frozenset()
            envelope_pid = cfg.get("correlation_pipeline_id")
            if (
                envelope_pid
                and self._settings_pipeline_id
                and envelope_pid != self._settings_pipeline_id
                and self._metrics is not None
            ):
                # Misconfiguration: the envelope this instance consumes belongs
                # to a different pipeline. Both chain_id and the envelope stamp
                # follow the config, so surface it rather than silently
                # re-keying every chain this instance emits.
                self._metrics.inc("config_pipeline_id_mismatch_total")
            self._pipeline_id = envelope_pid or self._settings_pipeline_id
            self._pipeline_name = (
                cfg.get("correlation_pipeline_name") or self._settings_pipeline_name
            )
            self._config_cache_loaded = True
        return self._config_cache
