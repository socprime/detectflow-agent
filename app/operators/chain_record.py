"""Chain record envelope materialization (Active Threat inlined).

`build_chain_record(...)` consumes an HoS rule envelope, an Active Threat
envelope, and a `ChainBuffer`, and produces the JSON dict that
correlation-job emits to `detectflow.chains-raw`. The full Active Threat
object is **inlined** into every chain — agent-job has NO AT broadcast and
must read AT directly off the chain payload.
"""

from __future__ import annotations

from app.operators.chain_buffer import ChainBuffer

# Fields to inline from the Active Threat envelope. Mirrors the chain
# envelope contract in the
# tests/fixtures/attack-chains/chain_raw_apt28_v1.json shape. Fields like
# `id`, `enabled`, `release_date`, `monitored_topics`, `source`, `updated_at`
# are intentionally excluded — they are operational/relational, not part of
# the human-facing snapshot the LLM and analyst see.
_AT_INLINE_FIELDS: tuple[str, ...] = (
    "name",
    "threat_type",
    "severity",
    "industries",
    "geographies",
    "summary",
    "investigation",
    "mitigation",
    "response",
    "threat_actors",
)


def _inline_active_threat(at: dict) -> dict:
    """Project the AT envelope down to the ``_AT_INLINE_FIELDS`` whitelist."""
    return {field: at.get(field) for field in _AT_INLINE_FIELDS}


def _find_match(tagged_event: dict, rule_uuid: str) -> dict:
    """Return the ``detectflow.matches[]`` entry for `rule_uuid`, or {} if absent.

    `rule_uuid` is a Sigma rule UUID (the inverted-index key), so matching is
    keyed on ``match.sigma_rule_uuid`` — NOT ``_rule_id`` (the control-plane
    ``rules.id``, which differs from the UUID in production). The match carries
    the rule's display metadata (`rule_name`, `mitre_techniques`).
    """
    matches = (tagged_event.get("detectflow") or {}).get("matches") or []
    for match in matches:
        if match.get("sigma_rule_uuid") == rule_uuid:
            return match
    return {}


def build_chain_record(
    *,
    hos: dict,
    active_threat: dict,
    hostname: str,
    buffer: ChainBuffer,
    revision: int,
    chain_id: str,
    window_start_iso: str,
    correlation_pipeline_id: str | None = None,
    correlation_pipeline_name: str | None = None,
    max_events_per_seq: int | None = None,
) -> dict:
    """Assemble the chains-raw envelope (Active Threat inlined).

    `revision` is supplied by the caller — `correlation-job` increments it
    each time the same `(hos_id, hostname, window)` re-emits.

    ``max_events_per_seq`` is the emit-time shrink knob: when set, only the
    chronologically-first N entries per seq are inlined (the rest are counted
    in ``events_dropped``). Used by the operator's record-size guard to keep
    the serialized chain under Kafka's max message size — the buffer-level cap
    (`Settings.chain_max_events_per_seq`) already bounds the common case.
    """
    total_seqs = len(hos.get("seqs", []) or [])

    # seqs[]: { seq, hit, rule_ids } for every seq in the rule, in the rule's
    # order. `rule_ids` carries the sigma UUIDs declared for that seq in the
    # HoS YAML verbatim — detectflow-backend resolves them to titles + techniques on
    # the read side. Same shape for hit and miss entries (the frontend's
    # kill-chain ribbon needs `rule_ids` to render a greyed-out missed seq).
    hit_seqs = set(buffer.seqs_hit.keys())
    seqs = [
        {
            "seq": int(s.get("seq")),
            "hit": int(s.get("seq")) in hit_seqs,
            "rule_ids": list(s.get("rule_ids") or []),
        }
        for s in hos.get("seqs", []) or []
    ]

    # events[]: flatten the buffer, preserve match metadata, sort by timestamp.
    events: list[dict] = []
    distinct_rule_ids: set[str] = set()
    events_dropped = buffer.dropped_events
    for seq, entries in buffer.seqs_hit.items():
        if max_events_per_seq is not None and len(entries) > max_events_per_seq:
            # Keep the chronologically-first slice — mirrors the agent prompt
            # builder's "first representative" semantics.
            entries = sorted(entries, key=lambda e: e.event.get("timestamp") or "")
            events_dropped += len(entries) - max_events_per_seq
            entries = entries[:max_events_per_seq]
        for entry in entries:
            raw = entry.event
            match = _find_match(raw, entry.rule_id)
            distinct_rule_ids.add(entry.rule_id)
            events.append(
                {
                    "event_id": raw.get("event_id"),
                    "sigma_rule_id": entry.rule_id,
                    # Control-plane rules.id. Renamed from tagged-events
                    # `_rule_id`; not the correlation key.
                    "rule_db_id": match.get("_rule_id"),
                    "sigma_rule_title": match.get("rule_name"),
                    "seq": seq,
                    "timestamp": raw.get("timestamp"),
                    "technique_ids": match.get("mitre_techniques", []) or [],
                    "pipeline_id": raw.get("pipeline_id"),
                    "parsed_event": raw.get("parsed_event") or {},
                }
            )
    events.sort(key=lambda e: e.get("timestamp") or "")

    timestamps = [e["timestamp"] for e in events if e.get("timestamp")]
    first_seen = min(timestamps) if timestamps else None
    last_seen = max(timestamps) if timestamps else None

    return {
        "chain_id": chain_id,
        "hos_rule_id": hos.get("id"),
        "active_threat_id": active_threat.get("id"),
        "active_threat": _inline_active_threat(active_threat),
        # Pass HoS-level `tags[]` through verbatim (attack.Txxxx +
        # active_threat.<uuid>); detectflow-backend filters by prefix on consume.
        "hos_tags": list(hos.get("tags") or []),
        "chain_type": "HOS",
        "hostname": hostname,
        "username": None,  # chains are keyed by hostname only
        "window_start": window_start_iso,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "coverage": buffer.coverage_pct(total_seqs),
        "seqs": seqs,
        "events": events,
        "event_count": len(events),
        # Matched-but-not-inlined events (per-seq cap / record-size guard).
        # Additive field: detectflow-backend's consumer is extra="ignore", agent-job's
        # ChainRaw is extra="allow" — older consumers simply don't see it.
        "events_dropped": events_dropped,
        "rule_count": len(distinct_rule_ids),
        # ADDITIVE fields. Identify the correlation
        # pipeline that produced this chain so the control plane can attribute
        # and scope it without parsing topic names — destination-topic names
        # are NOT unique across detection pipelines. Consumers are
        # extra="allow" (agent-job, which round-trips them to chains-analysed
        # untouched) / extra="ignore" (control plane, until it declares the
        # field on its message model). `None` is correct and expected on the
        # legacy single-instance deployment, which has no pipeline id.
        "correlation_pipeline_id": correlation_pipeline_id,
        "correlation_pipeline_name": correlation_pipeline_name,
        "revision": revision,
    }
