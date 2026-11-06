"""Prompt builder for the ChainAnalysisAgent.

Produces `(system_message, user_message)` from a `ChainRaw`. The chain
envelope already carries the full `active_threat` inlined by
correlation-job — no extra lookup.

Rendering: one representative event per
`(seq, sigma_rule_id, pipeline_id)` group. Representative = the
chronologically first by `(timestamp, event_id)`; its `parsed_event`
is rendered verbatim. Group header carries seq, rule_title,
event_count, first_seen, last_seen, techniques. Destination Kafka
topics are not identity and are not rendered.

Cap: at most `PIPELINE_PER_GROUP_CAP` distinct `pipeline_id` values per
`(seq, sigma_rule_id)`. Excess buckets (chronologically latest first
events) are dropped from the prompt and counted in
`log_sources_capped`. The chains-raw envelope is uncapped.

Rule-less events (`sigma_rule_id is None`) each form their own
singleton group (keyed by `id(ev)`) and are never aggregated.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from app.operators.chain_models import ChainEvent, ChainRaw

# Informational only — the v3.2 render almost always fits a typical
# chain, so this budget is not enforced: nothing truncates, drops, or warns
# when the rendered prompt exceeds it. An over-long prompt is rejected or
# truncated by the LLM endpoint itself (provider-dependent).
DEFAULT_CHAR_BUDGET = 24_000

# 3.2: grouping pivoted from `source_topic` to `pipeline_id`, and both the
# `source_topic:` group line and the `pipelines:` meta line left the render.
# Same structure, different bytes — a verdict analysed under 3.1 is not
# reproducible from a 3.2 prompt, so the audit key has to move with it.
PROMPT_BUILDER_VERSION = "3.2"
AGGREGATION_METHOD = "one_per_group_per_pipeline"

# Caps the `event_ids` list inside `aggregation_summary[i]`. Full audit
# lives in chains-raw; this just keeps the prompt-side audit tractable.
AGGREGATION_SUMMARY_EVENT_ID_CAP = 50

PIPELINE_PER_GROUP_CAP = 5
UNKNOWN_PIPELINE_ID = "<unknown-pipeline>"


SYSTEM_PROMPT = """You are a senior SOC analyst reviewing an attack chain produced by a Higher Order Sigma (HoS) correlation rule. The chain represents multiple Sigma detections grouped by hostname within a time window, matching a known Active Threat profile.

Each detected event group is shown as: a header (sequence, rule name, event count, time range, techniques) and ONE representative event's full `parsed_event`. The representative is the chronologically first event of the group; all other events in the group share the same Sigma rule on the same chain step AND the same detection pipeline but may differ in their content (timestamps, source IPs, command lines, etc.). When inferring verdict, treat the representative as illustrative of the group; the `event_count` + time range tells you the scope of the burst. A single `(seq, rule)` may appear as multiple groups when the rule fired on events from more than one detection pipeline — keep those groups separate; the verdict comes from `parsed_event` content, not from how the event was routed.

Decide whether this is a real threat, suspicious activity warranting investigation, a false positive, or whether the chain lacks enough signal for a confident judgment. Consider:
- Whether the sequence of TTPs matches the threat actor's documented playbook
- Whether the temporal proximity, parent-child process lineage, and command-line content support a malicious narrative
- Whether benign software or operator activity could plausibly explain the events

Respond with a single JSON object — no surrounding prose, no code fences:

{
  "verdict": "TRUE" | "SUSPICIOUS" | "FALSE_POSITIVE" | "INSUFFICIENT_CONTEXT",
  "confidence": <float between 0 and 1>,
  "summary": "<one short paragraph: what happened, on which host, why this verdict>",
  "review": {
    "reasoning": "<analyst-style multi-sentence justification>",
    "indicators": ["<concrete IoC or behavior 1>", "..."],
    "recommended_actions": ["<action 1>", "..."],
    "missing_context": ["<concrete piece of evidence that would have allowed a confident verdict>", "..."]
  }
}

When the single representative event lacks the signal to confidently distinguish TRUE / SUSPICIOUS / FALSE_POSITIVE (for example: empty or generic `parsed_event`, missing rule title, group's `event_count` + time range alone insufficient), emit `"verdict": "INSUFFICIENT_CONTEXT"` with low `confidence`. Populate `missing_context` with specific items that would have unblocked a confident verdict — e.g. "full command_line for evt-099", "destination IPs across the burst in group seq=3", "parent process for the representative of group seq=2". Do NOT guess when you are unsure; an honest INSUFFICIENT_CONTEXT verdict is the correct output. The analyst will pull what is missing from the full chain envelope.

`missing_context` may be omitted when the verdict is TRUE / SUSPICIOUS / FALSE_POSITIVE."""


# ---------------------------------------------------------------------------
# Group dataclass + result envelopes
# ---------------------------------------------------------------------------


@dataclass
class _Group:
    """One rendered (seq, sigma_rule_id, pipeline_id) group.

    `representative` is the chronologically-first event by
    `(timestamp, event_id)` within the group. `event_ids` carries every
    event id in the group in chronological order — audit-only, capped
    when surfaced into `aggregation_summary`. `pipeline_id` is the
    detection pipeline that produced the tagged event (or the
    `<unknown-pipeline>` literal when missing — see
    `UNKNOWN_PIPELINE_ID`). It is grouping identity only and is not
    rendered into the prompt.
    """

    seq: int
    sigma_rule_id: str | None
    sigma_rule_title: str | None
    pipeline_id: str
    event_count: int
    first_seen: str | None
    last_seen: str | None
    representative: ChainEvent
    event_ids: list[str | None] = field(default_factory=list)


@dataclass
class PromptBuildResult:
    """Output of ``build_prompt_with_aggregation``: rendered messages + aggregation audit trail."""

    system: str
    user: str
    aggregation_summary: list[dict[str, Any]]
    aggregation_method: str = AGGREGATION_METHOD
    # Kept in the shape for downstream backwards compat — current render
    # path never drops groups nor caps events, so these are always 0.
    groups_dropped: int = 0
    events_capped: int = 0
    log_sources_capped: int = 0


def _event_sort_key(ev: ChainEvent) -> tuple[str, str]:
    """Sort key for chronological event ordering: ``(timestamp, event_id)``."""
    return (ev.timestamp or "", ev.event_id or "")


def _event_pipeline_id(ev: ChainEvent) -> str:
    """Return ``ev.pipeline_id`` or the ``UNKNOWN_PIPELINE_ID`` sentinel when absent."""
    return ev.pipeline_id or UNKNOWN_PIPELINE_ID


def _group_key(ev: ChainEvent) -> tuple[Any, ...]:
    """Return the aggregation key for an event: ``(seq, rule_id, pipeline_id)`` or a singleton identity key."""
    # Rule-less events bypass aggregation: each one renders as its own
    # singleton (keyed by object identity so identical content still
    # produces distinct groups).
    if ev.sigma_rule_id is None:
        return ("__singleton__", id(ev))
    return (ev.seq, ev.sigma_rule_id, _event_pipeline_id(ev))


def _parent_key(grp: _Group) -> tuple[Any, ...]:
    """Return the ``(seq, sigma_rule_id)`` parent key used to group sibling pipeline buckets."""
    return (grp.seq, grp.sigma_rule_id)


def _bucket_into_groups(events: list[ChainEvent]) -> list[_Group]:
    """Partition ``events`` into ``_Group`` objects keyed by ``(seq, rule_id, pipeline_id)``.

    Insertion order is preserved so group rendering is deterministic.
    Within each group, events are sorted chronologically to select the representative.
    """
    order: list[Any] = []
    by_key: dict[Any, list[ChainEvent]] = {}
    for ev in events:
        k = _group_key(ev)
        if k not in by_key:
            by_key[k] = []
            order.append(k)
        by_key[k].append(ev)

    groups: list[_Group] = []
    for k in order:
        evs = sorted(by_key[k], key=_event_sort_key)
        ts = [e.timestamp for e in evs if e.timestamp]
        rep = evs[0]
        groups.append(
            _Group(
                seq=rep.seq,
                sigma_rule_id=rep.sigma_rule_id,
                sigma_rule_title=rep.sigma_rule_title,
                pipeline_id=_event_pipeline_id(rep),
                event_count=len(evs),
                first_seen=min(ts) if ts else None,
                last_seen=max(ts) if ts else None,
                representative=rep,
                event_ids=[e.event_id for e in evs],
            )
        )
    return groups


def _apply_pipeline_cap(
    groups: list[_Group], cap: int = PIPELINE_PER_GROUP_CAP
) -> tuple[list[_Group], int]:
    """Drop excess pipeline buckets per ``(seq, rule_id)`` parent beyond ``cap``.

    Returns the filtered group list and the count of dropped buckets.
    Earliest-dated buckets survive; undated ones are deprioritised.
    """
    parent_to_groups: dict[Any, list[_Group]] = {}
    for grp in groups:
        parent = _parent_key(grp) if grp.sigma_rule_id is not None else id(grp)
        parent_to_groups.setdefault(parent, []).append(grp)

    survivors: set[int] = set()
    dropped = 0
    for siblings in parent_to_groups.values():
        if len(siblings) <= cap:
            survivors.update(id(g) for g in siblings)
            continue
        # None first_seen sorts last so dated groups outrank undated ones.
        ordered = sorted(
            siblings,
            key=lambda g: (g.first_seen is None, g.first_seen or ""),
        )
        for keeper in ordered[:cap]:
            survivors.add(id(keeper))
        dropped += len(siblings) - cap

    if dropped == 0:
        return groups, 0
    return [g for g in groups if id(g) in survivors], dropped


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _format_threat_actor(actor: Any) -> str:
    """Render one threat-actor line. Objects are `{id, name, description}`;
    the pre-enrichment wire shape is a bare MITRE group id string."""
    if isinstance(actor, str):
        return f"  - {actor}"
    if isinstance(actor, dict):
        label = actor.get("name") or actor.get("id") or "?"
        desc = actor.get("description") or ""
        return f"  - {label}: {desc}".rstrip()
    return f"  - {actor}"


def _format_at_block(at: dict[str, Any]) -> str:
    """Render the Active Threat section of the user message."""
    industries = ", ".join(at.get("industries") or []) or "—"
    geographies = ", ".join(at.get("geographies") or []) or "—"
    actors = at.get("threat_actors") or []
    actor_lines = "\n".join(_format_threat_actor(a) for a in actors)
    return (
        f"# Active Threat: {at.get('name') or '?'} "
        f"({at.get('threat_type') or '?'}, {at.get('severity') or '?'})\n"
        f"Industries: {industries}\n"
        f"Geographies: {geographies}\n"
        f"Summary: {at.get('summary') or '—'}\n"
        f"Investigation: {at.get('investigation') or '—'}\n"
        f"Mitigation: {at.get('mitigation') or '—'}\n"
        f"Response: {at.get('response') or '—'}\n"
        f"Threat actors:\n{actor_lines or '  —'}"
    )


def _format_chain_meta(chain: ChainRaw) -> str:
    """Render the chain metadata section (id, host, window, coverage, seqs)."""
    hits = [str(s.seq) for s in chain.seqs if s.hit]
    misses = [str(s.seq) for s in chain.seqs if not s.hit]
    return (
        f"# Chain\n"
        f"chain_id: {chain.chain_id}\n"
        f"hostname: {chain.hostname}\n"
        f"window_start: {chain.window_start}\n"
        f"first_seen: {chain.first_seen}\n"
        f"last_seen: {chain.last_seen}\n"
        f"coverage: {chain.coverage}%\n"
        f"seqs hit: {', '.join(hits) or '—'}\n"
        f"seqs missed: {', '.join(misses) or '—'}\n"
        f"revision: {chain.revision}"
    )


def _format_group_block(idx: int, grp: _Group) -> str:
    """Render one event-group block: header + representative ``parsed_event``."""
    rep = grp.representative
    techniques = ", ".join(rep.technique_ids) or "—"
    rule_label = grp.sigma_rule_title or grp.sigma_rule_id or "?"
    parsed_str = json.dumps(
        rep.parsed_event,
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )
    return (
        f'[{idx}] Group seq={grp.seq} rule="{rule_label}"\n'
        f"    event_count: {grp.event_count}, "
        f"first_seen: {grp.first_seen}, last_seen: {grp.last_seen}\n"
        f"    techniques: {techniques}\n"
        f"    representative event_id: {rep.event_id or '—'}\n"
        f"    representative parsed_event:\n"
        f"    {parsed_str}"
    )


def _events_header(group_count: int, raw_count: int, log_sources_capped: int = 0) -> str:
    """Render the events-section header line, noting group vs. raw counts and any cap."""
    if group_count == raw_count:
        base = f"# Events ({group_count} of {raw_count} shown)"
    else:
        base = f"# Events ({group_count} groups from {raw_count} raw events)"
    if log_sources_capped > 0:
        base = f"{base} [+{log_sources_capped} pipeline group(s) dropped by cap]"
    return base


def _build_user_message(at_block: str, meta_block: str, events_block: str) -> str:
    """Concatenate the three rendered sections into the final user message."""
    return f"{at_block}\n\n{meta_block}\n\n{events_block}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_prompt(
    chain: ChainRaw,
    *,
    char_budget: int = DEFAULT_CHAR_BUDGET,
) -> tuple[str, str]:
    """Return ``(system_message, user_message)`` for a chain. Convenience wrapper over ``build_prompt_with_aggregation``."""
    result = build_prompt_with_aggregation(chain, char_budget=char_budget)
    return result.system, result.user


def build_prompt_with_aggregation(
    chain: ChainRaw,
    *,
    char_budget: int = DEFAULT_CHAR_BUDGET,
) -> PromptBuildResult:
    """Build the full prompt with aggregation metadata for a chain.

    Groups events by ``(seq, rule_id, pipeline_id)``, applies the per-pipeline
    cap, and renders ``(system, user)`` messages plus an audit trail.
    ``char_budget`` is advisory — no truncation or fallback path exists.
    """
    at_block = _format_at_block(chain.active_threat.model_dump())
    meta_block = _format_chain_meta(chain)
    groups = _bucket_into_groups(chain.events)
    groups, log_sources_capped = _apply_pipeline_cap(groups)

    rendered_groups = [_format_group_block(i, g) for i, g in enumerate(groups, start=1)]
    header = _events_header(len(groups), len(chain.events), log_sources_capped)
    events_block = header + ("\n" + "\n\n".join(rendered_groups) if rendered_groups else "\n—")
    user = _build_user_message(at_block, meta_block, events_block)

    aggregation_summary = [
        {
            "seq": g.seq,
            "sigma_rule_id": g.sigma_rule_id,
            "pipeline_id": g.pipeline_id,
            "event_count": g.event_count,
            "event_ids": g.event_ids[:AGGREGATION_SUMMARY_EVENT_ID_CAP],
            "first_seen": g.first_seen,
            "last_seen": g.last_seen,
        }
        for g in groups
    ]

    _ = char_budget  # advisory only; no fallback path

    return PromptBuildResult(
        system=SYSTEM_PROMPT,
        user=user,
        aggregation_summary=aggregation_summary,
        aggregation_method=AGGREGATION_METHOD,
        groups_dropped=0,
        events_capped=0,
        log_sources_capped=log_sources_capped,
    )
