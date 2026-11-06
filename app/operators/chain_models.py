"""Pydantic models for the chain envelope (raw + analysed).

Wire-schema contract: matches `tests/fixtures/attack-chains/chain_raw_apt28_v1.json`
and `chain_analysed_apt28_v1.json` exactly.

`extra="allow"` is set on every model so fields added to the envelope by
detectflow-backend or correlation-job in the future flow through agent-job
unchanged. Round-trip (validate → dump) is lossless on the canonical
fixtures — see `tests/operators/test_chain_models.py`.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class LlmVerdict(StrEnum):
    """LLM verdict enum surfaced into `chains-analysed.llm_verdict`.

    `INSUFFICIENT_CONTEXT` under the v2 (one-representative-per-group)
    prompt renderer fires when the *single representative event* of a
    group lacks the signal to confidently distinguish
    TRUE / SUSPICIOUS / FALSE_POSITIVE — e.g. empty / generic
    `parsed_event`, missing rule title, or the group's `event_count` +
    time range alone insufficient. The earlier "events dropped from
    prompt by cascading aggregation" trigger no longer exists (the
    cascade is gone — single render path always emits one
    representative per group, never drops or caps).
    """

    TRUE = "TRUE"
    SUSPICIOUS = "SUSPICIOUS"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"


_MODEL_CONFIG = ConfigDict(extra="allow")


class ThreatActor(BaseModel):
    model_config = _MODEL_CONFIG

    id: str | None = None
    name: str | None = None
    description: str | None = None


class ActiveThreatInline(BaseModel):
    """The 10-field whitelist correlation-job inlines into every chain.

    Mirror of `app.operators.chain_record._AT_INLINE_FIELDS`. Operational
    fields (id, enabled, monitored_topics, release_date, source, updated_at)
    are intentionally excluded from this snapshot.

    `threat_actors` accepts the current `{id, name}` objects *and* the
    pre-enrichment string list (MITRE group ids like ``"G1007"``) so
    in-flight chains-raw records are not dropped while the control plane
    rolls out the object shape.
    """

    model_config = _MODEL_CONFIG

    name: str | None = None
    threat_type: str | None = None
    severity: str | None = None
    industries: list[str] = Field(default_factory=list)
    geographies: list[str] = Field(default_factory=list)
    summary: str | None = None
    investigation: str | None = None
    mitigation: str | None = None
    response: str | None = None
    threat_actors: list[ThreatActor | str] = Field(default_factory=list)


class SeqInfo(BaseModel):
    """One seq in the matched HoS rule, with hit/miss flag and the sigma
    UUIDs declared for that seq in the HoS YAML.

    `rule_ids` is the consumer's hook for resolving expected techniques in
    missed seqs — detectflow-backend joins these UUIDs against its
    sigma-rules table to produce titles + technique_ids on the read side.
    For hit seqs the same data lives on `events[].sigma_rule_id` /
    `events[].technique_ids` (only fired rules carry titles upstream)."""

    model_config = _MODEL_CONFIG

    seq: int
    hit: bool
    rule_ids: list[str] = Field(default_factory=list)


class ChainEvent(BaseModel):
    model_config = _MODEL_CONFIG

    event_id: str | None = None
    sigma_rule_id: str | None = None
    # Control-plane `rules.id`. Copied from tagged-events
    # `detectflow.matches[]._rule_id` and renamed at emit. Not the
    # correlation key — that remains `sigma_rule_id` (Sigma UUID).
    rule_db_id: str | None = None
    sigma_rule_title: str | None = None
    seq: int
    timestamp: str | None = None
    technique_ids: list[str] = Field(default_factory=list)
    pipeline_id: str | None = None
    parsed_event: dict[str, Any] = Field(default_factory=dict)


class ChainRaw(BaseModel):
    """Envelope on `detectflow.chains-raw` (correlation-job → agent-job).

    The Active Threat is inlined into the envelope.
    """

    model_config = _MODEL_CONFIG

    chain_id: str
    hos_rule_id: str
    active_threat_id: str
    active_threat: ActiveThreatInline
    # HoS-level tags from the HoS envelope `tags[]`, passed through verbatim
    # — includes `attack.Txxxx` ATT&CK technique markers + the
    # `active_threat.<uuid>` back-pointer. No parsing on our side; the
    # consumer filters/maps the prefix space it cares about.
    hos_tags: list[str] = Field(default_factory=list)
    chain_type: str = "HOS"
    hostname: str
    username: str | None = None
    window_start: str
    first_seen: str | None = None
    last_seen: str | None = None
    coverage: float
    seqs: list[SeqInfo] = Field(default_factory=list)
    events: list[ChainEvent] = Field(default_factory=list)
    event_count: int = 0
    rule_count: int = 0
    # No `pipeline_names`: it held distinct destination-topic names, never
    # pipeline names, and no consumer read it back out. The per-flow identity
    # is `events[].pipeline_id`; the control plane resolves display names from
    # its own pipelines table. Pre-removal records still deserialize — the
    # field lands in `extra` under `extra="allow"` and round-trips untouched.
    revision: int = 1


class ChainAnalysed(ChainRaw):
    """Envelope on `detectflow.chains-analysed` (agent-job → detectflow-backend).

    Adds the LLM enrichment fields. On terminal LLM failure,
    `llm_verdict=None` + `ai_summary="LLM unavailable"` + error captured in
    `llm_review` (graceful degradation).
    """

    ai_summary: str
    llm_verdict: LlmVerdict | None = None
    llm_confidence: float | None = None
    llm_review: dict[str, Any] = Field(default_factory=dict)
    analysed_at: str
