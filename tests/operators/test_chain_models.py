"""Round-trip + AT-inline anchor tests for chain envelope Pydantic models.

If these break, agent-job is silently dropping or coercing fields produced
by correlation-job — every downstream agent-job operator builds on
top of `ChainRaw`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.operators.chain_models import (
    ActiveThreatInline,
    ChainAnalysed,
    ChainRaw,
    LlmVerdict,
)

FIXTURES_DIR = Path(__file__).parents[1] / "fixtures" / "attack-chains"

# Whitelist mirror — must match `app.operators.chain_record._AT_INLINE_FIELDS`
# exactly. Drift between the two is a contract bug.
AT_INLINE_FIELDS = (
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


def _load(name: str) -> dict:
    return json.loads((FIXTURES_DIR / name).read_text())


def test_threat_actors_accept_mitre_group_id_strings():
    """Pre-enrichment AT payloads carried ``threat_actors`` as MITRE ids.

    Agent-job used to drop those chains-raw records (`Input should be an
    object`). Strings must parse, round-trip, and mix with `{id, name}`
    objects so in-flight records survive the control-plane rollout.
    """
    raw = _load("chain_raw_apt28_v1.json")
    raw["active_threat"]["threat_actors"] = ["G1007", "G1024"]

    parsed = ChainRaw.model_validate(raw)
    dumped = parsed.model_dump(mode="json")

    assert parsed.active_threat.threat_actors == ["G1007", "G1024"]
    assert dumped["active_threat"]["threat_actors"] == ["G1007", "G1024"]

    raw["active_threat"]["threat_actors"] = [
        "G1007",
        {"id": "G0024", "name": "APT28"},
    ]
    mixed = ChainRaw.model_validate(raw)
    dumped_actors = mixed.model_dump(mode="json")["active_threat"]["threat_actors"]
    assert dumped_actors[0] == "G1007"
    assert dumped_actors[1]["id"] == "G0024"
    assert dumped_actors[1]["name"] == "APT28"


def test_chain_raw_round_trip_lossless():
    """`ChainRaw.model_validate(fixture).model_dump()` ≡ original fixture."""
    raw = _load("chain_raw_apt28_v1.json")

    parsed = ChainRaw.model_validate(raw)
    dumped = parsed.model_dump(mode="json")

    assert dumped == raw


def test_chain_analysed_round_trip_lossless():
    raw = _load("chain_analysed_apt28_v1.json")

    parsed = ChainAnalysed.model_validate(raw)
    dumped = parsed.model_dump(mode="json")

    assert dumped == raw


def test_active_threat_inline_exposes_all_10_whitelisted_fields():
    """The inline AT block must declare every whitelisted field — drift
    against `chain_record._AT_INLINE_FIELDS` is a cross-module contract bug."""
    declared = set(ActiveThreatInline.model_fields.keys())
    assert declared == set(AT_INLINE_FIELDS)


def test_unknown_fields_preserved_not_dropped():
    """Future-compat: if correlation-job adds a field, agent-job must not
    silently strip it on round-trip."""
    raw = _load("chain_raw_apt28_v1.json")
    raw["new_future_field"] = {"k": "v"}
    raw["active_threat"]["future_at_field"] = ["x"]

    parsed = ChainRaw.model_validate(raw)
    dumped = parsed.model_dump(mode="json")

    assert dumped["new_future_field"] == {"k": "v"}
    assert dumped["active_threat"]["future_at_field"] == ["x"]


def test_llm_verdict_enum_values():
    assert LlmVerdict.TRUE.value == "TRUE"
    assert LlmVerdict.SUSPICIOUS.value == "SUSPICIOUS"
    assert LlmVerdict.FALSE_POSITIVE.value == "FALSE_POSITIVE"


def test_llm_verdict_rejects_unknown_value():
    raw = _load("chain_analysed_apt28_v1.json")
    raw["llm_verdict"] = "MAYBE"

    with pytest.raises(Exception):
        ChainAnalysed.model_validate(raw)


def test_chain_analysed_allows_null_verdict_for_graceful_degradation():
    """Terminal LLM failure path: `llm_verdict=None` + ai_summary message."""
    raw = _load("chain_analysed_apt28_v1.json")
    raw["llm_verdict"] = None
    raw["llm_confidence"] = None
    raw["ai_summary"] = "LLM unavailable"
    raw["llm_review"] = {"error": "openai 503 after 3 retries"}

    parsed = ChainAnalysed.model_validate(raw)

    assert parsed.llm_verdict is None
    assert parsed.llm_confidence is None
    assert parsed.ai_summary == "LLM unavailable"
    assert parsed.llm_review == {"error": "openai 503 after 3 retries"}


def test_chain_raw_inherits_into_analysed_without_field_loss():
    """All ChainRaw fields are still present on ChainAnalysed."""
    raw_fields = set(ChainRaw.model_fields.keys())
    analysed_fields = set(ChainAnalysed.model_fields.keys())
    assert raw_fields.issubset(analysed_fields)
    assert analysed_fields - raw_fields == {
        "ai_summary",
        "llm_verdict",
        "llm_confidence",
        "llm_review",
        "analysed_at",
    }


def test_chain_raw_round_trips_correlation_pipeline_fields():
    """The pipeline stamp reaches `chains-analysed` with ZERO agent-job code
    change — it rides `extra="allow"` on ChainRaw/ChainAnalysed and agent-job
    round-trips extras verbatim. Proven here rather than trusted."""
    raw = _load("chain_raw_apt28_v1.json")
    raw["correlation_pipeline_id"] = "3f2b8c14-9f6a-4c3d-8f21-2a7b5c9d1e04"
    raw["correlation_pipeline_name"] = "Correlation Pipeline A"

    model = ChainRaw.model_validate(raw)
    assert model.model_dump()["correlation_pipeline_id"] == raw["correlation_pipeline_id"]
    assert model.model_dump()["correlation_pipeline_name"] == "Correlation Pipeline A"

    analysed = ChainAnalysed.model_validate(
        {
            **model.model_dump(),
            "ai_summary": "s",
            "llm_verdict": "TRUE",
            "llm_confidence": 0.9,
            "llm_review": {},
            "analysed_at": "2026-04-22T10:00:00Z",
        }
    )
    dumped = analysed.model_dump()
    assert dumped["correlation_pipeline_id"] == raw["correlation_pipeline_id"]
    assert dumped["correlation_pipeline_name"] == "Correlation Pipeline A"
