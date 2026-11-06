"""LLM output parser tests — drift modes + fallback path."""

from __future__ import annotations

import json

import pytest

from app.operators.agent_output import (
    FALLBACK_CONFIDENCE,
    FALLBACK_SUMMARY,
    parse_llm_response,
)
from app.operators.chain_models import LlmVerdict


def _well_formed(**overrides) -> str:
    payload = {
        "verdict": "TRUE",
        "confidence": 0.87,
        "summary": "Multi-stage APT28 chain on WKST-FIN-05.",
        "review": {
            "reasoning": "5/6 seqs hit, parent-child lineage matches playbook.",
            "indicators": ["RAR archive execution", "encoded PowerShell"],
            "recommended_actions": ["Isolate host", "Reset credentials"],
        },
    }
    payload.update(overrides)
    return json.dumps(payload)


def test_well_formed_json_parsed_lossless():
    parsed = parse_llm_response(_well_formed())

    assert parsed.parse_failed is False
    assert parsed.verdict is LlmVerdict.TRUE
    assert parsed.confidence == 0.87
    assert parsed.summary.startswith("Multi-stage")
    assert parsed.review["reasoning"].startswith("5/6")
    assert parsed.review["indicators"] == ["RAR archive execution", "encoded PowerShell"]


@pytest.mark.parametrize(
    "fenced",
    [
        "```json\n{}\n```",
        "```\n{}\n```",
        "  ```json\n{}\n```  ",
    ],
)
def test_markdown_code_fences_stripped(fenced):
    body = _well_formed()
    fenced_text = fenced.replace("{}", body, 1)
    parsed = parse_llm_response(fenced_text)

    assert parsed.parse_failed is False
    assert parsed.verdict is LlmVerdict.TRUE


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("TRUE", LlmVerdict.TRUE),
        ("true", LlmVerdict.TRUE),
        ("True", LlmVerdict.TRUE),
        ("True Positive", LlmVerdict.TRUE),
        ("malicious", LlmVerdict.TRUE),
        ("SUSPICIOUS", LlmVerdict.SUSPICIOUS),
        ("suspicious", LlmVerdict.SUSPICIOUS),
        ("FALSE_POSITIVE", LlmVerdict.FALSE_POSITIVE),
        ("false positive", LlmVerdict.FALSE_POSITIVE),
        ("False-Positive", LlmVerdict.FALSE_POSITIVE),
        ("benign", LlmVerdict.FALSE_POSITIVE),
    ],
)
def test_verdict_casing_and_alias_normalisation(raw, expected):
    parsed = parse_llm_response(_well_formed(verdict=raw))

    assert parsed.parse_failed is False
    assert parsed.verdict is expected


def test_verdict_unknown_value_falls_back():
    parsed = parse_llm_response(_well_formed(verdict="MAYBE"))

    assert parsed.parse_failed is True
    assert parsed.verdict is LlmVerdict.SUSPICIOUS
    assert parsed.confidence == FALLBACK_CONFIDENCE
    assert "MAYBE" in (parsed.fallback_reason or "")


@pytest.mark.parametrize(
    "raw,expected",
    [
        (0.0, 0.0),
        (1.0, 1.0),
        (0.42, 0.42),
        (87, 0.87),
        (87.0, 0.87),
        ("0.5", 0.5),
        ("65", 0.65),
    ],
)
def test_confidence_percent_coercion(raw, expected):
    parsed = parse_llm_response(_well_formed(confidence=raw))

    assert parsed.parse_failed is False
    assert parsed.confidence == pytest.approx(expected, abs=1e-4)


@pytest.mark.parametrize("raw", [-0.1, 1.1, 101, "high", None, float("nan")])
def test_confidence_out_of_range_or_invalid_falls_back(raw):
    parsed = parse_llm_response(_well_formed(confidence=raw))

    assert parsed.parse_failed is True
    assert parsed.verdict is LlmVerdict.SUSPICIOUS


def test_review_plain_string_wrapped_into_structured_object():
    parsed = parse_llm_response(_well_formed(review="A free-form analyst note."))

    assert parsed.parse_failed is False
    assert parsed.review == {
        "reasoning": "A free-form analyst note.",
        "indicators": [],
        "recommended_actions": [],
    }


def test_review_dict_missing_subfields_filled_with_defaults():
    parsed = parse_llm_response(_well_formed(review={"reasoning": "only this"}))

    assert parsed.parse_failed is False
    assert parsed.review["reasoning"] == "only this"
    assert parsed.review["indicators"] == []
    assert parsed.review["recommended_actions"] == []


def test_missing_summary_falls_back():
    body = json.dumps(
        {
            "verdict": "TRUE",
            "confidence": 0.5,
            "review": {"reasoning": "x"},
        }
    )
    parsed = parse_llm_response(body)

    assert parsed.parse_failed is True
    assert parsed.summary == FALLBACK_SUMMARY


@pytest.mark.parametrize(
    "template",
    [
        "Here's the analysis: {} hope that helps!",
        "Sure! Based on the events provided:\n\n{}\n\nLet me know if you need more.",
        "Analysis result: {}",
    ],
)
def test_prose_wrapped_json_extracted_and_parsed(template):
    """Prose around a valid JSON object (a drift mode the whole-string fence
    regex cannot catch) must parse via the balanced-block extraction, not fall
    back to SUSPICIOUS/0.3."""
    parsed = parse_llm_response(template.format(_well_formed()))

    assert parsed.parse_failed is False
    assert parsed.verdict is LlmVerdict.TRUE
    assert parsed.confidence == 0.87


def test_prose_wrapped_json_with_braces_in_string_values():
    """The extraction scanner must be string-aware: braces inside JSON string
    values (incl. escaped quotes) must not unbalance the depth counter."""
    body = _well_formed(summary='Ran cmd {echo "hi \\"x\\""} on host')
    parsed = parse_llm_response(f"Verdict below.\n{body}\nDone.")

    assert parsed.parse_failed is False
    assert parsed.summary == 'Ran cmd {echo "hi \\"x\\""} on host'


def test_prose_with_invalid_braced_block_still_falls_back():
    """A balanced-but-not-JSON {...} block fails the recovery parse and takes
    the existing fallback path with the original decode error."""
    parsed = parse_llm_response("In set notation {a, b, c} we denote membership.")

    assert parsed.parse_failed is True
    assert parsed.verdict is LlmVerdict.SUSPICIOUS
    assert parsed.confidence == FALLBACK_CONFIDENCE
    assert (parsed.fallback_reason or "").startswith("json_decode_error")


def test_prose_with_unbalanced_brace_falls_back():
    parsed = parse_llm_response("An opening brace { with no closing partner.")

    assert parsed.parse_failed is True
    assert (parsed.fallback_reason or "").startswith("json_decode_error")


def test_non_json_garbage_falls_back():
    parsed = parse_llm_response("This is not JSON at all, just prose.")

    assert parsed.parse_failed is True
    assert parsed.verdict is LlmVerdict.SUSPICIOUS
    assert parsed.confidence == FALLBACK_CONFIDENCE
    assert parsed.review["reasoning"] == "This is not JSON at all, just prose."
    assert parsed.summary == FALLBACK_SUMMARY


def test_empty_response_falls_back():
    parsed = parse_llm_response("")

    assert parsed.parse_failed is True
    assert parsed.fallback_reason == "empty_response"


def test_top_level_array_falls_back():
    parsed = parse_llm_response(json.dumps([1, 2, 3]))

    assert parsed.parse_failed is True
    assert parsed.fallback_reason == "payload_not_object"


def test_extra_top_level_fields_preserved_in_extras():
    body = json.dumps(
        {
            "verdict": "TRUE",
            "confidence": 0.5,
            "summary": "x",
            "review": {"reasoning": "y"},
            "model_metadata": {"latency_ms": 1234},
        }
    )
    parsed = parse_llm_response(body)

    assert parsed.parse_failed is False
    assert parsed.extras == {"model_metadata": {"latency_ms": 1234}}
