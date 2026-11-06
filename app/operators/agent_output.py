"""LLM response parser for ChainAnalysisAgent.

Parses the raw text returned by the LLM into the validated
`(verdict, confidence, summary, review)` quad that downstream serializes
into the `chains-analysed` envelope. Resilient to common drift modes:

- markdown code fences (```json ... ```)
- prose-wrapped JSON ("Here's the analysis: {...}") — first balanced
  top-level ``{...}`` block is extracted as a last resort before fallback
- verdict casing variants (true / True / TRUE; "false positive" / "false_positive")
- confidence as percent (0..100) instead of fraction (0..1)
- review delivered as plain string instead of structured object

On unrecoverable parse failure, emits the **safe-default fallback**:

    verdict   = SUSPICIOUS
    confidence = 0.3
    summary    = "LLM output unparsable"
    review     = {"reasoning": <raw text>, "indicators": [], "recommended_actions": []}

The chain is never lost — the analyst sees something the moment any byte
came back. Terminal LLM failures (no bytes at all) take a different path
in `llm_client.py`.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from app.config.logging import get_logger
from app.operators.chain_models import LlmVerdict

logger = get_logger(__name__)

FALLBACK_CONFIDENCE = 0.3
FALLBACK_SUMMARY = "LLM output unparsable"

_CODE_FENCE_RE = re.compile(r"^\s*```(?:json|JSON)?\s*\n?(.*?)\n?```\s*$", re.DOTALL)

_VERDICT_ALIASES: dict[str, LlmVerdict] = {
    "TRUE": LlmVerdict.TRUE,
    "TRUE_POSITIVE": LlmVerdict.TRUE,
    "TRUEPOSITIVE": LlmVerdict.TRUE,
    "MALICIOUS": LlmVerdict.TRUE,
    "SUSPICIOUS": LlmVerdict.SUSPICIOUS,
    "SUSPECT": LlmVerdict.SUSPICIOUS,
    "FALSE_POSITIVE": LlmVerdict.FALSE_POSITIVE,
    "FALSEPOSITIVE": LlmVerdict.FALSE_POSITIVE,
    "BENIGN": LlmVerdict.FALSE_POSITIVE,
    "FALSE": LlmVerdict.FALSE_POSITIVE,
    "INSUFFICIENT_CONTEXT": LlmVerdict.INSUFFICIENT_CONTEXT,
    "INSUFFICIENTCONTEXT": LlmVerdict.INSUFFICIENT_CONTEXT,
    "UNKNOWN": LlmVerdict.INSUFFICIENT_CONTEXT,
    "INSUFFICIENT": LlmVerdict.INSUFFICIENT_CONTEXT,
}


@dataclass
class ParsedAnalysis:
    """Validated result of a single LLM response parse.

    ``parse_failed=True`` indicates the safe-default fallback path was taken;
    ``fallback_reason`` carries the specific failure slug for metrics.
    """

    verdict: LlmVerdict
    confidence: float
    summary: str
    review: dict[str, Any]
    parse_failed: bool = False
    fallback_reason: str | None = None
    extras: dict[str, Any] = field(default_factory=dict)
    missing_context: list[str] = field(default_factory=list)


def _strip_code_fences(text: str) -> str:
    """Strip surrounding ```json ... ``` or ``` ... ``` fences if present."""
    m = _CODE_FENCE_RE.match(text.strip())
    if m:
        return m.group(1).strip()
    return text.strip()


def _extract_first_json_object(text: str) -> str | None:
    """Best-effort: return the first balanced top-level ``{...}`` block, or ``None``.

    Last-resort recovery for prose-wrapped JSON ("Here's the analysis: {...}
    hope that helps") — a drift mode `_strip_code_fences` cannot catch because
    its regex only matches a whole-string fence. The scan is string-aware
    (braces inside JSON string values, including escaped quotes, don't move
    the depth counter), so `'{"summary": "a {weird} value"}'` extracts whole.

    Returns the raw substring; the caller still runs ``json.loads`` on it —
    a balanced-but-invalid block (e.g. ``{not json}``) fails there and takes
    the existing fallback path.
    """
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None  # unbalanced — no complete top-level object


def _normalise_verdict(value: Any) -> LlmVerdict | None:
    """Map a raw verdict string to ``LlmVerdict`` via ``_VERDICT_ALIASES``, or ``None`` on unknown."""
    if not isinstance(value, str):
        return None
    key = re.sub(r"[^A-Z_]", "", value.upper().replace(" ", "_").replace("-", "_"))
    return _VERDICT_ALIASES.get(key)


def _normalise_confidence(value: Any) -> float | None:
    """Accept fraction (0..1) or percent (0..100). Reject anything else."""
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    if f != f:  # NaN
        return None
    if 0.0 <= f <= 1.0:
        return round(f, 4)
    # Percent path only kicks in for clearly >1 values. The 1.0–2.0 band is
    # ambiguous (could be drift either way) — safer to fall back than to
    # silently divide by 100 and report 1.5% confidence.
    if 2.0 <= f <= 100.0:
        logger.warning(
            "LLM returned confidence as percent — coercing to fraction",
            raw_value=f,
        )
        return round(f / 100.0, 4)
    return None


def _normalise_review(value: Any) -> dict[str, Any]:
    """Wrap a plain string into the structured review shape."""
    if isinstance(value, dict):
        out = dict(value)
        out.setdefault("reasoning", "")
        out.setdefault("indicators", [])
        out.setdefault("recommended_actions", [])
        return out
    if isinstance(value, str):
        return {"reasoning": value, "indicators": [], "recommended_actions": []}
    return {"reasoning": "", "indicators": [], "recommended_actions": []}


def _coerce_missing_context(value: Any) -> list[str]:
    """Best-effort: accept list[str], drop non-strings, treat anything else as []."""
    if isinstance(value, list):
        return [str(x) for x in value if isinstance(x, (str, int, float))]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _fallback(raw_text: str, reason: str) -> ParsedAnalysis:
    """Return the safe-default ``ParsedAnalysis`` for any unrecoverable parse failure."""
    logger.warning("LLM output fallback triggered", reason=reason)
    return ParsedAnalysis(
        verdict=LlmVerdict.SUSPICIOUS,
        confidence=FALLBACK_CONFIDENCE,
        summary=FALLBACK_SUMMARY,
        review={
            "reasoning": raw_text,
            "indicators": [],
            "recommended_actions": [],
        },
        parse_failed=True,
        fallback_reason=reason,
    )


def parse_llm_response(raw_text: str) -> ParsedAnalysis:
    """Parse raw LLM text into a validated `ParsedAnalysis`.

    Never raises — always returns a usable result. `parse_failed=True`
    flags the safe-default fallback path for metrics and tests.
    """
    if not raw_text or not raw_text.strip():
        return _fallback(raw_text or "", "empty_response")

    cleaned = _strip_code_fences(raw_text)

    try:
        payload = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        # Direct parse + fence-strip both failed — try extracting the first
        # balanced top-level {...} block (prose-wrapped JSON) before giving up.
        extracted = _extract_first_json_object(cleaned)
        if extracted is None:
            return _fallback(raw_text, f"json_decode_error: {exc.msg}")
        try:
            payload = json.loads(extracted)
            logger.info(
                "LLM output was prose-wrapped JSON — extracted embedded object",
                surrounding_chars=len(cleaned) - len(extracted),
            )
        except json.JSONDecodeError:
            # Report the ORIGINAL error — the extraction was a recovery
            # attempt, not the primary parse.
            return _fallback(raw_text, f"json_decode_error: {exc.msg}")

    if not isinstance(payload, dict):
        return _fallback(raw_text, "payload_not_object")

    verdict = _normalise_verdict(payload.get("verdict"))
    if verdict is None:
        return _fallback(raw_text, f"unknown_verdict: {payload.get('verdict')!r}")

    confidence = _normalise_confidence(payload.get("confidence"))
    if confidence is None:
        return _fallback(raw_text, f"invalid_confidence: {payload.get('confidence')!r}")

    summary = payload.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        return _fallback(raw_text, "missing_or_empty_summary")

    review = _normalise_review(payload.get("review"))

    # `missing_context` is the analyst-handoff hint the LLM emits when it
    # picks INSUFFICIENT_CONTEXT — items it would have needed to decide.
    # Accept the field either at top level or nested in `review`, normalise
    # to a typed list, and re-pin it inside `review` so chains-analysed
    # carries the same shape regardless of where the LLM put it.
    missing_context = _coerce_missing_context(
        payload.get("missing_context") or review.get("missing_context")
    )
    if missing_context:
        review["missing_context"] = missing_context

    extras = {
        k: v
        for k, v in payload.items()
        if k not in {"verdict", "confidence", "summary", "review", "missing_context"}
    }

    return ParsedAnalysis(
        verdict=verdict,
        confidence=confidence,
        summary=summary.strip(),
        review=review,
        extras=extras,
        missing_context=missing_context,
    )
