"""HoS YAML parser — extracts the matcher-relevant body from a HoS rule's
YAML text.

Wire format: detectflow-backend ships a thin envelope containing the full HoS
YAML as a `yaml_text` string field. This module owns the structural parse
and validation that the broadcast handler needs to populate broadcast state.
It mirrors the existing sigma-rules pattern in `detectflow-matchnode` where the
broadcast handler is the single source of truth for rule-shape validation.

What this module enforces (matcher-relevant only):

- YAML parses and the root is a mapping.
- A `detection` block exists and is a mapping.
- At least one `seqN` key under `detection` (numeric suffix) carrying a
  non-empty `ruleid|contains` list. A `seqN` without one is skipped, not
  rejected, and then does not count towards the rule's total steps.
- `detection.timeframe` parses to a strictly positive integer of seconds.
  Accepts `Ns`, `Nm`, `Nh`, `Nd` shorthand and bare integers (interpreted
  as seconds).
- `detection.condition` equals `"chain by hostname"` (whitespace-collapsed,
  case-sensitive on the keyword to match the upstream HoS rule format).

What it does NOT enforce (detectflow-backend concerns, out of
scope for the matcher):

- `level` enum, `tags` shape, `active_threat.<uuid>` tag presence,
  `ruleid|contains` UUID-ness, `logsource.category`. Those are upstream
  validation gates; the matcher accepts pre-validated rules and trusts
  the envelope's top-level metadata for `id` / `active_threat_id`.
"""

from __future__ import annotations

import re

import yaml


class HosYamlError(Exception):
    """Base for any structural rejection of a HoS YAML body."""

    reason: str = "invalid_yaml"


class MalformedYamlError(HosYamlError):
    reason = "invalid_yaml"


class MissingDetectionError(HosYamlError):
    reason = "missing_detection"


class EmptySeqsError(HosYamlError):
    reason = "empty_seqs"


class InvalidTimeframeError(HosYamlError):
    reason = "invalid_timeframe"


class UnsupportedConditionError(HosYamlError):
    reason = "unsupported_condition"


# `chain by hostname` is the only supported condition. Upstream validates
# it too, but the matcher must self-defend.
_REQUIRED_CONDITION = "chain by hostname"

# `30m`, `300s`, `1h`, `2d`, or bare seconds (`1800`).
_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smhd]?)\s*$", re.IGNORECASE)
_DURATION_UNIT_S = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}

_SEQ_KEY_RE = re.compile(r"^seq(\d+)$")


def hos_body_from_envelope(envelope: dict) -> dict:
    """Build the matcher's in-state HoS body from a wire envelope.

    The wire envelope is what detectflow-backend publishes on `detectflow.hos-rules`.
    Structural fields (`seqs`, `timeframe_seconds`, `condition`)
    come from parsing `envelope['yaml_text']`; envelope-level metadata
    (`id`, `active_threat_id`, `level`, `tags`, ...) is trusted as-is.

    Raises a `HosYamlError` subclass on structural problems with the YAML.
    Envelope-level field absence (e.g. missing `id`) is the broadcast
    handler's concern, not this helper's.
    """
    yaml_text = envelope.get("yaml_text")
    if not isinstance(yaml_text, str) or not yaml_text.strip():
        raise MalformedYamlError("`yaml_text` missing or empty in envelope")
    parsed = parse_hos_yaml(yaml_text)
    body = dict(envelope)
    body.pop("yaml_text", None)
    body["seqs"] = parsed["seqs"]
    body["timeframe_seconds"] = parsed["timeframe_seconds"]
    body["condition"] = parsed["condition"]
    return body


def parse_hos_yaml(yaml_text: str) -> dict:
    """Parse a HoS YAML body to the matcher's internal shape.

    Returns a dict with stable keys regardless of YAML phrasing::

        {
            "seqs": [{"seq": int, "rule_ids": [str, ...]}, ...],   # sorted by seq
            "timeframe_seconds": int,                              # > 0
            "condition": str,                                      # "chain by hostname"
        }

    Raises a `HosYamlError` subclass on any structural problem. Each
    subclass carries a `reason` slug used by the broadcast handler for
    metric labeling.
    """
    try:
        doc = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        raise MalformedYamlError(f"yaml parse failed: {exc}") from exc

    if not isinstance(doc, dict):
        raise MalformedYamlError(f"expected mapping at root, got {type(doc).__name__}")

    detection = doc.get("detection")
    if not isinstance(detection, dict):
        raise MissingDetectionError("`detection` block missing or not a mapping")

    seqs = _extract_seqs(detection)
    if not seqs:
        raise EmptySeqsError("`detection` has no seqN keys with rule_ids")

    timeframe_s = _parse_timeframe(detection.get("timeframe"))
    condition = _normalize_condition(detection.get("condition"))

    return {
        "seqs": seqs,
        "timeframe_seconds": timeframe_s,
        "condition": condition,
    }


def _extract_seqs(detection: dict) -> list[dict]:
    """Walk the detection block, pull `seqN` entries with their rule_ids,
    return sorted by seq number. Missing/empty rule_ids skip the entry —
    the EmptySeqsError check at the call site catches the all-empty case."""
    out: list[dict] = []
    for key, body in detection.items():
        m = _SEQ_KEY_RE.match(str(key))
        if not m:
            continue
        if not isinstance(body, dict):
            continue
        rule_ids = body.get("ruleid|contains")
        if not isinstance(rule_ids, list) or not rule_ids:
            continue
        # Coerce to strings, drop empties — defensive against odd YAML.
        cleaned = [str(r).strip() for r in rule_ids if str(r).strip()]
        if not cleaned:
            continue
        out.append({"seq": int(m.group(1)), "rule_ids": cleaned})
    out.sort(key=lambda s: s["seq"])
    return out


def _parse_timeframe(raw) -> int:
    """Accept `Ns|Nm|Nh|Nd` strings or bare ints. Returns seconds, > 0."""
    if raw is None:
        raise InvalidTimeframeError("`detection.timeframe` is required")
    if isinstance(raw, bool):  # bool is an int subclass — be explicit
        raise InvalidTimeframeError(f"timeframe must be a duration, got bool {raw!r}")
    if isinstance(raw, int):
        if raw <= 0:
            raise InvalidTimeframeError(f"timeframe must be > 0, got {raw}")
        return raw
    if not isinstance(raw, str):
        raise InvalidTimeframeError(
            f"timeframe must be a duration string or int, got {type(raw).__name__}"
        )
    m = _DURATION_RE.match(raw)
    if not m:
        raise InvalidTimeframeError(f"unparseable timeframe: {raw!r}")
    value = int(m.group(1))
    unit = m.group(2).lower()
    seconds = value * _DURATION_UNIT_S[unit]
    if seconds <= 0:
        raise InvalidTimeframeError(f"timeframe resolves to {seconds}s, must be > 0")
    return seconds


def _normalize_condition(raw) -> str:
    """Validate and collapse whitespace in the condition string; raise ``UnsupportedConditionError`` on mismatch."""
    if not isinstance(raw, str) or not raw.strip():
        raise UnsupportedConditionError("`detection.condition` is required")
    collapsed = " ".join(raw.split())
    if collapsed != _REQUIRED_CONDITION:
        raise UnsupportedConditionError(f"only `{_REQUIRED_CONDITION}` is supported, got {raw!r}")
    return collapsed
