"""parse_hos_yaml — structural parse + matcher-relevant validation.

The negative cases mirror the upstream HoS validation where they
overlap with what the matcher must self-defend against (timeframe,
condition, seqs presence). Cases like `level` enum and `tags` shape are
upstream concerns and intentionally NOT covered here.
"""

from __future__ import annotations

import pytest

from app.operators.hos_yaml import (
    EmptySeqsError,
    InvalidTimeframeError,
    MalformedYamlError,
    MissingDetectionError,
    UnsupportedConditionError,
    parse_hos_yaml,
)

APT28_YAML = """
title: APT28 Sample Chain
id: 40500000-0000-4000-8000-000000000028
status: stable
tags:
  - attack.T1203
  - active_threat.a7000000-0000-4000-8000-000000000028
logsource:
  category: detectflow
detection:
  seq1:
    ruleid|contains:
      - '5e000002-0000-4000-8000-000000000002'
      - '5e000003-0000-4000-8000-000000000003'
  seq2:
    ruleid|contains:
      - '5e000004-0000-4000-8000-000000000004'
  seq3:
    ruleid|contains:
      - '5e000006-0000-4000-8000-000000000006'
  timeframe: 30m
  condition: chain by hostname
level: high
"""


# ---------------------------------------------------------------------------
# Positive
# ---------------------------------------------------------------------------


def test_apt28_positive_parses_to_expected_internal_shape():
    body = parse_hos_yaml(APT28_YAML)
    assert body["timeframe_seconds"] == 1800
    assert body["condition"] == "chain by hostname"
    assert [s["seq"] for s in body["seqs"]] == [1, 2, 3]
    assert body["seqs"][0]["rule_ids"] == [
        "5e000002-0000-4000-8000-000000000002",
        "5e000003-0000-4000-8000-000000000003",
    ]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("60s", 60),
        ("60", 60),
        (60, 60),
        ("5m", 300),
        ("1h", 3600),
        ("2d", 172800),
        ("  30m  ", 1800),  # whitespace tolerated
        ("30M", 1800),  # case-insensitive unit
    ],
)
def test_timeframe_accepts_duration_shorthand_and_bare_seconds(raw, expected):
    yaml_text = APT28_YAML.replace("timeframe: 30m", f"timeframe: {raw!s}")
    body = parse_hos_yaml(yaml_text)
    assert body["timeframe_seconds"] == expected


def test_seqs_are_sorted_by_number_regardless_of_yaml_order():
    yaml_text = """
detection:
  seq3:
    ruleid|contains: ['c']
  seq1:
    ruleid|contains: ['a']
  seq2:
    ruleid|contains: ['b']
  timeframe: 60s
  condition: chain by hostname
"""
    body = parse_hos_yaml(yaml_text)
    assert [s["seq"] for s in body["seqs"]] == [1, 2, 3]
    assert [s["rule_ids"] for s in body["seqs"]] == [["a"], ["b"], ["c"]]


def test_condition_whitespace_collapsed():
    yaml_text = APT28_YAML.replace(
        "condition: chain by hostname", "condition: 'chain   by  hostname'"
    )
    body = parse_hos_yaml(yaml_text)
    assert body["condition"] == "chain by hostname"


# ---------------------------------------------------------------------------
# Negative — MalformedYaml / MissingDetection / EmptySeqs / InvalidTimeframe
#   / UnsupportedCondition
# ---------------------------------------------------------------------------


def test_unparseable_yaml_raises_malformed():
    with pytest.raises(MalformedYamlError):
        parse_hos_yaml(":\n  - this is not\n: : valid yaml")


def test_root_not_a_mapping_raises_malformed():
    with pytest.raises(MalformedYamlError):
        parse_hos_yaml("- just\n- a\n- list\n")


def test_missing_detection_block_raises():
    with pytest.raises(MissingDetectionError):
        parse_hos_yaml("title: t\nid: x\nlevel: high\n")


def test_detection_present_but_no_seqN_keys_raises_empty_seqs():
    yaml_text = """
detection:
  timeframe: 30m
  condition: chain by hostname
"""
    with pytest.raises(EmptySeqsError):
        parse_hos_yaml(yaml_text)


def test_detection_seqN_with_empty_rule_ids_treated_as_empty_seqs():
    yaml_text = """
detection:
  seq1:
    ruleid|contains: []
  timeframe: 30m
  condition: chain by hostname
"""
    with pytest.raises(EmptySeqsError):
        parse_hos_yaml(yaml_text)


@pytest.mark.parametrize("bad", ["forever", "30x", "", "  ", "-30m", None, True, False, [], {}])
def test_invalid_timeframe_raises(bad):
    yaml_text = APT28_YAML.replace(
        "timeframe: 30m", f"timeframe: {bad!r}" if bad is not None else ""
    )
    if bad is None:
        # remove the timeframe line entirely
        yaml_text = "\n".join(line for line in APT28_YAML.splitlines() if "timeframe:" not in line)
    with pytest.raises(InvalidTimeframeError):
        parse_hos_yaml(yaml_text)


@pytest.mark.parametrize("bad", [0, -1, -3600])
def test_non_positive_timeframe_raises(bad):
    """Non-positive timeframes are rejected by the parser, so the broadcast
    handler rejects them via the parser's exception."""
    yaml_text = APT28_YAML.replace("timeframe: 30m", f"timeframe: {bad}")
    with pytest.raises(InvalidTimeframeError):
        parse_hos_yaml(yaml_text)


@pytest.mark.parametrize(
    "bad",
    [
        "chain by username",
        "chain by user",
        "count() > 5",
        "",
        "   ",
    ],
)
def test_unsupported_condition_raises(bad):
    yaml_text = APT28_YAML.replace("condition: chain by hostname", f"condition: '{bad}'")
    with pytest.raises(UnsupportedConditionError):
        parse_hos_yaml(yaml_text)


def test_missing_condition_raises_unsupported():
    yaml_text = "\n".join(line for line in APT28_YAML.splitlines() if "condition:" not in line)
    with pytest.raises(UnsupportedConditionError):
        parse_hos_yaml(yaml_text)


# ---------------------------------------------------------------------------
# Reason slugs are stable — the broadcast handler labels metrics by them
# ---------------------------------------------------------------------------


def test_exception_reasons_are_the_documented_slugs():
    assert MalformedYamlError().reason == "invalid_yaml"
    assert MissingDetectionError().reason == "missing_detection"
    assert EmptySeqsError().reason == "empty_seqs"
    assert InvalidTimeframeError().reason == "invalid_timeframe"
    assert UnsupportedConditionError().reason == "unsupported_condition"
