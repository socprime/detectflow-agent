"""Anchor tests for deterministic chain_id derivation."""

import uuid

import pytest

from app.core.chain_id import build_chain_id, format_window_start

HOS_ID = "40500000-0000-4000-8000-000000000028"
HOSTNAME = "WKST-FIN-05"
WINDOW_START_ISO = "2026-04-22T09:30:00Z"
PIPELINE_A = "3f2b8c14-9f6a-4c3d-8f21-2a7b5c9d1e04"
PIPELINE_B = "8c41d0f7-6b52-4e19-a3d7-1f5c8e2b90a6"


def test_chain_id_is_deterministic():
    a = build_chain_id(uuid.NAMESPACE_DNS, HOS_ID, HOSTNAME, WINDOW_START_ISO)
    b = build_chain_id(uuid.NAMESPACE_DNS, HOS_ID, HOSTNAME, WINDOW_START_ISO)
    assert a == b


def test_chain_id_matches_fixture_inputs():
    """Lock the namespace + format. If this changes, fixtures must update."""
    chain_id = build_chain_id(uuid.NAMESPACE_DNS, HOS_ID, HOSTNAME, WINDOW_START_ISO)
    assert chain_id == "6966fa87-8a76-5910-b216-61ffb99ec038"


def test_chain_id_accepts_namespace_as_string():
    """Settings stores namespace as string — both forms must agree."""
    from_str = build_chain_id(str(uuid.NAMESPACE_DNS), HOS_ID, HOSTNAME, WINDOW_START_ISO)
    from_uuid = build_chain_id(uuid.NAMESPACE_DNS, HOS_ID, HOSTNAME, WINDOW_START_ISO)
    assert from_str == from_uuid


@pytest.mark.parametrize(
    "field_idx,changed_inputs",
    [
        (0, ("99999999-9999-9999-9999-999999999999", HOSTNAME, WINDOW_START_ISO, PIPELINE_A)),
        (1, (HOS_ID, "OTHER-HOST", WINDOW_START_ISO, PIPELINE_A)),
        (2, (HOS_ID, HOSTNAME, "2026-04-22T09:35:00Z", PIPELINE_A)),
        (3, (HOS_ID, HOSTNAME, WINDOW_START_ISO, PIPELINE_B)),
    ],
)
def test_chain_id_changes_when_any_input_changes(field_idx, changed_inputs):
    base = build_chain_id(uuid.NAMESPACE_DNS, HOS_ID, HOSTNAME, WINDOW_START_ISO, PIPELINE_A)
    other = build_chain_id(uuid.NAMESPACE_DNS, *changed_inputs)
    assert base != other, f"chain_id collapsed when input #{field_idx} changed"


def test_chain_id_is_scoped_by_correlation_pipeline():
    """The collision this scoping exists to prevent: two MSSP customers
    each own a host named `WKST-FIN-05` and share the same catalogue HoS rule.
    Under an unscoped 3-part seed both would mint the SAME id, so one customer's
    chain overwrote (or revision-guarded away) the other's."""
    a = build_chain_id(uuid.NAMESPACE_DNS, HOS_ID, HOSTNAME, WINDOW_START_ISO, PIPELINE_A)
    b = build_chain_id(uuid.NAMESPACE_DNS, HOS_ID, HOSTNAME, WINDOW_START_ISO, PIPELINE_B)
    assert a != b
    # Still deterministic within a pipeline.
    assert a == build_chain_id(uuid.NAMESPACE_DNS, HOS_ID, HOSTNAME, WINDOW_START_ISO, PIPELINE_A)


def test_chain_id_without_pipeline_id_matches_legacy_literal():
    """The legacy single-instance deployment has no CORRELATION_PIPELINE_ID.
    Its ids MUST stay byte-identical across the upgrade, so the fallback is the
    3-part seed — this is the value pinned for it."""
    assert (
        build_chain_id(uuid.NAMESPACE_DNS, HOS_ID, HOSTNAME, WINDOW_START_ISO)
        == "6966fa87-8a76-5910-b216-61ffb99ec038"
    )


@pytest.mark.parametrize("absent", [None, ""])
def test_chain_id_empty_pipeline_id_is_treated_as_absent(absent):
    """An empty string is not a pipeline — it must not scope the id (and must
    not produce a third, leading-`|` variant of the seed)."""
    assert build_chain_id(
        uuid.NAMESPACE_DNS, HOS_ID, HOSTNAME, WINDOW_START_ISO, absent
    ) == build_chain_id(uuid.NAMESPACE_DNS, HOS_ID, HOSTNAME, WINDOW_START_ISO)


def test_chain_id_namespace_stays_global_across_pipelines():
    """Cross-repo invariant 10: scoping lives in the seed string, NEVER in a
    per-pipeline namespace. Same namespace + same pipeline ⇒ same id."""
    from_str = build_chain_id(
        str(uuid.NAMESPACE_DNS), HOS_ID, HOSTNAME, WINDOW_START_ISO, PIPELINE_A
    )
    from_uuid = build_chain_id(uuid.NAMESPACE_DNS, HOS_ID, HOSTNAME, WINDOW_START_ISO, PIPELINE_A)
    assert from_str == from_uuid


def test_format_window_start_is_utc_z_suffixed():
    # 2026-04-22T09:30:00Z = 1776850200
    assert format_window_start(1776850200) == "2026-04-22T09:30:00Z"


def test_format_window_start_round_trips_through_chain_id():
    """The output of format_window_start MUST be the canonical input
    consumed by build_chain_id — otherwise determinism breaks across
    producers that derive the ISO string differently."""
    iso = format_window_start(1776850200)
    expected = build_chain_id(uuid.NAMESPACE_DNS, HOS_ID, HOSTNAME, WINDOW_START_ISO)
    actual = build_chain_id(uuid.NAMESPACE_DNS, HOS_ID, HOSTNAME, iso)
    assert actual == expected
