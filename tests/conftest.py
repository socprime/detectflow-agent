"""Shared test fixtures — load JSON envelopes from tests/fixtures/attack-chains."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.config.settings import Settings
from app.observability import activity as activity_mod
from app.observability.activity import ActivityReporter, reset_activity_reporter

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "attack-chains"


@pytest.fixture(autouse=True)
def _disabled_activity_reporter(monkeypatch):
    """Default EVERY test to a disabled (no-op) activity-reporter singleton.

    The job-health reporter is a per-process singleton built from env settings,
    whose default activity topic is non-empty — so any code path that calls
    ``get_activity_reporter()`` (e.g. ``analyse_chain_raw`` on the LLM
    degradation path) would otherwise open a REAL ``confluent_kafka.Producer``
    against the configured broker and leak network I/O across the unit suite.
    Pinning a disabled singleton keeps the suite broker-free; tests that need an
    enabled stub reporter monkeypatch ``_reporter`` themselves (which overrides
    this default for that test, then is restored on teardown). Test modules that
    define their own same-named autouse fixture take precedence over this one.
    """
    reset_activity_reporter()
    disabled = ActivityReporter(
        Settings(
            kafka_bootstrap_servers="dummy",
            kafka_auth_method="PLAINTEXT",
            kafka_activity_topic="",
        ),
        entity_name="test",
    )
    monkeypatch.setattr(activity_mod, "_reporter", disabled)
    yield
    reset_activity_reporter()


def _load_json(name: str) -> dict:
    return json.loads((FIXTURES_DIR / name).read_text())


def _load_jsonl(name: str) -> list[dict]:
    return [
        json.loads(line) for line in (FIXTURES_DIR / name).read_text().splitlines() if line.strip()
    ]


@pytest.fixture
def hos_envelope_apt28() -> dict:
    """Wire-shape envelope as detectflow-backend publishes on `detectflow.hos-rules`
    post-pivot — thin: id/active_threat_id/title/level/tags/... + yaml_text.
    Used by broadcast-handler tests that simulate Kafka delivery."""
    return _load_json("hos_envelope_apt28.json")


@pytest.fixture
def hos_apt28(hos_envelope_apt28) -> dict:
    """Internal HoS body — what the broadcast handler stores in
    HOS_RULES_STATE after parsing the wire envelope. Equivalent to
    `hos_body_from_envelope(hos_envelope_apt28)`. Used by downstream
    consumers (chain_record assembly, internal-shape assertions)."""
    from app.operators.hos_yaml import hos_body_from_envelope

    return hos_body_from_envelope(hos_envelope_apt28)


@pytest.fixture
def at_apt28() -> dict:
    return _load_json("at_envelope_apt28.json")


@pytest.fixture
def at_apt28_delete() -> dict:
    """Phase 1 logical-delete envelope for the APT28 AT (cross-repo
    two-phase delete pattern, mirroring sigma-rules in detectflow-matchnode)."""
    return _load_json("at_envelope_apt28_delete.json")


@pytest.fixture
def chains_config() -> dict:
    return _load_json("chains_config.json")


@pytest.fixture
def events_apt28() -> list[dict]:
    return _load_jsonl("events_apt28.jsonl")


@pytest.fixture
def chain_raw_apt28() -> dict:
    return _load_json("chain_raw_apt28_v1.json")
