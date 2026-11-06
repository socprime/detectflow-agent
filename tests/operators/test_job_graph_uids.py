"""Job-graph stability — every addressable operator carries a frozen `uid()`.

Flink derives an operator's state handle from its `uid()` when one is set and
from its **position in the job graph** when one is not. Both jobs deploy with
`upgradeMode: last-state`, so a topology change under auto-generated ids
restores into an incompatible graph: either the restore fails ("Cannot map
checkpoint state for operator <hash> to the new program") and the job
crash-loops, or someone sets `allowNonRestoredState` and the job comes up
having *silently* dropped every keyed `ChainBuffer` — while the main source is
pinned to `latest`, so the events that would rebuild them are already past.

Two things are pinned here:

1. The uid **strings** — asserted as literals, deliberately NOT imported from
   `app.core.operator_uids`, so a rename fails this test instead of quietly
   deleting on-disk state.
2. That the correlation uid set is **invariant under a membership change**
   (`test_correlation_uids_stable_across_membership_change`). That is the test
   this whole exercise exists for: adding or removing a member detection
   pipeline must not move a single operator.

No JVM. `create_kafka_source` / `create_kafka_sink` / the watermark strategies
/ `ByteArraySchema` are patched out, and the environment is a fake recorder —
`Types.STRING()` and the `MapStateDescriptor` constants are pure Python (proved
by the existing `test_correlation_main.py`, which imports the same modules).

`ByteArraySchema` has to be patched even though its only consumer
(`create_kafka_source`) already is: it is *constructed* at the call site, and
its constructor opens the py4j gateway, i.e. spawns `java`. The CI image has no
JDK, so an unpatched one turns this whole module red there while passing on any
dev box that happens to have Java installed.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.config.settings import Settings
from app.core import operator_uids

# ---------------------------------------------------------------------------
# Fake DataStream recorder
# ---------------------------------------------------------------------------


class _FakeStream:
    """DataStream stand-in: transformations return a fresh node; uid/name record."""

    _NEW_NODE = ("map", "flat_map", "union", "broadcast", "key_by", "connect", "process", "sink_to")
    _SELF = ("slot_sharing_group", "set_parallelism", "disable_chaining")

    def __init__(self, graph: _FakeGraph) -> None:
        self._graph = graph

    def uid(self, value: str) -> _FakeStream:
        self._graph.uids.append(value)
        return self

    def name(self, value: str) -> _FakeStream:
        self._graph.names.append(value)
        return self

    def __getattr__(self, item: str) -> Any:
        if item in self._NEW_NODE:
            return lambda *a, **kw: self._graph.node()
        if item in self._SELF:
            return lambda *a, **kw: self
        raise AttributeError(item)


class _FakeGraph:
    """Fake StreamExecutionEnvironment; collects every uid()/name() of one build."""

    def __init__(self) -> None:
        self.uids: list[str] = []
        self.names: list[str] = []

    def node(self) -> _FakeStream:
        return _FakeStream(self)

    def from_source(self, **kwargs: Any) -> _FakeStream:
        return self.node()


def _settings(**overrides: Any) -> Settings:
    defaults: dict[str, Any] = {
        "kafka_bootstrap_servers": "dummy",
        "kafka_auth_method": "PLAINTEXT",
        "kafka_input_topics": "detectflow.tagged-events",
    }
    return Settings(**(defaults | overrides))


def _build_correlation(graph: _FakeGraph, settings: Settings) -> MagicMock:
    """Run correlation `build_pipeline` against the fake graph; return the
    patched `create_kafka_source` mock so source arity can be asserted."""
    from app.jobs.correlation import __main__ as correlation_main

    with (
        patch.object(correlation_main, "create_kafka_source") as mock_source,
        patch.object(correlation_main, "create_kafka_sink"),
        patch.object(correlation_main, "_correlation_watermark_strategy"),
        patch.object(correlation_main, "WatermarkStrategy"),
        patch.object(correlation_main, "ByteArraySchema"),
    ):
        mock_source.return_value = MagicMock()
        correlation_main.build_pipeline(graph, settings)
    return mock_source


# ---------------------------------------------------------------------------
# Correlation-job
# ---------------------------------------------------------------------------

# Literal strings on purpose — see the module docstring. Changing a uid is a
# state deletion, so it must break a test, not just move a constant.
EXPECTED_CORRELATION_UIDS = {
    "correlation-tagged-events-source",
    "correlation-tagged-events-bridge",
    "correlation-meta-source-active-threats",
    "correlation-meta-source-hos-rules",
    "correlation-meta-source-chains-config",
    "correlation-meta-tombstone-filter-active-threats",
    "correlation-meta-tombstone-filter-hos-rules",
    "correlation-meta-tombstone-filter-chains-config",
    "correlation-meta-tag-active-threats",
    "correlation-meta-tag-hos-rules",
    "correlation-meta-tag-chains-config",
    "correlation-hos-matcher",
    "correlation-chains-raw-sink",
}

EXPECTED_AGENT_UIDS = {
    "agent-chains-raw-source",
    "agent-chain-parse-bridge",
    "agent-output-decode",
    "agent-chains-analysed-sink",
}


def test_correlation_uids_are_frozen() -> None:
    graph = _FakeGraph()
    _build_correlation(graph, _settings())

    assert set(graph.uids) == EXPECTED_CORRELATION_UIDS, (
        "correlation-job uid set drifted — these strings are a contract with "
        "on-disk Flink state; a rename deletes the state it identifies"
    )
    assert len(graph.uids) == 13


def test_correlation_uids_stable_across_membership_change() -> None:
    """THE test. A correlation pipeline gaining or losing member detection
    pipelines must not move an operator: same uids, same count, one source."""
    one = _FakeGraph()
    _build_correlation(one, _settings(kafka_input_topics="a"))

    four = _FakeGraph()
    _build_correlation(four, _settings(kafka_input_topics="a,b,c,d"))

    assert sorted(one.uids) == sorted(four.uids), (
        "the job graph changed when the member topic set changed — a "
        "`last-state` upgrade would restore into an incompatible graph"
    )


def test_correlation_uids_are_unique() -> None:
    """Flink rejects a job whose transformations share a uid."""
    graph = _FakeGraph()
    _build_correlation(graph, _settings(kafka_input_topics="a,b,c"))
    assert len(set(graph.uids)) == len(graph.uids)


@pytest.mark.parametrize(
    ("topics_csv", "expected_topics"),
    [("a", ["a"]), ("a,b,c,d", ["a", "b", "c", "d"])],
)
def test_correlation_uses_one_source_regardless_of_member_count(
    topics_csv: str, expected_topics: list[str]
) -> None:
    """One main source + 3 meta sources, whatever the member count. The old
    one-source-per-topic construction is what made the topology member-dependent."""
    graph = _FakeGraph()
    mock_source = _build_correlation(graph, _settings(kafka_input_topics=topics_csv))

    assert mock_source.call_count == 4, "expected 1 main + 3 meta KafkaSources"
    main_call = mock_source.call_args_list[0]
    assert main_call.args[1] == expected_topics, (
        "the single main source must subscribe to every member topic at once"
    )


def test_correlation_operator_names_are_topic_free() -> None:
    """The Flink UI must be comparable across correlation pipelines, whose topic
    names differ per customer."""
    graph = _FakeGraph()
    _build_correlation(graph, _settings(kafka_input_topics="dest-cust-a,dest-cust-b"))
    for label in graph.names:
        assert "dest-cust" not in label
        assert "detectflow." not in label


# ---------------------------------------------------------------------------
# Agent-job
# ---------------------------------------------------------------------------


def test_agent_uids_are_frozen() -> None:
    pytest.importorskip("flink_agents", reason="agent-job entrypoint requires flink-agents")
    from app.jobs.agent import __main__ as agent_main

    graph = _FakeGraph()
    agents_env = MagicMock()
    # from_datastream(...).apply(...).to_datastream(...) must land on a fake node
    # so the uid()/name() after it are recorded.
    agents_env.from_datastream.return_value.apply.return_value.to_datastream.return_value = (
        graph.node()
    )

    with (
        patch.object(agent_main, "create_kafka_source"),
        patch.object(agent_main, "create_kafka_sink"),
        patch.object(agent_main, "WatermarkStrategy"),
        patch.object(agent_main, "Types"),
    ):
        agent_main.build_pipeline(graph, agents_env, _settings())

    assert set(graph.uids) == EXPECTED_AGENT_UIDS
    assert len(graph.uids) == 4


# ---------------------------------------------------------------------------
# Registry invariants
# ---------------------------------------------------------------------------


def _all_registry_uids() -> list[str]:
    """Every uid the registry publishes — scanned, not hand-listed, so a new
    constant is covered by the guards below the moment it is added."""
    flat: list[str] = []
    for name, value in vars(operator_uids).items():
        if name.startswith("_") or not name.isupper() or name == "META_ROLES":
            continue
        if isinstance(value, str):
            flat.append(value)
        elif isinstance(value, dict):
            flat.extend(v for v in value.values() if isinstance(v, str))
    return flat


def test_no_uid_embeds_a_topic_or_instance_id() -> None:
    """Hard constraint: uids are keyed by ROLE only. One image must produce the
    same uids for every correlation pipeline, so no uid may carry a topic name,
    a `JOB_ID` or a `CORRELATION_PIPELINE_ID`."""
    values = _all_registry_uids()
    assert values, "registry scan found nothing — the guard would pass vacuously"
    for value in values:
        assert "." not in value, f"{value!r} looks like it embeds a topic name"
        assert not value.startswith("detectflow"), f"{value!r} embeds a topic name"


def test_registry_covers_both_jobs() -> None:
    assert EXPECTED_CORRELATION_UIDS | EXPECTED_AGENT_UIDS == set(_all_registry_uids())
