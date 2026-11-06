"""`normalize_topics` — one source, many topics, fixed job-graph arity.

The correlation job used to build one `KafkaSource` per input topic and union
them, so the operator count tracked the correlation pipeline's member count and
every membership edit changed the topology (and therefore every auto-generated
operator id). `KafkaSourceBuilder.set_topics` is varargs, so a single source can
hold the whole member list — this helper is the normalisation in front of it.

Deduping is not cosmetic: a repeated topic would be consumed twice by one
source, double-counting every event towards chain coverage.
"""

from __future__ import annotations

import pytest

from app.connectors.kafka_source import normalize_topics


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("a", ["a"]),
        (["a", "b"], ["a", "b"]),
        (("a",), ["a"]),
        (["a", "a", "b"], ["a", "b"]),  # dedup, order preserved
        (["b", "a", "b"], ["b", "a"]),  # first occurrence wins
        ([" a ", ""], ["a"]),  # strip + drop empties
        ("  a  ", ["a"]),
    ],
)
def test_normalize_topics_returns_deduped_ordered_list(
    raw: str | list[str], expected: list[str]
) -> None:
    assert normalize_topics(raw) == expected


@pytest.mark.parametrize("raw", [[], "", ["  "], ["", " "], ()])
def test_normalize_topics_rejects_empty(raw: str | list[str]) -> None:
    """An empty subscription must fail loudly at graph-build time — a source with
    no topics silently produces nothing forever."""
    with pytest.raises(ValueError, match="at least one non-empty topic"):
        normalize_topics(raw)
