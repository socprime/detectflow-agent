"""Consumer-group id = `{kafka_consumer_group}-{job_id}{suffix}`.

This formula is the whole of a correlation pipeline's Kafka offset/lag
separation, and it is load-bearing only because `job_id` is distinct per
deployment. Two instances sharing a job id commit to the SAME group — which
matters most for agent-job, whose source starts from `committed` offsets, so a
twin's commits make a stateless redeploy skip chains or re-read them through a
paid LLM. That is what `assert_distinct_job_identity` guards, so the formula is
pinned here.

NB the group id does NOT drive partition assignment: Flink's KafkaSource
(FLIP-27) assigns splits from the JobManager enumerator and only stores offsets
under the group. Verified on a live cluster — an actively-consuming
job's group reports STATE=Empty / #MEMBERS=0 while its source read every record.
So same-id instances duplicate work and clobber offsets; none goes idle.

The suffix is keyed by ROLE (`-correlation`, `-correlation-meta-<role>`), never
by topic name: one fixed-arity source covers every member topic, and meta topic
names become per-pipeline, so a topic-derived group id
would orphan committed offsets on every rename.

`normalize_topics` coverage lives in `test_kafka_source_topics.py` — not here.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from app.config.settings import Settings

MAIN_SUFFIX = "-correlation"
META_SUFFIXES = (
    "-correlation-meta-active_threats",
    "-correlation-meta-hos_rules",
    "-correlation-meta-chains_config",
)
AGENT_SUFFIX = "-agent"


def _settings(**overrides) -> Settings:
    base = {
        "kafka_bootstrap_servers": "dummy",
        "kafka_auth_method": "PLAINTEXT",
    }
    base.update(overrides)
    return Settings(**base)


def _group_id_for(settings: Settings, topics, suffix: str) -> str:
    """Build a source with the JVM seams patched out; return the group id set."""
    from app.connectors.kafka_source import create_kafka_source

    builder = MagicMock()
    with (
        patch("app.connectors.kafka_source.KafkaSource") as mock_source_cls,
        patch("app.connectors.kafka_source.KafkaOffsetsInitializer"),
        patch("app.connectors.kafka_source.SimpleStringSchema"),
    ):
        mock_source_cls.builder.return_value = builder
        create_kafka_source(settings, topics, consumer_group_suffix=suffix)

    builder.set_group_id.assert_called_once()
    return builder.set_group_id.call_args.args[0]


# ---------------------------------------------------------------------------
# The formula
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("suffix", (MAIN_SUFFIX, *META_SUFFIXES, AGENT_SUFFIX))
def test_group_id_is_prefix_job_id_suffix(suffix: str):
    settings = _settings(job_id="corr-3f2b8c14")
    assert settings.kafka_consumer_group == "flink-agent"
    assert _group_id_for(settings, "t", suffix) == f"flink-agent-corr-3f2b8c14{suffix}"


def test_main_lane_group_id_is_topic_free():
    """One source over N member topics ⇒ ONE group, whose id must not move when
    the member list is edited."""
    settings = _settings(job_id="corr-a")
    one = _group_id_for(settings, ["t1"], MAIN_SUFFIX)
    many = _group_id_for(settings, ["t1", "t2", "t3"], MAIN_SUFFIX)
    assert one == many == "flink-agent-corr-a-correlation"


# ---------------------------------------------------------------------------
# Isolation: distinct job_id ⇒ distinct groups; shared job_id ⇒ collision
# ---------------------------------------------------------------------------


def test_distinct_job_ids_produce_disjoint_group_families():
    """Two correlation pipelines on one cluster, same topics, same roles."""
    a = _settings(job_id="corr-aaaa")
    b = _settings(job_id="corr-bbbb")
    topics = ["detectflow.tagged-events.p1", "detectflow.tagged-events.p2"]

    for suffix in (MAIN_SUFFIX, *META_SUFFIXES):
        assert _group_id_for(a, topics, suffix) != _group_id_for(b, topics, suffix)

    families = {_group_id_for(a, topics, s) for s in (MAIN_SUFFIX, *META_SUFFIXES)}
    families |= {_group_id_for(b, topics, s) for s in (MAIN_SUFFIX, *META_SUFFIXES)}
    assert len(families) == 8  # 4 roles × 2 instances, no overlap


def test_equal_job_ids_collide_on_the_same_group():
    """The documented hazard: same job_id ⇒ same group ⇒ both instances commit
    over each other's offsets (and are indistinguishable in lag dashboards).
    Only a distinct JOB_ID prevents it."""
    a = _settings(job_id="local")
    b = _settings(job_id="local", correlation_pipeline_id="3f2b8c14-9f6a-4c3d-8f21-2a7b5c9d1e04")
    assert _group_id_for(a, "t", MAIN_SUFFIX) == _group_id_for(b, "t", MAIN_SUFFIX)


def test_pipeline_identity_alone_does_not_scope_the_group():
    """`correlation_pipeline_id` is identity-only — it must NOT leak into the
    group id (that would silently change group ids for an existing deployment
    the moment the control plane starts injecting it)."""
    plain = _settings(job_id="corr-a")
    scoped = _settings(
        job_id="corr-a",
        correlation_pipeline_id="3f2b8c14-9f6a-4c3d-8f21-2a7b5c9d1e04",
        correlation_pipeline_name="customer-a",
    )
    assert _group_id_for(plain, "t", MAIN_SUFFIX) == _group_id_for(scoped, "t", MAIN_SUFFIX)


def test_custom_consumer_group_prefix_is_honoured():
    settings = _settings(job_id="corr-a", kafka_consumer_group="other-prefix")
    assert _group_id_for(settings, "t", MAIN_SUFFIX) == "other-prefix-corr-a-correlation"


# ---------------------------------------------------------------------------
# Offset override validation (unchanged behaviour, pinned alongside)
# ---------------------------------------------------------------------------


def test_invalid_starting_offset_override_raises():
    from app.connectors.kafka_source import create_kafka_source

    with pytest.raises(ValueError, match="starting_offset must be one of"):
        create_kafka_source(
            _settings(job_id="corr-a"),
            "t",
            consumer_group_suffix=MAIN_SUFFIX,
            starting_offset_override="newest",
        )
