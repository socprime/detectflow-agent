"""Correlation-job entrypoint wiring — starting-offset contract + job name.

These tests pin the runtime-contract invariant: the main tagged-events
source must subscribe from `latest`, while the 3 broadcast meta sources
must stay on `earliest` (compacted topics — full materialised view is
required for the inverted sigma→HoS index and AT/config state).

They also pin the per-instance Flink JOB name (`correlation-job-<label>`),
which is what tells N correlation pipelines apart in the Flink UI and in
metric scopes — while a single deployment (JOB_ID=correlation-job)
keeps the exact bare name the integration helpers grep for.

`create_kafka_source` is mock-patched so the assertions are
implementation-agnostic of PyFlink's KafkaSource builder; the
watermark strategy and broadcast descriptors are also patched out so
the test does not depend on a JVM gateway.
"""

from __future__ import annotations

from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import pytest

from app.config.settings import Settings


@pytest.fixture
def settings() -> Settings:
    return Settings(
        kafka_bootstrap_servers="dummy",
        kafka_auth_method="PLAINTEXT",
        kafka_input_topics="detectflow.tagged-events",
    )


@patch("app.jobs.correlation.__main__._correlation_watermark_strategy")
@patch("app.jobs.correlation.__main__.create_kafka_source")
def test_main_stream_subscribes_from_latest(
    mock_create_source: MagicMock,
    mock_watermark: MagicMock,
    settings: Settings,
) -> None:
    from app.jobs.correlation.__main__ import _build_main_stream

    mock_create_source.return_value = MagicMock()
    mock_watermark.return_value = MagicMock()

    _build_main_stream(MagicMock(), settings)

    assert mock_create_source.call_count == 1
    for call in mock_create_source.call_args_list:
        kwargs = call.kwargs
        assert kwargs["starting_offset_override"] == "latest", (
            "tagged-events main source must subscribe from latest (runtime contract)"
        )


@patch("app.jobs.correlation.__main__._correlation_watermark_strategy")
@patch("app.jobs.correlation.__main__.create_kafka_source")
def test_main_stream_is_one_source_for_many_topics(
    mock_create_source: MagicMock,
    mock_watermark: MagicMock,
) -> None:
    """N member topics → ONE KafkaSource, still `latest`, one consumer group.

    Arity is a state contract: one source per topic would make the job graph a
    function of the correlation pipeline's member count, so a membership edit
    would change every auto-generated operator id."""
    from app.jobs.correlation.__main__ import _build_main_stream

    mock_create_source.return_value = MagicMock()
    mock_watermark.return_value = MagicMock()

    multi = Settings(
        kafka_bootstrap_servers="dummy",
        kafka_auth_method="PLAINTEXT",
        kafka_input_topics="a,b,c",
    )
    _build_main_stream(MagicMock(), multi)

    assert mock_create_source.call_count == 1, (
        "the main lane must stay one fixed-arity source regardless of member count"
    )
    call = mock_create_source.call_args
    assert call.args[1] == ["a", "b", "c"]
    assert call.kwargs["starting_offset_override"] == "latest"
    assert call.kwargs["consumer_group_suffix"] == "-correlation", (
        "the suffix must not embed a topic name — one source, one group"
    )


@patch("app.jobs.correlation.__main__.WatermarkStrategy")
@patch("app.jobs.correlation.__main__.ALL_BROADCAST_DESCRIPTORS", ())
@patch("app.jobs.correlation.__main__.ByteArraySchema")
@patch("app.jobs.correlation.__main__.create_kafka_source")
def test_broadcast_streams_subscribe_from_earliest(
    mock_create_source: MagicMock,
    mock_byte_array_schema: MagicMock,
    mock_watermark: MagicMock,
    settings: Settings,
) -> None:
    from app.jobs.correlation.__main__ import _build_broadcast_stream

    mock_create_source.return_value = MagicMock()

    _build_broadcast_stream(MagicMock(), settings)

    expected_lanes = {
        "active_threats": settings.kafka_active_threats_topic,
        "hos_rules": settings.kafka_hos_rules_topic,
        "chains_config": settings.kafka_chains_config_topic,
    }
    assert mock_create_source.call_count == 3

    seen_topics: set[str] = set()
    seen_suffixes: set[str] = set()
    for call in mock_create_source.call_args_list:
        args, kwargs = call.args, call.kwargs
        topic = args[1] if len(args) >= 2 else kwargs["topics"]
        seen_topics.add(topic)
        seen_suffixes.add(kwargs["consumer_group_suffix"])
        assert kwargs["starting_offset_override"] == "earliest", (
            f"broadcast meta source {topic!r} must subscribe from earliest "
            "(compacted topics — full materialised view required)"
        )

    assert seen_topics == set(expected_lanes.values())
    # Suffixes are keyed by ROLE, not by topic name: meta topic names become
    # per-correlation-pipeline, and a group id that
    # moved with the topic name would orphan committed offsets on every rename.
    assert seen_suffixes == {f"-correlation-meta-{role}" for role in expected_lanes}


# ---------------------------------------------------------------------------
# Per-instance Flink JOB name
# ---------------------------------------------------------------------------


def _run_correlation(settings: Settings) -> tuple[MagicMock, MagicMock]:
    """Drive `run()` with every JVM/Kafka seam patched; return (env, conf)."""
    from app.jobs.correlation import __main__ as correlation_main

    env = MagicMock()
    conf = MagicMock()
    with ExitStack() as stack:
        for target in (
            "ensure_pythonpath_for_workers",
            "configure_flink_environment",
            "build_pipeline",
            "get_activity_reporter",
        ):
            stack.enter_context(patch.object(correlation_main, target))
        stack.enter_context(patch.object(correlation_main, "get_settings", return_value=settings))
        stack.enter_context(patch.object(correlation_main, "Configuration", return_value=conf))
        stack.enter_context(
            patch.object(
                correlation_main,
                "StreamExecutionEnvironment",
                **{"get_execution_environment.return_value": env},
            )
        )
        correlation_main.run(input_topics=["t"], job_id=settings.job_id)
    return env, conf


def test_run_executes_with_per_instance_job_name():
    """A pipeline-scoped instance gets a suffixed JOB name — operator uids and
    names stay frozen (they address on-disk state); only the job name moves."""
    settings = Settings(
        kafka_bootstrap_servers="dummy",
        kafka_auth_method="PLAINTEXT",
        kafka_input_topics="t",
        job_id="corr-3f2b8c14",
        correlation_pipeline_name="customer-a",
    )
    env, conf = _run_correlation(settings)

    env.execute.assert_called_once_with("correlation-job-customer-a")
    # Also mirrored into pipeline.name so a future execute_async path cannot
    # regress the name (the explicit execute() argument still wins).
    assert ("pipeline.name", "correlation-job-customer-a") in {
        call.args for call in conf.set_string.call_args_list
    }


def test_run_keeps_the_bare_job_name_for_the_legacy_deployment():
    """JOB_ID=correlation-job with no pipeline vars — the name the integration
    helper matches on must not change."""
    settings = Settings(
        kafka_bootstrap_servers="dummy",
        kafka_auth_method="PLAINTEXT",
        kafka_input_topics="t",
        job_id="correlation-job",
    )
    env, _conf = _run_correlation(settings)

    env.execute.assert_called_once_with("correlation-job")


def test_run_job_name_stays_substring_matchable():
    """tests/integration/conftest.py locates the job
    with a `contains("correlation")` filter."""
    settings = Settings(
        kafka_bootstrap_servers="dummy",
        kafka_auth_method="PLAINTEXT",
        kafka_input_topics="t",
        job_id="sandbox-correlation",
    )
    env, _conf = _run_correlation(settings)

    (job_name,) = env.execute.call_args.args
    assert job_name == "correlation-job-sandbox-correlation"
    assert "correlation" in job_name


def test_run_refuses_default_job_id_when_pipeline_scoped():
    """The startup guard fires before any Kafka source is built: a
    pipeline-scoped instance still on JOB_ID=local would share consumer groups,
    txn-id prefixes and its activity entity_id with the next one."""
    from app.config.settings import JobIdentityError

    settings = Settings(
        kafka_bootstrap_servers="dummy",
        kafka_auth_method="PLAINTEXT",
        kafka_input_topics="t",
        job_id="local",
        correlation_pipeline_id="3f2b8c14-9f6a-4c3d-8f21-2a7b5c9d1e04",
    )
    with pytest.raises(JobIdentityError):
        _run_correlation(settings)
