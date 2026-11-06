"""Agent-job entrypoint bridge — poison-pill tolerance of ``ParseChainFlatMap``.

The chains-raw → ChainRaw flat_map bridge must NEVER raise: a raising parser
fails the Kafka source chain, Flink restarts the job, the same record is
re-read, and the job crash-loops forever. E.g. a stray
``{"_probe": "kafka-health-check"}`` record produced into chains-raw would
keep agent-job RESTARTING with zero analysed chains.

``ParseChainFlatMap`` is a rich FlatMapFunction (flat_map yields one ChainRaw
for a valid record, nothing for garbage) so drops surface as the
``records_dropped_total`` metric, not just a WARN log line.

Also covers ``validate_eos_timeouts`` (EXACTLY_ONCE transaction/checkpoint/
restart-backoff ordering) and the source wiring (committed offsets — a
stateless redeploy must not re-read the retained topic through a paid LLM).

Imported lazily inside tests — `app.jobs.agent.__main__` imports flink_agents,
which is heavyweight; skip cleanly where it is not installed.
"""

from __future__ import annotations

import json
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("flink_agents", reason="agent-job entrypoint requires flink-agents")

from app.config.settings import Settings  # noqa: E402
from app.jobs.agent.__main__ import (  # noqa: E402
    EOS_TIMEOUT_MARGIN_MS,
    MAX_RESTART_BACKOFF_MS,
    ParseChainFlatMap,
    build_pipeline,
    validate_eos_timeouts,
)
from app.operators.chain_models import ChainRaw  # noqa: E402


def _eos_settings(**overrides) -> Settings:
    return Settings(kafka_bootstrap_servers="dummy", kafka_auth_method="PLAINTEXT", **overrides)


# ---------------------------------------------------------------------------
# EOS timeout validation — txn timeout > checkpoint + restart backoff + margin
# ---------------------------------------------------------------------------


def test_validate_eos_timeouts_passes_on_default_ordering():
    """Defaults satisfy transaction.timeout.ms (600s) > agent checkpoint (180s)
    + max restart backoff (120s) + margin (60s) = 360s."""
    validate_eos_timeouts(_eos_settings())


def test_validate_eos_timeouts_raises_when_transaction_not_greater():
    """A transaction timeout <= the checkpoint timeout is a data-loss footgun —
    the EOS sink would have its transaction aborted by the broker before commit."""
    with pytest.raises(ValueError, match="EXACTLY_ONCE misconfiguration"):
        validate_eos_timeouts(
            _eos_settings(
                flink_transaction_timeout_ms=180000,
                agent_checkpoint_timeout_ms=180000,
            )
        )
    with pytest.raises(ValueError, match="must exceed"):
        validate_eos_timeouts(
            _eos_settings(
                flink_transaction_timeout_ms=120000,
                agent_checkpoint_timeout_ms=180000,
            )
        )


def test_validate_eos_timeouts_accounts_for_restart_backoff():
    """txn timeout > checkpoint timeout alone is NOT enough: a transaction
    opened just before a failure must also survive the restart backoff (during
    which nothing commits). 250s txn > 180s checkpoint but < 180+120+60=360s —
    must still be rejected."""
    with pytest.raises(ValueError, match="max restart backoff"):
        validate_eos_timeouts(
            _eos_settings(
                flink_transaction_timeout_ms=250000,
                agent_checkpoint_timeout_ms=180000,
            )
        )
    # Just above the bound passes.
    bound = 180000 + MAX_RESTART_BACKOFF_MS + EOS_TIMEOUT_MARGIN_MS
    validate_eos_timeouts(
        _eos_settings(
            flink_transaction_timeout_ms=bound + 1,
            agent_checkpoint_timeout_ms=180000,
        )
    )


# ---------------------------------------------------------------------------
# ParseChainFlatMap — poison-pill tolerance + drop metric
# ---------------------------------------------------------------------------


def _bridge() -> ParseChainFlatMap:
    fn = ParseChainFlatMap()
    # open(None) binds a stub-mode Metrics (no JVM) — the live path passes a
    # real RuntimeContext.
    fn.open(None)
    return fn


def test_parse_chain_yields_model_for_valid_record(chain_raw_apt28):
    fn = _bridge()
    out = list(fn.flat_map(json.dumps(chain_raw_apt28)))
    assert len(out) == 1
    assert isinstance(out[0], ChainRaw)
    assert out[0].chain_id == chain_raw_apt28["chain_id"]
    assert fn._metrics.get_counter("records_dropped_total") == 0


@pytest.mark.parametrize(
    "poison",
    [
        '{"_probe": "kafka-health-check"}',  # the classic stray health-check record
        "not json at all",
        "",
        "{}",
        '{"chain_id": "x"}',  # valid JSON, missing required fields
        '["a", "list"]',
    ],
)
def test_parse_chain_drops_poison_pills_without_raising(poison):
    fn = _bridge()
    assert list(fn.flat_map(poison)) == []
    assert fn._metrics.get_counter("records_dropped_total") == 1


def test_parse_chain_metric_counts_every_drop():
    """One bridge instance counts cumulatively — N poison pills → N drops."""
    fn = _bridge()
    for poison in ("garbage", "{}", '{"_probe": true}'):
        assert list(fn.flat_map(poison)) == []
    assert fn._metrics.get_counter("records_dropped_total") == 3


def test_parse_chain_usable_without_open():
    """Defensive: the constructor seeds a stub Metrics so the bridge never
    crashes if flat_map were ever invoked before open()."""
    fn = ParseChainFlatMap()
    assert list(fn.flat_map("garbage")) == []


# ---------------------------------------------------------------------------
# build_pipeline wiring — committed starting offsets
# ---------------------------------------------------------------------------


def test_build_pipeline_uses_committed_starting_offsets():
    """The chains-raw source must start from COMMITTED group offsets (with
    EARLIEST fallback for a brand-new group, handled in kafka_source.py) —
    "earliest" would re-read the whole retained topic through a paid LLM on
    every stateless redeploy."""
    settings = _eos_settings()
    with (
        patch("app.jobs.agent.__main__.create_kafka_source") as mock_source,
        patch("app.jobs.agent.__main__.create_kafka_sink"),
        # WatermarkStrategy.no_watermarks() / Types.STRING() reach into the JVM
        # gateway (needs `java`); env/agents_env are mocked, so stub the two
        # real JVM touches to keep this a pure wiring assertion.
        patch("app.jobs.agent.__main__.WatermarkStrategy"),
        patch("app.jobs.agent.__main__.Types"),
    ):
        build_pipeline(MagicMock(), MagicMock(), settings)

    mock_source.assert_called_once()
    assert mock_source.call_args.kwargs["starting_offset_override"] == "committed"


# ---------------------------------------------------------------------------
# Per-instance Flink JOB name — via pipeline.name, not execute()
# ---------------------------------------------------------------------------


def _run_agent(settings: Settings) -> list[tuple]:
    """Drive `run()` with every JVM/LLM seam patched.

    Returns the ``conf.set_string`` calls recorded AT THE MOMENT
    ``get_execution_environment(conf)`` ran — anything set after that point
    would never reach the job, so the snapshot is the ordering assertion.
    """
    from app.jobs.agent import __main__ as agent_main

    conf = MagicMock()
    at_env_build: list[tuple] = []

    def _capture(_conf):
        at_env_build.extend(call.args for call in conf.set_string.call_args_list)
        return MagicMock()

    with ExitStack() as stack:
        for target in (
            "ensure_pythonpath_for_workers",
            "configure_flink_environment",
            "build_pipeline",
            "get_activity_reporter",
            "AgentsExecutionEnvironment",
            "LlmClient",
            "Metrics",
        ):
            stack.enter_context(patch.object(agent_main, target))
        stack.enter_context(patch.object(agent_main, "get_settings", return_value=settings))
        stack.enter_context(patch.object(agent_main, "Configuration", return_value=conf))
        stack.enter_context(patch.object(agent_main.correlation_agent, "configure"))
        env_cls = stack.enter_context(patch.object(agent_main, "StreamExecutionEnvironment"))
        env_cls.get_execution_environment.side_effect = _capture
        agent_main.run(job_id=settings.job_id)
    return at_env_build


def test_run_sets_pipeline_name_config():
    """flink-agents' `agents_env.execute()` takes NO job-name argument, and
    PyFlink calls setJobName only when a name is passed — so `pipeline.name` is
    the only lever for naming this job, and it must be set BEFORE
    `get_execution_environment(conf)` reads the config."""
    settings = _eos_settings(job_id="agent-3f2b8c14", correlation_pipeline_name="customer-a")
    assert ("pipeline.name", "agent-job-customer-a") in _run_agent(settings)


def test_run_keeps_the_bare_job_name_for_the_legacy_deployment():
    """JOB_ID=agent-job with no pipeline vars — the name must not change."""
    assert ("pipeline.name", "agent-job") in _run_agent(_eos_settings(job_id="agent-job"))


def test_run_job_name_stays_substring_matchable():
    """tests/integration/conftest.py locates the job with a substring match."""
    calls = _run_agent(_eos_settings(job_id="sandbox-agent"))
    names = [value for key, value in calls if key == "pipeline.name"]
    assert names == ["agent-job-sandbox-agent"]
    assert "agent" in names[0]


def test_run_refuses_default_job_id_when_pipeline_scoped():
    """Same guard as correlation-job, and this job is the one that pays: its
    source starts from COMMITTED offsets, so a twin sharing the `-agent` group
    makes a stateless redeploy skip chains or re-read them through a paid LLM."""
    from app.config.settings import JobIdentityError

    settings = _eos_settings(
        job_id="local",
        correlation_pipeline_id="3f2b8c14-9f6a-4c3d-8f21-2a7b5c9d1e04",
    )
    with pytest.raises(JobIdentityError):
        _run_agent(settings)
