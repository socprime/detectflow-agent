"""Per-instance job identity — job names, the label, and the startup guard.

Under the per-customer correlation-pipeline model one
image runs as N job pairs on one Kafka cluster. Two things have to hold:

1. Every instance must be *tellable apart* — in the Flink UI, in metric scopes
   and in the activity feed — without renaming any operator (operator uids are
   frozen state handles; see app/core/operator_uids.py).
2. Two instances must never share a `job_id`. It scopes consumer groups
   (`{kafka_consumer_group}-{job_id}{suffix}`), EOS transactional-id prefixes
   and the activity `entity_id` all at once. The sharpest consequence is
   agent-job's source starting from `committed` offsets: a twin committing to
   the same group makes a stateless redeploy skip chains or re-read them
   through a paid LLM. Hence a fail-fast guard rather than a log line.
   (It is NOT partition stealing — Flink's KafkaSource assigns splits from the
   JM enumerator and never joins the group; see the guard's docstring.)

`JOB_ID` (the K8s deployment name, `corr-<uuid>`) and `CORRELATION_PIPELINE_ID`
(the bare `correlation_pipelines.id` UUID) are two different values. Conflating
them makes the control plane discard chain records, because it parses the
envelope's `correlation_pipeline_id` as a UUID.
"""

from __future__ import annotations

import pytest

from app.config.settings import (
    DEFAULT_JOB_ID,
    JobIdentityError,
    Settings,
    assert_distinct_job_identity,
)

PIPELINE_UUID = "3f2b8c14-9f6a-4c3d-8f21-2a7b5c9d1e04"
DEPLOYMENT_NAME = f"corr-{PIPELINE_UUID}"


def _settings(**overrides) -> Settings:
    base = {
        "kafka_bootstrap_servers": "dummy",
        "kafka_auth_method": "PLAINTEXT",
    }
    base.update(overrides)
    return Settings(**base)


# ---------------------------------------------------------------------------
# flink_job_name / instance_label
# ---------------------------------------------------------------------------


def test_legacy_deployment_keeps_the_bare_job_name():
    """JOB_ID=correlation-job (today's deployment name) must produce EXACTLY
    `correlation-job` — tests/integration/conftest.py
    matches on that name, and the deployment that exists today must not change."""
    settings = _settings(job_id="correlation-job")
    assert settings.flink_job_name("correlation-job") == "correlation-job"
    assert _settings(job_id="agent-job").flink_job_name("agent-job") == "agent-job"


def test_empty_label_returns_the_base():
    settings = _settings(job_id="")
    assert settings.instance_label() == ""
    assert settings.flink_job_name("correlation-job") == "correlation-job"


def test_pipeline_name_wins_over_id_and_job_id():
    settings = _settings(
        job_id=DEPLOYMENT_NAME,
        correlation_pipeline_id=PIPELINE_UUID,
        correlation_pipeline_name="customer-a",
    )
    assert settings.instance_label() == "customer-a"
    assert settings.flink_job_name("correlation-job") == "correlation-job-customer-a"
    assert settings.flink_job_name("agent-job") == "agent-job-customer-a"


def test_pipeline_id_used_when_name_absent():
    settings = _settings(job_id=DEPLOYMENT_NAME, correlation_pipeline_id=PIPELINE_UUID)
    assert settings.instance_label() == PIPELINE_UUID
    assert settings.flink_job_name("correlation-job") == f"correlation-job-{PIPELINE_UUID}"


def test_job_id_is_the_last_resort_label():
    """The integration compose files set only JOB_ID — the label must
    still separate those instances (e.g. `correlation-job-sandbox-correlation`)."""
    settings = _settings(job_id="sandbox-correlation")
    assert settings.flink_job_name("correlation-job") == "correlation-job-sandbox-correlation"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("Customer A", "Customer-A"),
        ("cust/omer", "cust-omer"),
        ("a  b", "a-b"),
        ("  padded  ", "padded"),
        ("[bracketed]", "bracketed"),
        ("emoji🙂here", "emoji-here"),
        ("__weird__", "__weird__"),  # `_` and `.` ARE in the safe alphabet
        ("v1.2", "v1.2"),
        ("--edges--", "edges"),  # leading/trailing separators trimmed
    ],
)
def test_label_is_sanitised_to_a_token_safe_alphabet(name: str, expected: str):
    """Flink folds the job name into the metric scope path, and reporters mangle
    non-alphanumerics differently — so the label is reduced to [A-Za-z0-9._-]."""
    settings = _settings(job_id="corr-x", correlation_pipeline_name=name)
    assert settings.instance_label() == expected


def test_label_equal_to_base_is_not_duplicated():
    settings = _settings(job_id="x", correlation_pipeline_name="correlation-job")
    assert settings.flink_job_name("correlation-job") == "correlation-job"


# ---------------------------------------------------------------------------
# JOB_ID vs CORRELATION_PIPELINE_ID — two distinct values
# ---------------------------------------------------------------------------


def test_deployment_name_and_pipeline_uuid_stay_distinct(monkeypatch):
    """Nothing derives one from the other. The control plane parses the chain
    envelope's `correlation_pipeline_id` as a UUID, so a `corr-<uuid>` value
    there fails validation and the record is dropped."""
    monkeypatch.setenv("JOB_ID", DEPLOYMENT_NAME)
    monkeypatch.setenv("CORRELATION_PIPELINE_ID", PIPELINE_UUID)
    settings = _settings()

    assert settings.job_id == DEPLOYMENT_NAME
    assert settings.correlation_pipeline_id == PIPELINE_UUID
    assert settings.job_id != settings.correlation_pipeline_id
    assert not settings.job_id.startswith(settings.correlation_pipeline_id)


def test_pipeline_id_is_never_populated_from_job_id(monkeypatch):
    """A deployment name alone leaves the pipeline id None — no prefix
    stripping, no fallback. `None` means the legacy single-instance deploy."""
    monkeypatch.delenv("CORRELATION_PIPELINE_ID", raising=False)
    monkeypatch.setenv("JOB_ID", DEPLOYMENT_NAME)
    settings = _settings()

    assert settings.correlation_pipeline_id is None
    assert settings.correlation_pipeline_name is None


# ---------------------------------------------------------------------------
# assert_distinct_job_identity
# ---------------------------------------------------------------------------


def test_guard_raises_on_default_job_id_when_pipeline_scoped():
    settings = _settings(job_id=DEFAULT_JOB_ID, correlation_pipeline_id=PIPELINE_UUID)
    with pytest.raises(JobIdentityError, match="still the default"):
        assert_distinct_job_identity(settings)


def test_guard_raises_when_only_the_pipeline_name_is_set():
    settings = _settings(job_id=DEFAULT_JOB_ID, correlation_pipeline_name="customer-a")
    with pytest.raises(JobIdentityError):
        assert_distinct_job_identity(settings)


def test_guard_only_warns_on_default_job_id_without_pipeline_vars():
    """Local dev ships JOB_ID=local (.env.example) — the guard
    must not turn that into a startup failure."""
    assert_distinct_job_identity(_settings(job_id=DEFAULT_JOB_ID))


def test_guard_honours_the_allow_default_escape_hatch():
    settings = _settings(
        job_id=DEFAULT_JOB_ID,
        correlation_pipeline_id=PIPELINE_UUID,
        allow_default_job_id=True,
    )
    assert_distinct_job_identity(settings)


@pytest.mark.parametrize("job_id", ["", "   ", "a b", "a/b", "a:b", "grüße"])
def test_guard_rejects_unsafe_job_ids(job_id: str):
    """job_id becomes a Kafka group id and an EOS transactional-id prefix."""
    with pytest.raises(JobIdentityError, match="unsafe"):
        assert_distinct_job_identity(_settings(job_id=job_id))


@pytest.mark.parametrize("job_id", [DEPLOYMENT_NAME, "correlation-job", "a.b_", "A-1.2"])
def test_guard_accepts_safe_job_ids(job_id: str):
    assert_distinct_job_identity(_settings(job_id=job_id))


def test_guard_warns_but_passes_when_cli_job_id_diverges_from_env(monkeypatch):
    """`run()` assigns settings.job_id from --job-id on the DRIVER only; workers
    rebuild Settings() from the environment. A CLI-only job id therefore never
    reaches a worker — loud, but not fatal (the driver may legitimately be
    started by hand)."""
    monkeypatch.setenv("JOB_ID", "env-value")
    settings = _settings(job_id="cli-value")
    assert_distinct_job_identity(settings)


def test_guard_does_not_mutate_settings():
    settings = _settings(job_id=DEPLOYMENT_NAME, correlation_pipeline_id=PIPELINE_UUID)
    assert_distinct_job_identity(settings)
    assert settings.job_id == DEPLOYMENT_NAME
    assert settings.correlation_pipeline_id == PIPELINE_UUID
