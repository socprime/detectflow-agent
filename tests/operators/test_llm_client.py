"""LlmClient tests — happy path, retry, terminal failure, throttling, metrics."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest
from pydantic import SecretStr

from app.config.settings import Settings
from app.observability.metrics import Metrics
from app.operators.llm_client import LlmClient, TokenBucket

# ---------------------------------------------------------------------------
# Fakes — minimal openai client stand-ins
# ---------------------------------------------------------------------------


@dataclass
class _FakeUsage:
    prompt_tokens: int = 100
    completion_tokens: int = 50


@dataclass
class _FakeMessage:
    content: str


@dataclass
class _FakeChoice:
    message: _FakeMessage


@dataclass
class _FakeResponse:
    choices: list[_FakeChoice]
    usage: _FakeUsage = field(default_factory=_FakeUsage)


class _FakeCompletions:
    def __init__(self, *, sequence: list[Any]):
        self._sequence = list(sequence)
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if not self._sequence:
            raise AssertionError("FakeCompletions ran out of programmed responses")
        item = self._sequence.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


class _FakeChat:
    def __init__(self, completions):
        self.completions = completions


class _FakeClient:
    def __init__(self, completions):
        self.chat = _FakeChat(completions)


# Provider-equivalent exceptions (named like openai's so the retry classifier
# treats them as transient without importing the real openai package errors).
class RateLimitError(Exception):
    pass


class APITimeoutError(Exception):
    pass


class APIConnectionError(Exception):
    pass


class InternalServerError(Exception):
    pass


class AuthenticationError(Exception):
    pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _settings(**overrides) -> Settings:
    # llm_model and flink_parallelism are pinned here (not relying on the in-code
    # defaults) because Settings() unconditionally loads .env, and any developer /
    # CI .env that sets them would otherwise override the defaults. flink_parallelism
    # matters for the rate-limit tests: the token bucket is sized
    # `llm_calls_per_minute // flink_parallelism`, so an ambient FLINK_PARALLELISM=2
    # (as in .env.example, copied to .env in CI) would halve the effective capacity
    # and break the "capacity == llm_calls_per_minute" assumption.
    base = {
        "kafka_bootstrap_servers": "localhost:9092",
        "kafka_auth_method": "PLAINTEXT",
        "llm_api_key": SecretStr("test-key"),
        "llm_model": "gpt-4o-mini",
        "llm_max_retries": 3,
        "llm_calls_per_minute": 60,
        "flink_parallelism": 1,
    }
    base.update(overrides)
    return Settings(**base)


def _client(
    *, sequence, llm_calls_per_minute=60, llm_max_retries=3
) -> tuple[LlmClient, _FakeCompletions, Metrics]:
    completions = _FakeCompletions(sequence=sequence)
    metrics = Metrics()
    settings = _settings(
        llm_calls_per_minute=llm_calls_per_minute,
        llm_max_retries=llm_max_retries,
    )
    client = LlmClient(
        settings,
        metrics,
        client_factory=lambda _s: _FakeClient(completions),
        sleep=lambda _: None,  # disable real sleep in tests
    )
    return client, completions, metrics


def _ok(content: str = '{"verdict": "TRUE"}') -> _FakeResponse:
    return _FakeResponse(choices=[_FakeChoice(message=_FakeMessage(content=content))])


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_happy_path_success_metrics_and_tokens():
    client, completions, metrics = _client(sequence=[_ok()])

    result = client.analyse("system msg", "user msg")

    assert result.ok
    assert result.text == '{"verdict": "TRUE"}'
    assert result.attempts == 1
    assert result.prompt_tokens == 100
    assert result.completion_tokens == 50

    assert metrics.get_counter("llm_calls_total", status="success") == 1
    assert metrics.get_counter("llm_tokens_total", kind="prompt") == 100
    assert metrics.get_counter("llm_tokens_total", kind="completion") == 50
    assert metrics.get_histogram("llm_latency_seconds")  # at least one sample

    # Settings flow through correctly
    assert completions.calls[0]["model"] == "gpt-4o-mini"
    assert completions.calls[0]["max_tokens"] == 2048


# ---------------------------------------------------------------------------
# Retry behaviour
# ---------------------------------------------------------------------------


def test_transient_503_retried_then_success():
    client, completions, metrics = _client(
        sequence=[InternalServerError("503"), _ok()],
        llm_max_retries=3,
    )

    result = client.analyse("s", "u")

    assert result.ok
    assert result.attempts == 2
    assert metrics.get_counter("llm_calls_total", status="success") == 1


def test_three_consecutive_503s_then_terminal_unavailable():
    client, completions, metrics = _client(
        sequence=[
            InternalServerError("boom"),
            InternalServerError("boom"),
            InternalServerError("boom"),
            InternalServerError("boom"),  # max_retries=3 → 4 attempts before terminal
        ],
        llm_max_retries=3,
    )

    result = client.analyse("s", "u")

    assert result.ok is False
    assert result.text is None
    assert result.attempts == 4
    assert result.status == "error"
    assert "InternalServerError" in (result.error or "")
    assert metrics.get_counter("llm_calls_total", status="error") == 1


def test_timeout_classified_as_timeout_status():
    client, completions, metrics = _client(
        sequence=[APITimeoutError("t")] * 4,
        llm_max_retries=3,
    )

    result = client.analyse("s", "u")

    assert result.status == "timeout"
    assert metrics.get_counter("llm_calls_total", status="timeout") == 1


def test_non_transient_error_fails_fast_without_retry():
    """Auth errors will never succeed on retry — don't waste budget."""
    client, completions, metrics = _client(
        sequence=[AuthenticationError("bad key")],
        llm_max_retries=3,
    )

    result = client.analyse("s", "u")

    assert result.ok is False
    assert result.attempts == 1  # no retry
    assert metrics.get_counter("llm_calls_total", status="error") == 1


# ---------------------------------------------------------------------------
# Throttling — local token bucket
# ---------------------------------------------------------------------------


def test_throttle_when_rate_limit_exhausted():
    client, completions, metrics = _client(
        sequence=[_ok()] * 10,
        llm_calls_per_minute=2,
    )

    # Bucket starts full at capacity=2 → 2 successes, then throttled.
    r1 = client.analyse("s", "u")
    r2 = client.analyse("s", "u")
    r3 = client.analyse("s", "u")

    assert r1.ok and r2.ok
    assert r3.ok is False
    assert r3.status == "throttled"
    assert metrics.get_counter("llm_calls_total", status="throttled") == 1
    assert metrics.get_counter("llm_calls_throttled_total") == 1


def test_throttled_call_does_not_hit_provider():
    """Provider client must NOT be invoked when locally throttled."""
    client, completions, metrics = _client(
        sequence=[_ok()],
        llm_calls_per_minute=1,
    )

    r1 = client.analyse("s", "u")
    r2 = client.analyse("s", "u")

    assert r1.ok
    assert r2.status == "throttled"
    # Provider was hit exactly once (for r1), not for the throttled r2
    assert len(completions.calls) == 1


# ---------------------------------------------------------------------------
# Bounded throttle wait — empty bucket blocks (backpressure) before degrading
# ---------------------------------------------------------------------------


def test_no_wait_when_token_available():
    """Happy path must not pay any throttle-wait latency."""
    completions = _FakeCompletions(sequence=[_ok()])
    sleeps: list[float] = []
    client = LlmClient(
        _settings(),
        Metrics(),
        client_factory=lambda _s: _FakeClient(completions),
        sleep=sleeps.append,
    )

    result = client.analyse("s", "u")

    assert result.ok
    assert sleeps == []  # token was available — zero sleep calls


def test_token_refilled_during_bounded_wait_leads_to_success():
    """Bucket empty at call time, but a token refills mid-wait → the call
    blocks briefly (intentional backpressure) and then succeeds."""
    clock = [0.0]
    sleeps: list[float] = []

    def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock[0] += seconds  # sleeping advances the bucket's clock

    completions = _FakeCompletions(sequence=[_ok()])
    client = LlmClient(
        _settings(llm_calls_per_minute=60, llm_throttle_max_wait_seconds=10.0),
        Metrics(),
        client_factory=lambda _s: _FakeClient(completions),
        sleep=fake_sleep,
    )
    # Swap in a fake-clock bucket and drain it: capacity 60 → refill 1 token/s,
    # so the first token reappears 1 s into the wait (4 × 0.25 s polls).
    client._bucket = TokenBucket(60, clock=lambda: clock[0])
    for _ in range(60):
        assert client._bucket.try_acquire()

    result = client.analyse("s", "u")

    assert result.ok
    assert sum(sleeps) == pytest.approx(1.0)  # waited exactly until the refill
    assert len(completions.calls) == 1


def test_wait_exhausted_takes_throttled_path():
    """No refill within the bounded wait → existing throttled degradation,
    after sleeping the full configured budget (not a second more)."""
    clock = [0.0]
    sleeps: list[float] = []

    def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock[0] += seconds

    completions = _FakeCompletions(sequence=[_ok()])
    metrics = Metrics()
    client = LlmClient(
        _settings(llm_calls_per_minute=60, llm_throttle_max_wait_seconds=2.0),
        metrics,
        client_factory=lambda _s: _FakeClient(completions),
        sleep=fake_sleep,
    )
    # Capacity 1 → refill 1 token per 60 s: nothing refills within the 2 s wait.
    client._bucket = TokenBucket(1, clock=lambda: clock[0])
    assert client._bucket.try_acquire()  # drain

    result = client.analyse("s", "u")

    assert result.ok is False
    assert result.status == "throttled"
    assert sum(sleeps) == pytest.approx(2.0)  # full budget, then gave up
    assert len(completions.calls) == 0  # provider never hit
    assert metrics.get_counter("llm_calls_throttled_total") == 1


def test_zero_wait_setting_restores_fail_fast_throttle():
    """llm_throttle_max_wait_seconds=0 → old behaviour: never sleep."""
    completions = _FakeCompletions(sequence=[_ok()] * 2)
    sleeps: list[float] = []
    client = LlmClient(
        _settings(llm_calls_per_minute=1, llm_throttle_max_wait_seconds=0.0),
        Metrics(),
        client_factory=lambda _s: _FakeClient(completions),
        sleep=sleeps.append,
    )

    r1 = client.analyse("s", "u")
    r2 = client.analyse("s", "u")

    assert r1.ok
    assert r2.status == "throttled"
    assert sleeps == []


# ---------------------------------------------------------------------------
# TokenBucket primitive
# ---------------------------------------------------------------------------


def test_token_bucket_refills_over_simulated_time():
    clock = [0.0]
    bucket = TokenBucket(60, clock=lambda: clock[0])

    # Drain 60 immediately
    for _ in range(60):
        assert bucket.try_acquire()
    assert bucket.try_acquire() is False

    # 30 seconds later → 30 tokens refilled
    clock[0] = 30.0
    acquired = sum(bucket.try_acquire() for _ in range(40))
    assert acquired == 30


# ---------------------------------------------------------------------------
# Response extraction edge cases
# ---------------------------------------------------------------------------


def test_empty_response_content_returns_empty_string_not_none():
    client, _, _ = _client(sequence=[_ok(content="")])

    result = client.analyse("s", "u")

    # Even empty content counts as a "response" — the parser will fall back.
    assert result.ok
    assert result.text == ""


def test_response_without_usage_does_not_crash():
    response = _FakeResponse(choices=[_FakeChoice(message=_FakeMessage(content="ok"))])
    response.usage = None
    client, _, metrics = _client(sequence=[response])

    result = client.analyse("s", "u")

    assert result.ok
    assert result.prompt_tokens == 0
    assert metrics.get_counter("llm_tokens_total", kind="prompt") == 0


def test_never_raises_on_unexpected_exception():
    """Defensive: any leak from the openai SDK must be caught."""

    class WeirdProviderError(Exception):
        pass

    client, _, _ = _client(sequence=[WeirdProviderError("???")])

    # Not in the transient set → fails fast, but does NOT raise.
    result = client.analyse("s", "u")

    assert result.ok is False
    assert "WeirdProviderError" in (result.error or "")


# ---------------------------------------------------------------------------
# TLS transport — SSL_CERT_FILE (default) vs the llm_ssl_verify escape hatch
# ---------------------------------------------------------------------------


def test_default_client_uses_sdk_transport_when_verification_enabled(monkeypatch):
    """Verification on = no custom transport, so httpx keeps honouring SSL_CERT_FILE.

    A self-signed / private-CA LLM endpoint is trusted through that env
    (the CA bundle is mounted into the agent-job pods), not through code.
    """
    captured: dict[str, Any] = {}

    class _FakeOpenAI:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr("openai.OpenAI", _FakeOpenAI)

    LlmClient._default_client(_settings())

    assert captured["http_client"] is None
    assert captured["max_retries"] == 0


def test_default_client_disables_tls_verification_when_opted_out(monkeypatch):
    import ssl

    import httpx

    captured: dict[str, Any] = {}

    class _FakeOpenAI:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr("openai.OpenAI", _FakeOpenAI)

    LlmClient._default_client(_settings(llm_ssl_verify=False))

    http_client = captured["http_client"]
    assert isinstance(http_client, httpx.Client)
    ssl_context = http_client._transport._pool._ssl_context
    assert ssl_context.verify_mode == ssl.CERT_NONE
    assert ssl_context.check_hostname is False


def test_insecure_http_client_is_none_by_default():
    # Default must stay "verify" — an accidental opt-out would silently accept
    # any certificate on the LLM leg.
    assert _settings().llm_ssl_verify is True
    assert LlmClient._insecure_http_client(_settings()) is None
