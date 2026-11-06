"""Provider-agnostic LLM client for ChainAnalysisAgent.

Wraps the `openai` SDK against any OpenAI-compatible `/v1/chat/completions`
endpoint — OpenAI, Anthropic (OpenAI-compat shim), Ollama, vLLM, Groq,
Together, LocalAI. Provider swap = `llm_base_url` + `llm_api_key` +
`llm_model` change in `Settings`. No code change.

TLS: an endpoint serving a self-signed / private-CA certificate is trusted by
pointing the standard `SSL_CERT_FILE` env at a PEM bundle holding that CA —
httpx (the SDK's transport) honours it, again with no code change; in
Kubernetes detectflow-backend mounts the bundle into the agent-job pods.
`llm_ssl_verify=false` drops verification entirely — a test-only escape hatch
for a certificate that cannot be fixed (see `_insecure_http_client`).

## Resilience policy

1. **Per-minute token bucket** rate limit (`llm_calls_per_minute`). When the
   bucket is empty, `analyse()` first blocks up to
   `llm_throttle_max_wait_seconds` for a refill (deliberate backpressure on
   the Flink task thread — a short burst slows the stream instead of
   permanently null-verdicting the excess chains). Only when the wait is
   exhausted does the call return `LlmResult.throttled(...)` and bump
   `llm_calls_throttled_total` — chain still emits, with `llm_verdict=null`.
2. **Exponential backoff retry** (`llm_max_retries`, default 3) on
   `RateLimitError`, `APITimeoutError`, `APIConnectionError`,
   `InternalServerError`. Non-transient errors (auth, bad request) fail
   fast — retrying them just wastes budget.
3. **Graceful degradation** on terminal failure: returns
   `LlmResult.unavailable(...)` — `llm_verdict=null`,
   `ai_summary="LLM unavailable"`, error captured in `llm_review`.

The chain is **never lost**: every public method on `LlmClient` returns
an `LlmResult` and never raises.

## Metrics (via the existing `Metrics` façade)

- `llm_calls_total{status=success|error|timeout|throttled}`
- `llm_calls_throttled_total`
- `llm_latency_seconds` (histogram, milliseconds-precision)
- `llm_tokens_total{kind=prompt|completion}`

NB: agent-job currently passes a context-free `Metrics()` stub, so these are
recorded in-process only and are not exported to Flink's metric reporters.
"""

from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from app.config.logging import get_logger
from app.config.settings import Settings
from app.observability.metrics import Metrics

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class LlmResult:
    """Outcome of a single LLM call.

    Exactly one of (`text`, `error`) is populated:
      - `text` set       → ok / fallback parsing handled downstream
      - `error` set      → rate-limited, terminal failure, or throttled
                           locally; downstream emits null-verdict envelope
    """

    text: str | None = None
    error: str | None = None
    status: str = "success"  # success | error | timeout | throttled
    attempts: int = 0
    latency_seconds: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    extras: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        """``True`` when the call succeeded and ``text`` is populated."""
        return self.text is not None and self.status == "success"

    @classmethod
    def success(cls, text: str, **kwargs: Any) -> LlmResult:
        """Construct a successful result with the raw response text."""
        return cls(text=text, status="success", **kwargs)

    @classmethod
    def throttled(cls, reason: str) -> LlmResult:
        """Construct a locally-throttled result (token bucket exhausted)."""
        return cls(error=reason, status="throttled")

    @classmethod
    def unavailable(cls, reason: str, *, attempts: int, status: str = "error") -> LlmResult:
        """Construct a terminal-failure result after all retry attempts are exhausted."""
        return cls(error=reason, status=status, attempts=attempts)


# ---------------------------------------------------------------------------
# Rate limiter — token bucket, per-minute budget, thread-safe
# ---------------------------------------------------------------------------


class TokenBucket:
    """Per-minute token bucket. `try_acquire()` is non-blocking.

    Thread-safe. Pemja runs the agent in a single Python interpreter inside
    the JVM, but the bucket may still be touched from worker threads, so a
    `Lock` is the conservative choice.
    """

    def __init__(self, capacity: int, *, clock: Any = time.monotonic):
        self._capacity = max(1, capacity)
        self._tokens: float = float(self._capacity)
        # capacity per 60 s
        self._refill_per_sec = self._capacity / 60.0
        self._last = clock()
        self._clock = clock
        self._lock = threading.Lock()

    def _refill(self) -> None:
        """Replenish tokens proportional to elapsed time since last call."""
        now = self._clock()
        elapsed = now - self._last
        if elapsed > 0:
            self._tokens = min(self._capacity, self._tokens + elapsed * self._refill_per_sec)
            self._last = now

    def try_acquire(self) -> bool:
        """Attempt to consume one token. Returns ``True`` on success, ``False`` if throttled."""
        with self._lock:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False


# ---------------------------------------------------------------------------
# Retry decision — which exceptions are worth retrying
# ---------------------------------------------------------------------------


def _is_transient_error(exc: BaseException) -> bool:
    """Return ``True`` for transient errors worth retrying; auth/bad-request errors are always ``False``."""
    name = type(exc).__name__
    transient_names = {
        "RateLimitError",
        "APITimeoutError",
        "Timeout",
        "APIConnectionError",
        "InternalServerError",
        "APIError",  # generic 5xx — coarse, but openai>=1 maps these distinctly when known
    }
    return name in transient_names


def _classify_terminal_status(exc: BaseException) -> str:
    """Return ``"timeout"`` for timeout errors, ``"error"`` for everything else."""
    name = type(exc).__name__
    if "Timeout" in name:
        return "timeout"
    return "error"


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class LlmClient:
    """Thin retry/rate-limit/metrics shell around an OpenAI-compat client.

    Construct one per agent instance (open() time). Inject a custom
    `client_factory` from tests to avoid network calls.
    """

    def __init__(
        self,
        settings: Settings,
        metrics: Metrics,
        *,
        client_factory: Any = None,
        sleep: Any = time.sleep,
    ):
        self._settings = settings
        self._metrics = metrics
        self._sleep = sleep
        # Snapshot at construction (like the bucket budget below) — settings are
        # env-driven and immutable for the life of the job, and a stable value
        # keeps the wall-time invariant auditable in one place.
        self._throttle_max_wait_s = settings.llm_throttle_max_wait_seconds
        # The token bucket is per-subtask, but `llm_calls_per_minute` is a GLOBAL
        # per-job budget — split it across the parallel subtasks so the aggregate
        # call rate stays ≈ the configured value instead of parallelism × budget
        # (an N× overspend / 429 risk on a paid endpoint).
        per_subtask_budget = max(
            1, settings.llm_calls_per_minute // max(1, settings.flink_parallelism)
        )
        self._bucket = TokenBucket(per_subtask_budget)
        if client_factory is None:
            self._client = self._default_client(settings)
        else:
            self._client = client_factory(settings)

    @staticmethod
    def _insecure_http_client(settings: Settings) -> Any | None:
        """Build the TLS-verification-off transport, or ``None`` when verification stays on.

        A self-hosted LLM with a self-signed / private-CA certificate normally
        needs **no** code path here: httpx (under the openai SDK) reads the
        standard ``SSL_CERT_FILE`` env and trusts that bundle — which is what
        detectflow-backend mounts into the agent-job pods. ``llm_ssl_verify=false``
        is the escape hatch for when the certificate itself cannot be fixed (a
        CN-only cert with no SAN, say): every certificate is then accepted, so it
        is a test-only setting and is logged as such on every job start.
        """
        if settings.llm_ssl_verify:
            return None

        import httpx

        logger.warning(
            "LLM TLS certificate verification is DISABLED (LLM_SSL_VERIFY=false) — "
            "traffic to the LLM endpoint is open to interception; use SSL_CERT_FILE "
            "with the endpoint's CA bundle instead",
            llm_base_url=settings.llm_base_url,
        )
        return httpx.Client(verify=False, timeout=settings.llm_request_timeout_seconds)

    @staticmethod
    def _default_client(settings: Settings) -> Any:
        """Construct the default ``openai.OpenAI`` client from settings.

        ``timeout`` bounds each request (the SDK default is 600 s read, which
        would stall the Pemja task thread and the checkpoint barrier). With it
        set, an unresponsive endpoint raises ``APITimeoutError``, which our own
        retry loop handles. ``max_retries=0`` disables the SDK's internal retry
        (default 2) so it does not multiply latency on top of our retry loop.
        ``http_client`` is only supplied when TLS verification is switched off —
        otherwise the SDK's own transport (which honours ``SSL_CERT_FILE``) is used.
        """
        from openai import OpenAI

        return OpenAI(
            base_url=settings.llm_base_url,
            api_key=settings.llm_api_key.get_secret_value(),
            timeout=settings.llm_request_timeout_seconds,
            max_retries=0,
            http_client=LlmClient._insecure_http_client(settings),
        )

    # Poll granularity for the bounded throttle wait. Small enough that a token
    # refilling mid-wait is picked up promptly; large enough to not busy-spin.
    _THROTTLE_POLL_INTERVAL_S = 0.25

    def _acquire_with_bounded_wait(self) -> bool:
        """Try to take a token; block (politely) up to the configured wait.

        Sleeping on the calling thread is INTENTIONAL: this runs on the Pemja
        task thread, so the stall propagates upstream as Flink backpressure and
        a short burst above `llm_calls_per_minute` slows the stream down instead
        of permanently emitting null-verdict chains (chains-raw has no re-drive
        path — a throttled chain is analysed never, not later).

        Wall-time invariant (keep these settings coherent): worst-case
        per-record time on this thread is
        ``llm_throttle_max_wait_seconds
          + llm_request_timeout_seconds × (llm_max_retries + 1)
          + Σ backoff (≤ 1+2+4 ≈ 7 s at 3 retries)``
        — with defaults 10 + 30×4 + 7 ≈ 137 s, which must stay well below
        ``agent_checkpoint_timeout_ms`` (180 s) or a single slow record blocks
        the checkpoint barrier past its timeout.

        ``llm_throttle_max_wait_seconds=0`` restores the old fail-fast
        behaviour (never wait).
        """
        if self._bucket.try_acquire():
            return True
        # Budget the wait by intended sleep durations rather than wall-clock
        # reads so an injected test sleep (no-op) terminates deterministically;
        # in production `time.sleep` makes the two equivalent.
        waited = 0.0
        while waited < self._throttle_max_wait_s:
            step = min(self._THROTTLE_POLL_INTERVAL_S, self._throttle_max_wait_s - waited)
            self._sleep(step)
            waited += step
            if self._bucket.try_acquire():
                return True
        return False

    def analyse(self, system: str, user: str) -> LlmResult:
        """Single chain analysis call. Never raises."""
        if not self._acquire_with_bounded_wait():
            self._metrics.inc("llm_calls_total", status="throttled")
            self._metrics.inc("llm_calls_throttled_total")
            logger.warning(
                "LLM call throttled by local rate limiter",
                waited_seconds=self._throttle_max_wait_s,
            )
            return LlmResult.throttled("local_rate_limit")

        attempts = 0
        last_exc: Exception | None = None
        max_attempts = self._settings.llm_max_retries + 1
        started = time.monotonic()

        for attempts in range(1, max_attempts + 1):
            try:
                response = self._client.chat.completions.create(
                    model=self._settings.llm_model,
                    max_tokens=self._settings.llm_max_tokens,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                )
            except Exception as exc:  # noqa: BLE001 — SDK errors must never escape.
                # Deliberately NOT BaseException: KeyboardInterrupt / SystemExit
                # must propagate so shutdown is not swallowed into a retry path
                # that can then time.sleep(≤30 s) mid-teardown.
                last_exc = exc
                if attempts >= max_attempts or not _is_transient_error(exc):
                    break
                delay = self._backoff_delay(attempts)
                logger.warning(
                    "LLM call transient error — retrying",
                    error_type=type(exc).__name__,
                    attempt=attempts,
                    next_delay_s=round(delay, 2),
                )
                self._sleep(delay)
                continue

            latency = time.monotonic() - started
            text, prompt_tokens, completion_tokens = self._extract_response(response)
            self._metrics.inc("llm_calls_total", status="success")
            self._metrics.record("llm_latency_seconds", latency)
            if prompt_tokens:
                self._metrics.inc("llm_tokens_total", value=prompt_tokens, kind="prompt")
            if completion_tokens:
                self._metrics.inc("llm_tokens_total", value=completion_tokens, kind="completion")
            return LlmResult.success(
                text=text,
                attempts=attempts,
                latency_seconds=latency,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
            )

        # Loop exited without return → terminal failure path.
        latency = time.monotonic() - started
        status = _classify_terminal_status(last_exc) if last_exc is not None else "error"
        reason = f"{type(last_exc).__name__ if last_exc else 'unknown'}: {last_exc}"
        self._metrics.inc("llm_calls_total", status=status)
        self._metrics.record("llm_latency_seconds", latency)
        logger.error(
            "LLM call terminal failure",
            attempts=attempts,
            status=status,
            error=reason,
        )
        return LlmResult.unavailable(reason, attempts=attempts, status=status)

    def _backoff_delay(self, attempt: int) -> float:
        """Exponential backoff with jitter: base 1s, cap 30s."""
        base = min(30.0, 2 ** (attempt - 1))
        return base * (0.5 + random.random() * 0.5)

    @staticmethod
    def _extract_response(response: Any) -> tuple[str, int, int]:
        """Extract ``(text, prompt_tokens, completion_tokens)`` from an API response."""
        try:
            text = response.choices[0].message.content or ""
        except (AttributeError, IndexError, TypeError):
            text = ""
        prompt_tokens = 0
        completion_tokens = 0
        usage = getattr(response, "usage", None)
        if usage is not None:
            prompt_tokens = int(getattr(usage, "prompt_tokens", 0) or 0)
            completion_tokens = int(getattr(usage, "completion_tokens", 0) or 0)
        return text, prompt_tokens, completion_tokens
