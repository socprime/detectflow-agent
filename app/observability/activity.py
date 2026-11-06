"""Job-health activity reporter for the cross-team ``detectflow.activity`` topic.

Both Flink jobs emit ``ActivityEvent`` health records here — consumed by
detectflow-backend's ``ActivityConsumerService`` for the audit log and
dashboard. This is a *side channel*, not part of the data path: it must never
break correlation/agent processing, so every public method swallows errors
(mirrors ``app/operators/llm_client.py`` "never raises").

## Wire contract (detectflow-backend ``apps/core/schemas.py::ActivityEvent``)

Topic ``detectflow.activity``. Kafka key = the event ``id`` UUID (utf-8). Kafka value
= a single JSON object (``json.dumps`` of the event dict). Plain JSON — NOT
Avro, no registry, no wrapper, no version field.

Required (the backend drops the whole message if any is missing): ``id`` (a valid
``uuid4`` string — a non-uuid parses but aborts the backend's DB batch insert),
``timestamp`` (ISO-8601 tz-aware string, NOT epoch millis), ``action``,
``entity_type``. Optional: ``entity_id``, ``entity_name``, ``user_id``,
``user_email``, ``details``, ``changes`` (dict / JSONB), ``source``,
``severity``.

Traps obeyed here:

1. ``severity`` is set EXPLICITLY on every event (the backend does not auto-derive
   it for foreign producers) — one of ``info`` / ``warning`` / ``error``.
2. The backend's consumer is ``extra="ignore"``: any extra top-level field is
   silently dropped. All non-standard data goes inside ``changes`` (dict) or
   ``details`` (string) — never a new top-level key.
3. ``timestamp`` is ISO-8601, ``id`` is ``str(uuid4())``.

For both jobs: ``entity_type="flink"``, ``entity_id=settings.job_id``,
``source="flink"``, ``user_id``/``user_email`` null, ``entity_name`` a human
label supplied per job (``ENTITY_NAME_CORRELATION`` / ``ENTITY_NAME_AGENT``).

Instance identity, once there is one job pair per correlation pipeline: the
deployment name stays in ``entity_id`` (what the control plane correlates on),
the human label gets an ``[instance-label]`` suffix, and the pipeline's bare
UUID rides in ``changes.correlation_pipeline`` — inside ``changes`` precisely
because trap 2 below forbids a new top-level key.

## Resilience & gating

- **Disabled mode**: if ``kafka_activity_topic`` is empty/unset, the reporter
  is a no-op and opens no producer. Unit tests run without a broker via this path or a
  stub producer.
- **Anti-flood gate**: high-volume alerts/errors pass a ``flood_key``; the
  same key is emitted at most once per ``activity_flood_cooldown_seconds``
  (mirrors detectflow-backend ``ErrorTracker``). Ungated events (started, heartbeat,
  one-off alerts) always emit.
- **at-least-once**: the side producer is a plain ``confluent_kafka.Producer``
  (acks=all + gzip from ``get_kafka_producer_config()``). No transactions /
  EXACTLY_ONCE — duplicate health events are harmless.

## Per-worker lazy construction

flink-agents (Pemja, thread mode) and Beam (process mode) both spawn worker
subprocesses that re-import this module fresh — a reporter built in the driver
does not survive the boundary, but environment variables (and thus
``Settings``) do. ``get_activity_reporter()`` lazily builds a per-worker
singleton from ``Settings`` on first use, idempotent across many calls
(mirrors ``correlation_agent._lazy_configure_from_env``).
"""

from __future__ import annotations

import json
import threading
import time
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.config.logging import get_logger
from app.config.settings import Settings, get_settings

logger = get_logger(__name__)

SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_ERROR = "error"

ACTION_STATUS_CHANGE = "status_change"
ACTION_ALERT = "alert"
ACTION_ERROR = "error"

# Human ``entity_name`` labels, one per job. Defined here (not at the four call
# sites) so driver and workers agree: ``get_activity_reporter`` is first-call
# wins on ``entity_name``, and whichever code path touches it first in a worker
# process fixes the label for that process's whole lifetime.
ENTITY_NAME_CORRELATION = "Attack Chains Correlation Job"
ENTITY_NAME_AGENT = "Attack Chains Agent Job"


def _now_iso() -> str:
    """Return the current UTC time as a tz-aware ISO-8601 string with microseconds.

    Example: ``2026-05-28T12:34:56.789012+00:00``. Matches the detectflow-backend
    ``ActivityEvent.timestamp`` contract (ISO-8601, NOT epoch millis).
    """
    return datetime.now(tz=UTC).isoformat()


class _FloodGate:
    """Per-key cooldown gate — thread-safe, mirrors detectflow-backend ``ErrorTracker``.

    ``should_emit(key)`` returns ``True`` the first time a key is seen and again
    only once ``cooldown_seconds`` have elapsed since the last allowed emit for
    that key. Used to keep high-volume drop/reject alerts from flooding the
    audit log.
    """

    def __init__(self, cooldown_seconds: float, *, clock: Any = time.monotonic):
        self._cooldown = max(0.0, float(cooldown_seconds))
        self._clock = clock
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def should_emit(self, key: str) -> bool:
        """Return ``True`` if ``key`` is outside its cooldown window (and arm it)."""
        now = self._clock()
        with self._lock:
            last = self._last.get(key)
            if last is None or (now - last) >= self._cooldown:
                self._last[key] = now
                return True
            return False

    def reset(self, key: str | None = None) -> None:
        """Reset gate state for one key, or all keys when ``key`` is ``None`` (test-only)."""
        with self._lock:
            if key is None:
                self._last.clear()
            else:
                self._last.pop(key, None)


class ActivityReporter:
    """Emits job-health ``ActivityEvent`` records to ``detectflow.activity``.

    Wraps a ``confluent_kafka.Producer`` built from
    ``settings.get_kafka_producer_config()`` plus the activity topic. Disabled
    (no-op, no producer) when the topic is empty. Never raises into the caller:
    ``produce()`` is wrapped in try/except and logged at warning.

    Construct via :func:`get_activity_reporter` rather than directly so workers
    share one per-process instance. A ``producer_factory`` hook lets tests
    inject a stub and avoid a real broker.

    Attributes:
        enabled: ``False`` when the topic is empty — every emit is a no-op.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        entity_name: str | None = None,
        producer_factory: Any = None,
    ):
        """Build a reporter for ``settings``.

        Args:
            settings: Application settings (topic, job_id, producer config).
            entity_name: Human label for the job (e.g. "Attack Chains Agent
                Job"). Defaults to ``settings.job_id`` when omitted.
            producer_factory: Optional ``(config: dict) -> producer`` callable
                for tests. When ``None`` a real ``confluent_kafka.Producer`` is
                created lazily on first emit.
        """
        self._settings = settings
        self._topic = (settings.kafka_activity_topic or "").strip()
        # Decorate the human label with the instance label so N correlation
        # pipelines are distinguishable in the audit log. Constant for the life
        # of the process, which is why doing it once in __init__ is correct
        # despite get_activity_reporter() being first-call-wins on entity_name.
        label = settings.instance_label()
        base_name = entity_name or settings.job_id
        self._entity_name = f"{base_name} [{label}]" if label and label != base_name else base_name
        # The DEPLOYMENT NAME (corr-<uuid>), which is what the control plane
        # already correlates on — never the pipeline UUID.
        self._entity_id = settings.job_id
        # The pipeline dimension rides inside `changes`: the backend's consumer is
        # extra="ignore", so a new TOP-LEVEL key would be silently dropped.
        # `id` here is the BARE UUID — the control plane parses it as one, so
        # job_id (not a UUID) must never be substituted.
        self._pipeline_context: dict[str, Any] = {}
        if settings.correlation_pipeline_id or settings.correlation_pipeline_name:
            self._pipeline_context = {
                "correlation_pipeline": {
                    "id": settings.correlation_pipeline_id,
                    "name": settings.correlation_pipeline_name,
                }
            }
        self._producer_factory = producer_factory
        self._producer: Any = None
        self._gate = _FloodGate(settings.activity_flood_cooldown_seconds)

    @property
    def enabled(self) -> bool:
        """``True`` when an activity topic is configured; ``False`` => no-op reporter."""
        return bool(self._topic)

    # ------- producer lifecycle -------

    def _get_producer(self) -> Any:
        """Lazily build (and cache) the side producer; ``None`` when disabled."""
        if not self.enabled:
            return None
        if self._producer is None:
            config = self._settings.get_kafka_producer_config()
            if self._producer_factory is not None:
                self._producer = self._producer_factory(config)
            else:
                from confluent_kafka import Producer

                self._producer = Producer(config)
        return self._producer

    def flush(self, timeout: float = 5.0) -> None:
        """Flush buffered events; safe to call on disabled or never-used reporters."""
        if self._producer is None:
            return
        try:
            self._producer.flush(timeout)
        except Exception as exc:  # noqa: BLE001 — health channel never raises
            logger.warning("activity_reporter flush failed", error=str(exc))

    # ------- taxonomy surface -------

    def emit_started(self, changes: dict[str, Any] | None = None) -> None:
        """Emit a ``status_change`` (info) marking the job transition to running.

        Call from ``run()`` right before ``execute()``. Defaults ``changes`` to
        ``{"status": {"old": "starting", "new": "running"}}``.
        """
        payload = changes or {"status": {"old": "starting", "new": "running"}}
        self._emit(ACTION_STATUS_CHANGE, SEVERITY_INFO, details="started", changes=payload)

    def heartbeat(self, changes: dict[str, Any] | None = None) -> None:
        """Emit a periodic liveness ``status_change`` (info) with ``details="heartbeat"``."""
        self._emit(ACTION_STATUS_CHANGE, SEVERITY_INFO, details="heartbeat", changes=changes)

    def emit_status_change(
        self,
        old: str,
        new: str,
        *,
        details: str | None = None,
    ) -> None:
        """Emit a generic ``status_change`` (info) carrying an ``{old, new}`` status delta."""
        self._emit(
            ACTION_STATUS_CHANGE,
            SEVERITY_INFO,
            details=details,
            changes={"status": {"old": old, "new": new}},
        )

    def emit_alert(
        self,
        reason: str,
        *,
        details: str | None = None,
        changes: dict[str, Any] | None = None,
        flood_key: str | None = None,
    ) -> None:
        """Emit an ``alert`` (warning) for a soft degradation.

        Covers LLM throttling, LLM parse drift, HoS rule rejection, and gated
        high-volume record drops. Pass ``flood_key`` for high-frequency sources
        so the anti-flood gate suppresses repeats within the cooldown window;
        ungated alerts always emit.

        Args:
            reason: Short machine-friendly reason; merged into ``changes`` as
                ``reason`` and used as the default ``details``.
            details: Human-readable description (defaults to ``reason``).
            changes: Extra structured context (goes in the ``changes`` dict).
            flood_key: Anti-flood key; ``None`` disables gating for this call.
        """
        self._emit_gated(
            ACTION_ALERT,
            SEVERITY_WARNING,
            reason=reason,
            details=details,
            changes=changes,
            flood_key=flood_key,
        )

    def emit_error(
        self,
        reason: str,
        *,
        details: str | None = None,
        changes: dict[str, Any] | None = None,
        flood_key: str | None = None,
    ) -> None:
        """Emit an ``error`` (error severity) for a terminal failure.

        Covers e.g. LLM unavailable after all retries. Same gating semantics as
        :meth:`emit_alert`.
        """
        self._emit_gated(
            ACTION_ERROR,
            SEVERITY_ERROR,
            reason=reason,
            details=details,
            changes=changes,
            flood_key=flood_key,
        )

    # ------- internals -------

    def _emit_gated(
        self,
        action: str,
        severity: str,
        *,
        reason: str,
        details: str | None,
        changes: dict[str, Any] | None,
        flood_key: str | None,
    ) -> None:
        """Apply the anti-flood gate, fold ``reason`` into ``changes``, then emit."""
        if flood_key is not None and not self._gate.should_emit(flood_key):
            return
        merged = dict(changes or {})
        merged.setdefault("reason", reason)
        self._emit(action, severity, details=details or reason, changes=merged)

    def _emit(
        self,
        action: str,
        severity: str,
        *,
        details: str | None = None,
        changes: dict[str, Any] | None = None,
    ) -> None:
        """Build the full ``ActivityEvent`` dict and produce it. Never raises.

        All non-standard data must arrive via ``changes`` / ``details`` —
        the backend's consumer silently drops unknown top-level keys.
        """
        if not self.enabled:
            return

        # Caller-supplied keys win, so an explicit correlation_pipeline is never
        # clobbered. Stays absent (changes untouched, possibly None) on the
        # legacy single-instance deployment.
        if self._pipeline_context:
            changes = {**self._pipeline_context, **(changes or {})}

        event_id = str(uuid4())
        event: dict[str, Any] = {
            "id": event_id,
            "timestamp": _now_iso(),
            "action": action,
            "entity_type": "flink",
            "entity_id": self._entity_id,
            "entity_name": self._entity_name,
            "user_id": None,
            "user_email": None,
            "details": details,
            "changes": changes,
            "source": "flink",
            "severity": severity,
        }

        try:
            producer = self._get_producer()
            if producer is None:
                return
            producer.produce(
                self._topic,
                key=event_id.encode("utf-8"),
                value=json.dumps(event).encode("utf-8"),
            )
            producer.poll(0)
        except Exception as exc:  # noqa: BLE001 — health channel never breaks the data path
            logger.warning(
                "activity_reporter emit failed",
                action=action,
                severity=severity,
                error=str(exc),
            )


# ---------------------------------------------------------------------------
# Per-worker lazy singleton. Worker subprocesses re-import this module fresh;
# the driver-built reporter does not cross the boundary, but Settings (env) do.
# ---------------------------------------------------------------------------

_reporter: ActivityReporter | None = None
_reporter_lock = threading.Lock()


def get_activity_reporter(entity_name: str | None = None) -> ActivityReporter:
    """Return the per-process ``ActivityReporter`` singleton, building it on first use.

    Idempotent — safe to call from every event / timer tick on every worker.
    The first call wins on ``entity_name``; later calls return the cached
    instance regardless of the argument. Built from ``get_settings()`` so each
    worker reconstructs a valid reporter from the environment without state
    passed from the driver.

    Args:
        entity_name: Human label for the job (e.g. "Attack Chains Correlation
            Job"). Only honoured on the first call per process.

    Returns:
        The shared :class:`ActivityReporter` (a no-op instance when the activity
        topic is unset).
    """
    global _reporter
    if _reporter is None:
        with _reporter_lock:
            if _reporter is None:
                _reporter = ActivityReporter(get_settings(), entity_name=entity_name)
    return _reporter


def reset_activity_reporter() -> None:
    """Drop the cached singleton so the next accessor call rebuilds it (test-only)."""
    global _reporter
    with _reporter_lock:
        _reporter = None


def start_heartbeat(
    reporter: ActivityReporter,
    *,
    interval_seconds: float | None = None,
    stop_event: threading.Event | None = None,
) -> threading.Event:
    """Run a daemon thread that calls ``reporter.heartbeat()`` every interval.

    The primitive for the agent job's liveness loop. Correlation, which is
    operator-driven, instead calls ``reporter.heartbeat()`` from a
    processing-time timer (it does not use this helper). No-op (returns
    immediately, thread exits) when the reporter is disabled.

    Args:
        reporter: The reporter to pulse.
        interval_seconds: Seconds between heartbeats; defaults to
            ``settings.activity_heartbeat_seconds`` via the reporter's settings.
        stop_event: Caller-owned stop flag; created if omitted. Set it to stop
            the loop. Returned so the caller can stop the thread on shutdown.

    Returns:
        The ``stop_event`` controlling the daemon thread.
    """
    stop = stop_event or threading.Event()
    interval = interval_seconds
    if interval is None:
        interval = float(reporter._settings.activity_heartbeat_seconds)  # noqa: SLF001

    if not reporter.enabled:
        return stop

    def _loop() -> None:
        while not stop.wait(interval):
            reporter.heartbeat()

    thread = threading.Thread(target=_loop, name="activity-heartbeat", daemon=True)
    thread.start()
    return stop
