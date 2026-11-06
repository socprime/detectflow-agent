"""ChainAnalysisAgent — orchestrates the analysis of one chain.

Pure composition of four building blocks:

  ChainRaw  ──build_prompt──>  (system, user)
                                    │
                                    ▼
                              llm_client.analyse  ──> LlmResult
                                    │
                                    ▼
                            parse_llm_response  ──> ParsedAnalysis
                                    │
                                    ▼
                          ChainAnalysed envelope (full shape)

Three LlmResult outcomes all map to a valid `ChainAnalysed`:

| LlmResult        | llm_verdict      | ai_summary             | llm_review                                  |
|------------------|------------------|-------------------------|---------------------------------------------|
| success (parsed) | TRUE/SUSP/FP     | parsed.summary          | parsed.review                               |
| success (drift)  | SUSPICIOUS       | "LLM output unparsable" | {reasoning: <raw>, indicators, actions}     |
| throttled        | None             | "LLM unavailable"       | {error: "local_rate_limit", ...}            |
| unavailable      | None             | "LLM unavailable"       | {error: "<error type>: <message>", ...}     |

Chain is **never lost** — every input produces an output of the full
ChainAnalysed shape. `chain_id` and `revision` flow through 1:1.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from typing import Any

from flink_agents.api.agents.agent import Agent
from flink_agents.api.decorators import action
from flink_agents.api.events.event import InputEvent, OutputEvent
from flink_agents.api.runner_context import RunnerContext

from app.config.logging import get_logger
from app.config.settings import Settings, get_settings
from app.observability.activity import (
    ENTITY_NAME_AGENT,
    get_activity_reporter,
    start_heartbeat,
)
from app.observability.metrics import Metrics
from app.operators.agent_output import parse_llm_response
from app.operators.agent_prompt import (
    PROMPT_BUILDER_VERSION,
    PromptBuildResult,
    build_prompt_with_aggregation,
)
from app.operators.chain_models import ChainAnalysed, ChainRaw
from app.operators.llm_client import LlmClient, LlmResult

logger = get_logger(__name__)

LLM_UNAVAILABLE_SUMMARY = "LLM unavailable"


# ---------------------------------------------------------------------------
# Module-level dependency container. flink-agents `@action` methods are
# static (no `self`), so the JVM-side dispatcher cannot pass per-instance
# state. The agent-job entrypoint calls `configure(...)` before `execute()`;
# tests bypass this by calling `analyse_chain_raw(...)` directly.
# ---------------------------------------------------------------------------


_llm_client: LlmClient | None = None
_metrics: Metrics | None = None
_settings: Settings | None = None

# Job-health heartbeat: started exactly once per Pemja worker (flink-agents
# owns the operator, so there is no per-task open() hook — the lazy-config
# path is the one place that runs once per worker before the first event).
_heartbeat_started = False
_heartbeat_lock = threading.Lock()


def configure(
    *,
    llm_client: LlmClient,
    metrics: Metrics,
    settings: Settings,
) -> None:
    """Wire module-level dependencies. Called once by the agent-job entrypoint before ``execute()``."""
    global _llm_client, _metrics, _settings
    _llm_client = llm_client
    _metrics = metrics
    _settings = settings


def _start_heartbeat_once() -> None:
    """Start the per-worker job-health heartbeat daemon thread exactly once.

    flink-agents owns the operator, so there is no per-task ``open()`` hook —
    the lazy-config path is the single seam that runs once per worker before
    the first event. The reporter (and thus the heartbeat) is a no-op when the
    activity topic is unset. Idempotent and thread-safe.
    """
    global _heartbeat_started
    if _heartbeat_started:
        return
    with _heartbeat_lock:
        if _heartbeat_started:
            return
        reporter = get_activity_reporter(ENTITY_NAME_AGENT)
        start_heartbeat(reporter)
        _heartbeat_started = True


def _lazy_configure_from_env() -> None:
    """Re-bootstrap module state from environment.

    flink-agents (Pemja, thread-mode) spawns Python workers that re-import
    the module fresh — module globals set by `configure(...)` in the
    submitter process don't survive that boundary. Environment variables
    do survive, so we lazy-init from them on first event when state is
    missing. Safe to call multiple times (idempotent).

    Also starts the per-worker job-health heartbeat daemon thread (once) — the
    worker builds its own activity reporter from the environment here, since
    the driver-side reporter does not cross the Pemja boundary.
    """
    _start_heartbeat_once()
    if _llm_client is not None and _metrics is not None and _settings is not None:
        return
    settings = get_settings()
    metrics = Metrics()
    configure(
        llm_client=LlmClient(settings, metrics),
        metrics=metrics,
        settings=settings,
    )


def _now_iso() -> str:
    """Return current UTC time as an ISO-8601 ``YYYY-MM-DDTHH:MM:SSZ`` string."""
    return datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _aggregation_audit_fields(prompt: PromptBuildResult) -> dict[str, Any]:
    """Extract the prompt-builder audit fields to embed in ``llm_review``."""
    return {
        "aggregation_summary": prompt.aggregation_summary,
        "aggregation_method": prompt.aggregation_method,
        "prompt_builder_version": PROMPT_BUILDER_VERSION,
        "log_sources_capped": prompt.log_sources_capped,
    }


def _enrich_success(
    chain: ChainRaw, llm_text: str, prompt: PromptBuildResult
) -> tuple[ChainAnalysed, bool]:
    """Build ``ChainAnalysed`` from a successful (non-empty) LLM response.

    Returns ``(analysed, parse_failed)`` — ``parse_failed`` is the parser's own
    drift flag, so the caller classifies the emit metric off the boolean rather
    than re-deriving it from a magic-string summary match.
    """
    parsed = parse_llm_response(llm_text)
    review = dict(parsed.review)
    if parsed.parse_failed:
        # Drift fallback already applied by parser — surface fallback marker
        # so detectflow-backend UI can render a hint.
        review.setdefault("parse_failed", True)
        review.setdefault("fallback_reason", parsed.fallback_reason)
        # Job-health: LLM returned bytes but they were unparsable; the
        # SUSPICIOUS fallback was applied. Gated — parse drift can recur per
        # chain under a model regression.
        get_activity_reporter(ENTITY_NAME_AGENT).emit_alert(
            "llm_parse_drift",
            details="LLM output unparsable; SUSPICIOUS fallback applied",
            changes={
                "chain_id": chain.chain_id,
                "fallback_reason": parsed.fallback_reason,
            },
            flood_key="agent_parse_drift",
        )
    # `missing_context` belongs alongside the LLM's own free-form findings.
    # parse_llm_response already pins it into review when populated; we
    # default to [] otherwise so consumers don't branch on presence.
    review.setdefault("missing_context", list(parsed.missing_context))
    review.update(_aggregation_audit_fields(prompt))

    base = chain.model_dump(mode="json")
    base.update(
        {
            "ai_summary": parsed.summary,
            "llm_verdict": parsed.verdict.value,
            "llm_confidence": parsed.confidence,
            "llm_review": review,
            "analysed_at": _now_iso(),
        }
    )
    return ChainAnalysed.model_validate(base), parsed.parse_failed


def _enrich_unavailable(
    chain: ChainRaw,
    *,
    reason: str,
    status: str,
    attempts: int,
    prompt: PromptBuildResult,
) -> ChainAnalysed:
    """Build ``ChainAnalysed`` for the graceful-degradation path (throttled / unavailable)."""
    review: dict[str, Any] = {
        "reasoning": f"{LLM_UNAVAILABLE_SUMMARY}: {reason}",
        "indicators": [],
        "recommended_actions": [],
        "missing_context": [],
        "error": reason,
        "status": status,
        "attempts": attempts,
    }
    review.update(_aggregation_audit_fields(prompt))

    base = chain.model_dump(mode="json")
    base.update(
        {
            "ai_summary": LLM_UNAVAILABLE_SUMMARY,
            "llm_verdict": None,
            "llm_confidence": None,
            "llm_review": review,
            "analysed_at": _now_iso(),
        }
    )
    return ChainAnalysed.model_validate(base)


def analyse_chain_raw(
    chain: ChainRaw,
    *,
    llm_client: LlmClient,
    metrics: Metrics,
    settings: Settings,
) -> ChainAnalysed:
    """Pure orchestration: ChainRaw → LLM → ChainAnalysed.

    Always returns a fully-populated `ChainAnalysed`. Never raises.
    """
    metrics.inc("chains_received_total")
    prompt = build_prompt_with_aggregation(chain, char_budget=settings.llm_prompt_char_budget)

    metrics.inc("chain_aggregation_method_total", method=prompt.aggregation_method)
    # Bump by the count of dropped sub-buckets, not 1 per chain — a chain
    # that drops 7 buckets should bump the counter by 7.
    if prompt.log_sources_capped > 0:
        metrics.inc("chain_log_sources_capped_total", value=prompt.log_sources_capped)

    result: LlmResult = llm_client.analyse(prompt.system, prompt.user)

    if result.ok:
        analysed, parse_failed = _enrich_success(chain, result.text or "", prompt)
        if parse_failed:
            metrics.inc("chains_emitted_total", verdict="parse_failed")
        else:
            metrics.inc("chains_emitted_total", verdict=analysed.llm_verdict.value)
        return analysed

    # Throttled or unavailable — graceful degradation path. The chain is still
    # emitted (null verdict); we additionally surface a job-health signal.
    reporter = get_activity_reporter(ENTITY_NAME_AGENT)
    if result.status == "throttled":
        # Soft degradation — local rate limiter; chain emitted with null verdict.
        reporter.emit_alert(
            "llm_throttled",
            details="LLM call throttled by local rate limiter; chain emitted with null verdict",
            changes={
                "chain_id": chain.chain_id,
                "status": result.status,
                "attempts": result.attempts,
                "reason_code": "local_rate_limit",
            },
            flood_key="agent_llm_throttled",
        )
    else:
        # Terminal failure after retries (status in {timeout, error}).
        reporter.emit_error(
            "llm_unavailable",
            details=f"LLM unavailable after {result.attempts} attempts: {result.error}",
            changes={
                "chain_id": chain.chain_id,
                "status": result.status,
                "attempts": result.attempts,
            },
            flood_key="agent_llm_unavailable",
        )

    analysed = _enrich_unavailable(
        chain,
        reason=result.error or "unknown",
        status=result.status,
        attempts=result.attempts,
        prompt=prompt,
    )
    metrics.inc("chains_emitted_total", verdict="null", llm_status=result.status)
    return analysed


# ---------------------------------------------------------------------------
# flink-agents Agent — thin shell. The orchestration above is the unit
# under test; this class is the JVM-side adapter.
# ---------------------------------------------------------------------------


class ChainAnalysisAgent(Agent):
    """Thread-mode (Pemja) flink-agents Agent.

    Single `@action(InputEvent)` — direct LLM call, no two-stage
    ChatRequestEvent ↔ ChatResponseEvent flow. The provider-agnostic
    `LlmClient` carries retry/rate-limit/metrics; this shell just
    orchestrates and emits.
    """

    @action(InputEvent)
    @staticmethod
    def analyse_input(event: InputEvent, ctx: RunnerContext) -> None:
        """Receive a chain-raw JSON string or ``ChainRaw`` from the input stream and emit ``ChainAnalysed``."""
        if _llm_client is None or _metrics is None or _settings is None:
            # Pemja worker re-imports the module fresh; the configure(...)
            # call in the submitter process didn't propagate. Bootstrap
            # from env (Settings is env-driven, env survives the boundary).
            _lazy_configure_from_env()
        else:
            # Deps already wired in this process (no lazy-config needed), but
            # the per-worker heartbeat still must start exactly once.
            _start_heartbeat_once()

        # Input coercion must NOT raise: flink-agents runs with
        # error-handling-strategy=FAIL, so an exception escaping this action
        # restarts the job onto the same record — a poison-pill crash loop
        # (the same failure mode the entrypoint's flat_map bridge guards
        # against). Malformed payloads are logged + counted + dropped instead.
        raw = event.input
        if isinstance(raw, ChainRaw):
            chain = raw
        elif isinstance(raw, (dict, str)):
            try:
                chain = (
                    ChainRaw.model_validate(raw)
                    if isinstance(raw, dict)
                    else ChainRaw.model_validate_json(raw)
                )
            except Exception as exc:  # noqa: BLE001 — drop, never crash-loop
                logger.error(
                    "ChainAnalysisAgent: invalid input dropped",
                    type=type(raw).__name__,
                    error=str(exc)[:500],
                )
                _metrics.inc("chains_dropped_invalid_input_total", reason="validation_error")
                return
        else:
            # Previously a silent drop — make it observable: an unexpected
            # input type means the upstream bridge contract changed.
            logger.error("ChainAnalysisAgent: unrecognised input type", type=type(raw).__name__)
            _metrics.inc("chains_dropped_invalid_input_total", reason="unrecognised_type")
            return

        analysed = analyse_chain_raw(
            chain,
            llm_client=_llm_client,
            metrics=_metrics,
            settings=get_settings() if _settings is None else _settings,
        )
        # Emit the analysed chain as a JSON string. The downstream Kafka
        # sink uses SimpleStringSchema (java.lang.String value serializer);
        # `to_datastream(output_type=Types.STRING())` then carries this str
        # across the operator boundary as a real Java String. Returning a
        # Pydantic model here would land in the JVM as a pickled byte[]
        # and trip ClassCastException at the sink.
        ctx.send_event(OutputEvent(output=analysed.model_dump_json()))
