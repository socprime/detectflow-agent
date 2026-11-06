"""Unified configuration using Pydantic Settings.

All environment variables loaded from .env file.
"""

import os
import re
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# NB: `app.config.logging` must NOT be imported at module level here. Its
# import-time `_auto_configure()` imports THIS module to read log_level /
# log_format, so a top-level import back makes the cycle resolve differently
# depending on which module is imported first: when settings goes first,
# logging's lookup of `get_settings` hits a half-initialised module, silently
# falls back to INFO/console and drops the configured log level (reproduced via
# `make env-check`, which imports settings directly). The one function that
# logs imports the logger lazily instead.

# The out-of-the-box job id. Distinct instances MUST override it: consumer
# groups, EOS transactional-id prefixes and the activity entity_id are all
# scoped by job_id, so two instances that keep the default share all three.
DEFAULT_JOB_ID = "local"

# Flink folds the job name into the metric scope path and non-alphanumerics are
# mangled differently per reporter (JMX / SLF4J / Prometheus), so instance
# labels are reduced to a token-safe alphabet before they reach a job name.
_JOB_LABEL_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
# The same alphabet, as a whole-string guard for job_id — which also becomes a
# Kafka group id and an EOS transactional-id prefix.
_JOB_ID_SAFE = re.compile(r"^[A-Za-z0-9._-]+$")


class Settings(BaseSettings):
    """Complete application configuration.

    All settings loaded from environment variables or .env file.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ==========================================
    # KAFKA CONFIGURATION
    # ==========================================

    # Connection
    kafka_bootstrap_servers: str = Field(
        description="Kafka bootstrap servers (comma-separated)",
        examples=["pkc-xxxxx.eu-central-1.aws.confluent.cloud:9092"],
    )
    # Authentication
    kafka_auth_method: Literal["SASL", "SSL", "PLAINTEXT"] = Field(
        default="SASL",
        description=(
            "Authentication method: SASL (API key), SSL (certificates), or PLAINTEXT (no auth)"
        ),
    )

    # SASL credentials (required if auth_method=SASL)
    kafka_api_key: SecretStr | None = Field(
        default=None,
        description="Kafka API key for SASL authentication. SecretStr — never logged.",
    )
    kafka_api_secret: SecretStr | None = Field(
        default=None,
        description="Kafka API secret for SASL authentication. SecretStr — never logged.",
    )

    # SSL certificates (required if auth_method=SSL)
    kafka_ssl_ca_location: str | None = Field(
        default=None,
        description="Path to CA certificate (PEM format)",
    )
    kafka_ssl_certificate_location: str | None = Field(
        default=None,
        description="Path to client certificate (PEM format)",
    )
    kafka_ssl_key_location: str | None = Field(
        default=None,
        description="Path to client private key (PEM format)",
    )
    kafka_ssl_key_password: SecretStr | None = Field(
        default=None,
        description="Password for encrypted private key. SecretStr — never logged.",
    )
    kafka_ssl_truststore_location: str | None = Field(
        default=None,
        description="Path to truststore (optional)",
    )
    kafka_ssl_truststore_password: SecretStr | None = Field(
        default=None,
        description="Truststore password (optional). SecretStr — never logged.",
    )
    kafka_ssl_check_hostname: bool = Field(
        default=True,
        description=(
            "Verify broker hostname against SSL certificate (default: True). "
            "Set to False for development or when broker cert does not match hostname; "
            "sets ssl.endpoint.identification.algorithm=none."
        ),
    )

    # ==========================================
    # CORRELATION-JOB INPUTS (tagged-events tech topic)
    # ==========================================

    # Tagged Sigma-detection events land on the member detection pipelines'
    # dedicated tagged-events topics. Each event carries top-level
    # `hostname`, `timestamp`, and `pipeline_id` meta fields (matcher
    # pre-parses per logsource config — no ECS unwrapping downstream).
    # Isolation is the Kafka subscription (`KAFKA_INPUT_TOPICS`); destination
    # topic names are SIEM output only and are not a correlation filter.
    #
    # Comma-separated list semantics are preserved (typically a single tech
    # topic; multi-element supported for environments that shard tagged events
    # across several topics). Override via --input-topics or KAFKA_INPUT_TOPICS.
    kafka_input_topics: str = Field(
        default="detectflow.tagged-events",
        description=(
            "Comma-separated tagged-events tech topic(s) for correlation-job. "
            "Defaults to the single canonical topic; override via deployment "
            "config when needed. Ignored by agent-job."
        ),
    )

    # ==========================================
    # ATTACK CHAINS — META & DATA TOPICS
    # ==========================================

    kafka_active_threats_topic: str = Field(
        default="detectflow.active-threats",
        description="Compacted broadcast topic with Active Threat (AT) definitions",
    )
    kafka_hos_rules_topic: str = Field(
        default="detectflow.hos-rules",
        description="Compacted broadcast topic with Higher Order Sigma (HoS) rules",
    )
    kafka_chains_config_topic: str = Field(
        default="detectflow.chains-config",
        description=(
            "Compacted broadcast topic with the pipeline's chain config (coverage "
            "threshold, window override, excluded Active Threats)"
        ),
    )
    kafka_chains_raw_topic: str = Field(
        default="detectflow.chains-raw",
        description="Output of correlation-job, input of agent-job (records have a NULL key)",
    )
    kafka_chains_analysed_topic: str = Field(
        default="detectflow.chains-analysed",
        description="Output of agent-job, consumed by detectflow-backend (records have a NULL key)",
    )

    # ==========================================
    # ATTACK CHAINS — DEFAULTS (overridable via chains-config broadcast)
    # ==========================================

    chain_coverage_threshold_pct: int = Field(
        default=60,
        ge=50,
        le=100,
        description=(
            "Default seq-coverage threshold as integer percent (50-100). A chain "
            "is emitted once distinct hit seqs / total seqs * 100 >= threshold. "
            "Configurable globally via chains-config (envelope field "
            "`threshold_pct`); operator compares percent-to-percent — no float "
            "conversion."
        ),
    )
    chain_default_window_seconds: int = Field(
        default=300,
        ge=10,
        le=86400,
        description=(
            "Fallback chain window in seconds. Currently unused: every HoS rule must "
            "define `detection.timeframe`, and chains-config "
            "`correlation_window_seconds` overrides it."
        ),
    )
    chain_buffer_cleanup_grace_seconds: int = Field(
        default=120,
        ge=0,
        le=3600,
        description=(
            "Grace period (seconds) added to a buffer's window end before the "
            "matcher's processing-time cleanup timer garbage-collects it from keyed "
            "state. Must be >= the out-of-orderness allowance (60 s). Cleanup runs on "
            "wall-clock time, so an event that arrives later than window_end + grace "
            "(ingestion lag, backlog after a restart) starts a fresh buffer instead "
            "of joining the old one. This is the GC backstop for the otherwise-unbounded "
            "(hos_id, hostname, window) keyed state (the event-time cleanup timer "
            "never fires because the operator watermark is pinned at Long.MIN)."
        ),
    )
    chain_max_events_per_seq: int = Field(
        default=15,
        ge=1,
        le=1000,
        description=(
            "Max matched events retained per seq in a chain buffer (and thus "
            "inlined into the chains-raw envelope). Coverage counts DISTINCT "
            "seqs, so capping entries never changes coverage; it bounds keyed-"
            "state growth and the emitted record size. Without a cap a dense "
            "hostname/window accumulates unbounded events and the serialized "
            "chain exceeds Kafka's 1 MiB max.request.size — the sink failure "
            "restarts the job, which re-emits the same oversized chain: a "
            "permanent crash loop. Dropped "
            "events are surfaced as `events_dropped` on the envelope."
        ),
    )
    chain_max_record_kb: int = Field(
        default=900,
        ge=64,
        le=10240,
        description=(
            "Emit-time guard: if a serialized chain record still exceeds this "
            "size (KiB), per-seq events are progressively halved (floor 1 per "
            "seq) until it fits. Keep below the Kafka producer/broker 1 MiB "
            "message limit with headroom for envelope overhead."
        ),
    )
    chain_reemit_debounce_seconds: int = Field(
        default=30,
        ge=0,
        le=3600,
        description=(
            "Min seconds between re-emits of the same chain buffer after the "
            "threshold has been crossed (0 disables debouncing). Without it every "
            "matching event re-emits the full chain with a bumped revision — a hot "
            "window turns N events into ~N near-identical revisions, each of which "
            "is an LLM call downstream. The first threshold-crossing emit is never delayed; "
            "suppressed changes are flushed as a final revision by the window-"
            "cleanup timer, so the last revision consumed by detectflow-backend always "
            "reflects the complete buffer. Suppressed re-emits are surfaced via "
            "`chain_reemits_suppressed_total`."
        ),
    )
    chain_id_namespace: str = Field(
        default="6ba7b810-9dad-11d1-80b4-00c04fd430c8",  # uuid.NAMESPACE_DNS
        description=(
            "UUID namespace for deterministic `chain_id = uuid5(NS, "
            "'{correlation_pipeline_id}|{hos_id}|{hostname}|{window_start_iso}')` "
            "(the pipeline id is omitted from the seed when it is unset). Default = NAMESPACE_DNS, kept overridable for "
            "forward compatibility — but it MUST stay global and identical "
            "across pipelines: the per-customer scoping lives in the seed "
            "string, never in a per-pipeline namespace."
        ),
    )

    # ==========================================
    # JOB-HEALTH ACTIVITY REPORTING (detectflow.activity topic)
    # ==========================================
    #
    # Both jobs emit ActivityEvent health records (started / heartbeat /
    # degradation alerts) to the cross-team `detectflow.activity` topic, consumed by
    # detectflow-backend's ActivityConsumerService for the audit log and
    # dashboard. The wire contract is plain JSON (NOT Avro): Kafka key = event
    # id UUID, value = a single ActivityEvent JSON object. Side producer reuses
    # `get_kafka_producer_config()` (librdkafka format, acks=all + gzip).
    # at-least-once; never transactional. Leave the topic empty to disable the
    # reporter entirely (no-op, no producer opened).

    kafka_activity_topic: str = Field(
        default="detectflow.activity",
        description=(
            "Cross-team job-health topic for ActivityEvent records. Empty/unset "
            "disables the ActivityReporter (no-op, no producer)."
        ),
    )
    activity_heartbeat_seconds: int = Field(
        default=60,
        ge=1,
        description="Interval between periodic job-health heartbeat events (seconds)",
    )
    activity_flood_cooldown_seconds: int = Field(
        default=300,
        ge=1,
        description=(
            "Anti-flood cooldown per flood_key (seconds). A gated alert/error for "
            "the same key is suppressed until this window elapses — mirrors "
            "detectflow-backend ErrorTracker (300s default)."
        ),
    )

    # ==========================================
    # KAFKA CONSUMER SETTINGS
    # ==========================================

    kafka_consumer_group: str = Field(
        default="flink-agent",
        description="Kafka consumer group ID",
    )
    kafka_producer_compression_type: Literal["none", "gzip", "snappy", "lz4", "zstd"] = Field(
        default="gzip",
        description=(
            "Compression codec for Flink Kafka sinks (chains-raw, chains-analysed). "
            "Default gzip: ~11× ratio on chains-raw (revisions repeat the events[] "
            "array, which compresses well) and a net CPU reduction on both TM and "
            "broker in our measurements. zstd is available on the Flink classpath "
            "(lib/zstd-jni-1.5.6-6.jar): ~17% better ratio but +38 pp peak TM CPU, "
            "so gzip stays the default."
        ),
    )
    kafka_starting_offset: Literal["earliest", "latest", "committed"] = Field(
        default="latest",
        description="Kafka starting offset strategy",
    )

    # ==========================================
    # MULTI-TENANCY CONFIGURATION
    # ==========================================

    job_id: str = Field(
        default=DEFAULT_JOB_ID,
        description=(
            "Unique job identifier — the K8s DEPLOYMENT NAME (corr-<uuid> / "
            "agent-<uuid>), NOT a UUID. Scopes Kafka consumer groups "
            "(kafka_source.py) and EOS transactional-id prefixes (kafka_sink.py), "
            "and labels activity events. MUST be supplied as the JOB_ID "
            "ENVIRONMENT variable, not only via --job-id: run() assigns it on the "
            "driver, while Pemja/Beam workers re-import the app and rebuild "
            "Settings() from the environment, so a CLI-only value is invisible to "
            "every worker. Two instances sharing a job_id share consumer groups."
        ),
    )
    correlation_pipeline_id: str | None = Field(
        default=None,
        description=(
            "BARE UUID of the correlation pipeline this instance serves "
            "(control-plane correlation_pipelines.id) — distinct from job_id, "
            "which carries the corr-<uuid> deployment name; never derive one from "
            "the other. None = the legacy single-instance deployment. Identity "
            "only: surfaced on the Flink job name, activity events and the "
            "identity gauge, and it is the fallback the chain envelope's "
            "correlation_pipeline_id uses when the broadcast config omits one "
            "(the control plane parses that field as a UUID, so job_id would be "
            "rejected). NEVER used to build topic names — topics arrive fully "
            "resolved via the KAFKA_* env vars."
        ),
    )
    correlation_pipeline_name: str | None = Field(
        default=None,
        description=(
            "Human label of the correlation pipeline (control-plane "
            "correlation_pipelines.name). Used for the Flink job name and the "
            "activity entity label only — never for routing."
        ),
    )
    allow_default_job_id: bool = Field(
        default=False,
        description=(
            "Escape hatch: allow starting a pipeline-scoped instance while JOB_ID "
            "is still the default. Downgrades the startup guard to a warning. For "
            "deliberate local experiments only."
        ),
    )

    # ==========================================
    # FLINK CONFIGURATION
    # ==========================================

    flink_parallelism: int = Field(
        default=1,
        ge=1,
        le=100,
        description=(
            "Default operator parallelism. Keep 1 for the correlation-job: "
            "with parallelism>1 the AdaptiveScheduler starts degraded at p=1 when "
            "only one TM slot is ready, then rescales up the moment the next TM "
            "registers — and that rescale CANCELS the in-flight checkpoint and "
            "restarts the whole job ('Checkpoint Coordinator is suspending'). On "
            "every cold start that guarantees the first checkpoint is thrown away "
            "before it can complete, so the job never makes durable progress and "
            "chains-raw stays empty. p=1 needs a single slot, never rescales, and "
            "runs one Beam (process-mode) harness — plenty for the current event "
            "rate while keeping checkpoints stable."
        ),
    )

    flink_checkpoint_interval_ms: int = Field(
        default=60000,
        ge=1000,
        description="Checkpoint interval in milliseconds",
    )
    flink_checkpoint_timeout_ms: int = Field(
        default=900000,
        ge=10000,
        description=(
            "Checkpoint timeout in milliseconds. Sized for the correlation-job "
            "cold start: its process-mode KeyedBroadcastProcessFunction rebuilds "
            "broadcast state by replaying the full meta-topic history (active-"
            "threats/hos-rules/chains-config) from earliest, and the first Beam "
            "bundle that drains that replay must finish before the checkpoint "
            "barrier can pass. A 5-min timeout expired mid-replay and — with "
            "tolerable-failed-checkpoints=0 — restarted the job into a cold "
            "replay again (perpetual loop, zero completed checkpoints, no durable "
            "progress). 15 min comfortably covers the replay; once the "
            "first checkpoint completes, failovers restore state and skip the "
            "replay entirely, so the longer ceiling only applies on cold start."
        ),
    )
    agent_checkpoint_timeout_ms: int = Field(
        default=180000,
        ge=10000,
        description=(
            "Checkpoint timeout for the AGENT-job only (overrides "
            "flink_checkpoint_timeout_ms when the agent entrypoint passes it). The "
            "agent has no cold-start broadcast replay, so it does not need the "
            "correlation-job's 15-min ceiling. NOTE: the chains-analysed sink now "
            "runs AT_LEAST_ONCE, so the EOS coupling below is currently DORMANT — "
            "output visibility no longer waits on checkpoint commit. The constraint "
            "still matters if chains-analysed is ever switched back to EXACTLY_ONCE: "
            "it MUST stay below flink_transaction_timeout_ms, because the EOS sink "
            "commits its Kafka transaction only when a checkpoint completes, and the "
            "broker aborts any transaction open longer than transaction.timeout.ms — "
            "so transaction.timeout.ms must exceed the worst-case checkpoint duration "
            "(plus interval + restart margin) or analysed chains are lost on a slow "
            "checkpoint. 3 min comfortably covers the agent's real durations "
            "(observed 15-31 s) once the per-attempt LLM timeout bounds operator stall."
        ),
    )
    flink_transaction_timeout_ms: int = Field(
        default=600000,
        ge=60000,
        description=(
            "Kafka producer transaction.timeout.ms for EXACTLY_ONCE sinks. "
            "Currently DORMANT for chains-analysed (it runs AT_LEAST_ONCE, no "
            "transactions); retained for the kafka_sink.py EOS default and any sink "
            "switched back to EXACTLY_ONCE. Must be GREATER than the EOS job's "
            "checkpoint timeout (agent_checkpoint_timeout_ms) — see that field. Kept "
            "at 10 min: safely "
            "above the agent's 3-min checkpoint timeout (interval + duration margin) "
            "and at/below the Kafka 4.x broker default transaction.max.timeout.ms "
            "(15 min), which caps how high this may go without a broker-side change."
        ),
    )
    flink_min_pause_between_checkpoints_ms: int = Field(
        default=30000,
        ge=0,
        description="Minimum pause between checkpoints in milliseconds",
    )
    flink_tolerable_failed_checkpoints: int = Field(
        default=3,
        ge=0,
        description=(
            "Number of consecutive checkpoint failures tolerated before the job "
            "is restarted (Flink default is 0 — any single failure restarts). "
            "0 is too brittle for the correlation-job cold start: a transient "
            "first-checkpoint expiry should not nuke the job into a fresh "
            "broadcast replay. Keeps EOS guarantees (this bounds failures, not "
            "successful checkpoints)."
        ),
    )
    flink_unaligned_checkpoints: bool = Field(
        default=False,
        description=(
            "Enable unaligned checkpoints (barrier overtakes in-flight data, "
            "in-flight buffers are snapshotted). Default OFF: the reference "
            "PyFlink 2.2 process-mode job (the detectflow-matchnode matcher) "
            "runs aligned, and the unaligned + process-mode python operator "
            "combination is unproven. The broadcast replay is incremental and "
            "fast, so there is no backpressure reason to enable it."
        ),
    )

    # ==========================================
    # STATE BACKEND & CHECKPOINTS CONFIGURATION
    # ==========================================

    state_backend: Literal["memory", "rocksdb"] = Field(
        default="rocksdb",
        description=(
            "State backend for storing operator state:\n"
            "  - memory: Heap-based (fast, but limited by JVM heap)\n"
            "  - rocksdb: Disk-based embedded DB (supports large state, incremental checkpoints)"
        ),
    )

    checkpoint_path: str = Field(
        default="file:///opt/flink/checkpoints",
        description=(
            "Checkpoint storage path:\n"
            "  - file:///opt/flink/checkpoints (default Docker volume)\n"
            "  - file:///mnt/nfs/flink-checkpoints (e.g. an NFS mount)"
        ),
    )

    # ==========================================
    # ROCKSDB PERFORMANCE TUNING
    # ==========================================

    rocksdb_writebuffer_size_mb: int = Field(default=64, ge=8, le=512)
    rocksdb_writebuffer_count: int = Field(default=3, ge=2, le=10)
    rocksdb_block_cache_size_mb: int = Field(default=256, ge=8, le=2048)
    rocksdb_block_size_kb: int = Field(default=4, ge=1, le=64)
    rocksdb_compaction_style: Literal["LEVEL", "UNIVERSAL", "FIFO"] = Field(default="LEVEL")
    rocksdb_thread_num: int = Field(default=4, ge=1, le=32)

    # ==========================================
    # LLM CONFIGURATION (provider-agnostic via OpenAI-compatible API)
    # ==========================================
    #
    # The agent-job uses the `openai` SDK against any OpenAI-compatible
    # `/v1/chat/completions` endpoint. Swap providers via `llm_base_url`
    # + `llm_api_key` + `llm_model` — no code change required. Examples:
    #
    #   - OpenAI:   https://api.openai.com/v1
    #   - Anthropic: https://api.anthropic.com/v1   (OpenAI-compat shim)
    #   - Ollama:   http://localhost:11434/v1       (api_key="ollama")
    #   - vLLM / Groq / Together / LocalAI: provider-specific URL
    #
    # The LLM endpoint is called directly (provider-agnostic).

    llm_api_key: SecretStr = Field(
        default=SecretStr("dummy"),
        description=(
            "API key for the OpenAI-compatible LLM endpoint. SecretStr — never "
            "logged. Use 'dummy' for local servers that don't require auth (vLLM, Ollama)."
        ),
    )
    llm_base_url: str = Field(
        default="https://api.openai.com/v1",
        description="Base URL for the OpenAI-compatible chat-completions endpoint",
    )
    llm_model: str = Field(
        default="gpt-4o-mini",
        description="Model name passed to chat.completions.create(model=...)",
    )
    llm_max_tokens: int = Field(
        default=2048,
        ge=1,
        description="max_tokens cap on the LLM response",
    )
    llm_prompt_char_budget: int = Field(
        default=24_000,
        ge=1_000,
        description=(
            "Character budget for the LLM user prompt — advisory, NOT enforced. Conservative "
            "3 chars/token estimate — 24 000 chars ≈ 8 K tokens. The v3.2 prompt "
            "builder renders one representative event per (seq, rule, pipeline_id) "
            "group; the render almost always fits a typical chain, so the budget is a "
            "soft guide, not a hard cap — there is no truncation/cascade fallback."
        ),
    )
    llm_calls_per_minute: int = Field(
        default=60,
        ge=1,
        description=(
            "GLOBAL per-job LLM call budget (token bucket). Each parallel subtask "
            "receives `llm_calls_per_minute // flink_parallelism` (floor 1), so the "
            "aggregate call rate across all subtasks stays ≈ this value rather than "
            "parallelism × budget. Excess calls take the graceful-degradation path "
            "(null verdict) and bump `llm_calls_throttled_total`."
        ),
    )
    llm_throttle_max_wait_seconds: float = Field(
        default=10.0,
        ge=0,
        le=60,
        description=(
            "Max seconds to block waiting for a token-bucket permit before taking "
            "the throttled (null-verdict) degradation path. 0 = never wait (old "
            "behaviour: any burst above llm_calls_per_minute permanently null-"
            "verdicts the excess chains). A bounded wait converts short bursts "
            "into natural Flink backpressure instead of lost analyses. Keep small "
            "enough that worst-case per-record wall time (this wait + timeout × "
            "(llm_max_retries+1) + backoff) stays well below "
            "`agent_checkpoint_timeout_ms`."
        ),
    )
    llm_max_retries: int = Field(
        default=3,
        ge=0,
        le=10,
        description="Number of exponential-backoff retries on transient LLM errors",
    )
    llm_ssl_verify: bool = Field(
        default=True,
        description=(
            "Verify the LLM endpoint's TLS certificate. Keep True. A self-hosted "
            "endpoint with a self-signed / private-CA certificate is supported "
            "WITHOUT turning this off: point the standard `SSL_CERT_FILE` env at a "
            "PEM bundle containing that CA (httpx, under the openai SDK, honours it) "
            "— detectflow-backend mounts the bundle into the agent-job pods. Set to "
            "False only as a temporary escape hatch when the certificate cannot be "
            "supplied (e.g. it has no SAN for the endpoint's IP): the client then "
            "accepts ANY certificate, so traffic to the LLM is open to interception."
        ),
    )
    llm_request_timeout_seconds: float = Field(
        default=30.0,
        gt=0,
        description=(
            "Per-attempt request timeout (seconds) for the LLM call, passed to the "
            "OpenAI-compatible client. WITHOUT this, the SDK default read timeout is "
            "600 s — a hung/black-holing endpoint would block the Pemja task thread "
            "(and the checkpoint barrier) for up to 600 s per attempt. Bounding it "
            "makes the APITimeoutError → retry path actually fire and keeps the worst-"
            "case LLM wall-time per chain (timeout × (llm_max_retries+1) + backoff) "
            "safely below `agent_checkpoint_timeout_ms`. Keeping it below the "
            "checkpoint timeout also avoids stalling the checkpoint barrier (matters "
            "even under AT_LEAST_ONCE), and preserves the dormant EXACTLY_ONCE "
            "invariant (max LLM wall-time ≪ checkpoint timeout ≪ transaction timeout) "
            "should chains-analysed ever switch back to EOS."
        ),
    )

    # ==========================================
    # LOGGING CONFIGURATION
    # ==========================================

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Logging level",
    )
    log_format: Literal["console", "json"] = Field(
        default="json",
        description="Log output format: 'console' for human-readable, 'json' for Fluent Bit/Loki/ELK",
    )

    # ==========================================
    # VALIDATORS
    # ==========================================

    @field_validator("kafka_api_key", "kafka_api_secret")
    @classmethod
    def validate_sasl_credentials(cls, v, info):
        if info.data.get("kafka_auth_method") == "SASL" and not v:
            raise ValueError(f"{info.field_name} is required when KAFKA_AUTH_METHOD=SASL")
        return v

    @field_validator(
        "kafka_ssl_ca_location",
        "kafka_ssl_certificate_location",
        "kafka_ssl_key_location",
    )
    @classmethod
    def validate_ssl_certificates(cls, v, info):
        if info.data.get("kafka_auth_method") == "SSL" and not v:
            raise ValueError(f"{info.field_name} is required when KAFKA_AUTH_METHOD=SSL")
        return v

    # ==========================================
    # HELPER METHODS
    # ==========================================

    def get_input_topics_list(self) -> list[str]:
        """Parse kafka_input_topics CSV into list of topics."""
        return [t.strip() for t in self.kafka_input_topics.split(",") if t.strip()]

    def instance_label(self) -> str:
        """Token-safe label identifying this job instance (may be empty)."""
        raw = (
            self.correlation_pipeline_name or self.correlation_pipeline_id or self.job_id or ""
        ).strip()
        return _JOB_LABEL_UNSAFE.sub("-", raw).strip("-")

    def flink_job_name(self, base: str) -> str:
        """Per-instance Flink job name, e.g. ``correlation-job-customer-a``.

        Returns ``base`` unchanged when the label is empty or already equals it,
        so a single deployment (JOB_ID=correlation-job) keeps the exact
        name the integration helpers grep for.
        """
        label = self.instance_label()
        if not label or label == base:
            return base
        return f"{base}-{label}"

    def get_kafka_base_config(self) -> dict[str, str]:
        return {
            "bootstrap.servers": self.kafka_bootstrap_servers,
        }

    def get_kafka_auth_config(self) -> dict[str, str]:
        """Get Kafka authentication configuration (for librdkafka / Python clients)"""
        if self.kafka_auth_method == "SASL":
            return {
                "security.protocol": "SASL_SSL",
                "sasl.mechanisms": "PLAIN",
                "sasl.username": self.kafka_api_key.get_secret_value()
                if self.kafka_api_key
                else "",
                "sasl.password": (
                    self.kafka_api_secret.get_secret_value() if self.kafka_api_secret else ""
                ),
            }
        elif self.kafka_auth_method == "SSL":
            config = {
                "security.protocol": "SSL",
                "ssl.ca.location": self.kafka_ssl_ca_location,
                "ssl.certificate.location": self.kafka_ssl_certificate_location,
                "ssl.key.location": self.kafka_ssl_key_location,
            }
            if not self.kafka_ssl_check_hostname:
                config["ssl.endpoint.identification.algorithm"] = "none"
            if self.kafka_ssl_key_password:
                config["ssl.key.password"] = self.kafka_ssl_key_password.get_secret_value()
            if self.kafka_ssl_truststore_location:
                config["ssl.truststore.location"] = self.kafka_ssl_truststore_location
            if self.kafka_ssl_truststore_password:
                config["ssl.truststore.password"] = (
                    self.kafka_ssl_truststore_password.get_secret_value()
                )
            return config
        else:
            return {"security.protocol": "PLAINTEXT"}

    def _read_pem_file(self, file_path: str | None) -> str | None:
        if not file_path:
            return None
        try:
            from pathlib import Path

            return Path(file_path).read_text()
        except Exception:
            return None

    def get_kafka_flink_auth_config(self) -> dict[str, str]:
        """Get Kafka authentication config for PyFlink (Java Kafka client format).

        IMPORTANT: Java Kafka client uses different property names than librdkafka!
        - Truststore: ssl.truststore.type=PEM + ssl.truststore.location (file path works)
        - Keystore: ssl.keystore.type=PEM + ssl.keystore.certificate.chain (PEM content!)
                    + ssl.keystore.key (PEM content!)
        """
        if self.kafka_auth_method == "SASL":
            # JAAS values are double-quoted — escape backslash and quote so a
            # secret containing either cannot break out of the config string.
            def _jaas_escape(v: SecretStr | None) -> str:
                raw = v.get_secret_value() if v else ""
                return raw.replace("\\", "\\\\").replace('"', '\\"')

            jaas_config = (
                f"org.apache.flink.kafka.shaded.org.apache.kafka.common.security.plain.PlainLoginModule required "
                f'username="{_jaas_escape(self.kafka_api_key)}" '
                f'password="{_jaas_escape(self.kafka_api_secret)}";'
            )
            return {
                "security.protocol": "SASL_SSL",
                "sasl.mechanism": "PLAIN",
                "sasl.jaas.config": jaas_config,
                "enable.metrics.push": "false",
            }
        elif self.kafka_auth_method == "SSL":
            cert_content = self._read_pem_file(self.kafka_ssl_certificate_location)
            key_content = self._read_pem_file(self.kafka_ssl_key_location)

            config: dict[str, str] = {
                "security.protocol": "SSL",
                "ssl.truststore.type": "PEM",
                "ssl.truststore.location": self.kafka_ssl_ca_location,
                "enable.metrics.push": "false",
            }

            if cert_content and key_content:
                config["ssl.keystore.type"] = "PEM"
                config["ssl.keystore.certificate.chain"] = cert_content
                config["ssl.keystore.key"] = key_content

            if not self.kafka_ssl_check_hostname:
                config["ssl.endpoint.identification.algorithm"] = ""
            if self.kafka_ssl_key_password:
                # PEM keystores must use ssl.key.password — the Java client
                # rejects ssl.keystore.password with PEM ("SSL key store password
                # cannot be specified with PEM format") and fails at startup.
                config["ssl.key.password"] = self.kafka_ssl_key_password.get_secret_value()
            if self.kafka_ssl_truststore_location:
                config["ssl.truststore.type"] = "JKS"
                config["ssl.truststore.location"] = self.kafka_ssl_truststore_location
            if self.kafka_ssl_truststore_password:
                config["ssl.truststore.password"] = (
                    self.kafka_ssl_truststore_password.get_secret_value()
                )
            return config
        else:
            return {
                "security.protocol": "PLAINTEXT",
                "enable.metrics.push": "false",
            }

    def get_kafka_consumer_config(self) -> dict[str, str]:
        return {
            **self.get_kafka_base_config(),
            **self.get_kafka_auth_config(),
            "group.id": self.kafka_consumer_group,
            # librdkafka accepts only earliest|latest|none here — "committed" is a
            # KafkaOffsetsInitializer concept; fall back to its reset strategy.
            "auto.offset.reset": (
                self.kafka_starting_offset
                if self.kafka_starting_offset in ("earliest", "latest")
                else "earliest"
            ),
            "enable.auto.commit": "false",
        }

    def get_kafka_producer_config(self) -> dict[str, str]:
        return {
            **self.get_kafka_base_config(),
            **self.get_kafka_auth_config(),
            "acks": "all",
            "compression.type": "gzip",
        }


# ==========================================
# SINGLETON PATTERN
# ==========================================

_settings: Settings | None = None


def get_settings() -> Settings:
    """Get singleton settings instance"""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reload_settings() -> Settings:
    """Force reload settings (useful for testing)"""
    global _settings
    _settings = Settings()
    return _settings


# ==========================================
# INSTANCE IDENTITY GUARD
# ==========================================


class JobIdentityError(RuntimeError):
    """Raised when this instance cannot be told apart from another one."""


def assert_distinct_job_identity(settings: Settings) -> None:
    """Refuse to start (or warn) when JOB_ID cannot uniquely identify this job.

    ``job_id`` is the only thing separating two instances on one Kafka cluster.
    Sharing it collapses four scopes onto one key:

    1. **Committed offsets.** Group ids are ``{kafka_consumer_group}-{job_id}
       {suffix}`` (app/connectors/kafka_source.py), so both instances commit to
       the same group. Harmless for correlation-job (pinned to ``latest``;
       offsets only feed lag dashboards) but load-bearing for **agent-job**,
       whose source starts from ``committed``: a stateless redeploy resumes at
       whatever the other instance last committed, silently skipping chains or
       re-reading them through a paid LLM.
    2. **Lag monitoring.** Per-pipeline lag collapses into one group, so no
       dashboard can attribute lag to a customer.
    3. **EOS transactional-id prefixes** (``{job_id}-{topic}``,
       app/connectors/kafka_sink.py) — two instances sharing a prefix fence
       each other's producers. Dormant while both sinks are AT_LEAST_ONCE.
    4. **Activity ``entity_id``** — both instances report as the same entity,
       so the audit log cannot tell them apart.

    NB what this is *not*: Flink's ``KafkaSource`` (FLIP-27) assigns partitions
    from the JobManager's split enumerator and only ever *stores offsets* under
    the group id — it never joins the group. Verified on a live
    cluster: an actively-consuming job's group reports ``STATE=Empty``,
    ``#MEMBERS=0``, no assignment strategy. So two instances sharing a job_id
    do NOT split partitions and neither goes idle; they each read everything
    and clobber each other's committed offsets. Fail fast on that, not on a
    partition-stealing story the connector cannot produce.

    Scope: this catches the *default* job id, not every duplicate — two
    instances deliberately started on the same non-default id still both run.
    Uniqueness of real deployments comes from the control plane, which derives
    JOB_ID from the K8s deployment name.

    Also checks driver/worker divergence. ``run()`` assigns ``settings.job_id``
    from ``--job-id`` on the driver, but workers rebuild ``Settings()`` from the
    environment, so a CLI-only value means worker-emitted activity events carry
    a different ``entity_id`` than driver-emitted ones (and, for agent-job, the
    worker re-reads LLM config from the environment too).

    Called explicitly from both entrypoints — deliberately NOT a Pydantic
    validator, so constructing ``Settings()`` stays side-effect free (``make
    env-check`` builds one from ``.env.example``, which ships ``JOB_ID=local``).

    Raises:
        JobIdentityError: if job_id is empty/unsafe, or is still the default
            while pipeline identity vars are set (unless
            ``allow_default_job_id``).
    """
    # Lazy: a module-level import of app.config.logging would close an
    # import cycle with its `_auto_configure()` (see the note at the top).
    from app.config.logging import get_logger

    logger = get_logger(__name__)

    job_id = (settings.job_id or "").strip()
    pipeline_scoped = bool(settings.correlation_pipeline_id or settings.correlation_pipeline_name)

    if not _JOB_ID_SAFE.match(job_id):
        raise JobIdentityError(
            f"JOB_ID {job_id!r} is empty or contains characters unsafe for a Kafka "
            "group id / transactional-id prefix; use [A-Za-z0-9._-]+."
        )

    env_job_id = (os.environ.get("JOB_ID") or "").strip()
    if env_job_id != job_id:
        logger.warning(
            "JOB_ID env var does not match the effective job id — workers rebuild "
            "Settings() from the environment and will use the env value",
            effective_job_id=job_id,
            env_job_id=env_job_id or "(unset)",
        )

    if job_id == DEFAULT_JOB_ID:
        message = (
            "JOB_ID is still the default 'local'. Consumer groups, EOS "
            "transactional-id prefixes and the activity entity_id are all scoped "
            "by JOB_ID, so a second instance would commit offsets over this one's "
            "(agent-job resumes from committed offsets — chains get skipped or "
            "re-read through a paid LLM) and become indistinguishable in the audit "
            "log. Set a distinct JOB_ID env var per deployment."
        )
        if pipeline_scoped and not settings.allow_default_job_id:
            raise JobIdentityError(message)
        logger.warning(message, pipeline_scoped=pipeline_scoped)
