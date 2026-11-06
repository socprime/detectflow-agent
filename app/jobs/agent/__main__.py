"""Agent-job entrypoint (Attack Chains).

Thread-mode (Pemja) PyFlink job that consumes chain records from
``detectflow.chains-raw``, runs them through ``ChainAnalysisAgent`` via
flink-agents, and emits enriched records to ``detectflow.chains-analysed``.

Pipeline shape:

  KafkaSource(chains-raw, committed offsets)
    → .flat_map(ParseChainFlatMap)        # bridge Java String → Python BaseModel; drops poison pills
    → AgentsExecutionEnvironment.from_datastream(key_selector=chain_id)
        .apply(ChainAnalysisAgent())      # emits OutputEvent(output=json str)
        .to_datastream(output_type=Types.STRING())
    → KafkaSink(chains-analysed, AT_LEAST_ONCE)

The source starts from the consumer group's COMMITTED offsets (EARLIEST
fallback for a brand-new group): a stateless redeploy resumes where the
group left off instead of re-reading the whole retained chains-raw topic
through a paid LLM. Checkpoint/savepoint state still wins on restore.

`key_selector=chain_id` keys the Flink-internal exchange into the agent
stage, so one chain's revisions are processed by a single subtask in
arrival order. This keying is INTERNAL only — the chains-analysed Kafka
records are written with NULL keys (sticky/round-robin topic
partitioning); cross-revision ordering on the wire is handled by the
consumer's monotonic-revision guard in the control plane.

The ``output_type=Types.STRING()`` on ``to_datastream`` tells PyFlink to
hand the JVM a real ``java.lang.String`` (not a pickled byte[]) so the
Kafka sink's ``SimpleStringSchema`` can serialize it. Pairs with the
agent action's ``OutputEvent(output=analysed.model_dump_json())``.

Run with::

    python -m app.jobs.agent
"""

import argparse
import os
import sys

from dotenv import load_dotenv
from flink_agents.api.execution_environment import AgentsExecutionEnvironment
from pyflink.common import Configuration, WatermarkStrategy
from pyflink.common.typeinfo import Types
from pyflink.datastream import StreamExecutionEnvironment
from pyflink.datastream.connectors.kafka import DeliveryGuarantee
from pyflink.datastream.functions import FlatMapFunction

from app.config.logging import get_logger
from app.config.settings import Settings, assert_distinct_job_identity, get_settings
from app.connectors.kafka_sink import create_kafka_sink
from app.connectors.kafka_source import create_kafka_source
from app.core import operator_uids
from app.jobs._flink_env import configure_flink_environment, ensure_pythonpath_for_workers
from app.observability.activity import ENTITY_NAME_AGENT, get_activity_reporter
from app.observability.metrics import Metrics
from app.operators import correlation_agent
from app.operators.chain_models import ChainRaw
from app.operators.correlation_agent import ChainAnalysisAgent
from app.operators.llm_client import LlmClient

load_dotenv()

logger = get_logger(__name__)

# Base Flink JOB name — suffixed with the instance label by
# `settings.flink_job_name()` so one agent-job per correlation pipeline is
# distinguishable in the Flink UI and in metric scopes, while the legacy single
# deployment (JOB_ID=agent-job) keeps the bare name. Operator uid()/name()
# values are NOT per-instance: they are frozen by role in
# app/core/operator_uids.py because they address on-disk state.
AGENT_JOB_BASE_NAME = "agent-job"


class ParseChainFlatMap(FlatMapFunction):
    """Parse chains-raw records into ``ChainRaw``; DROP unparseable garbage.

    flat_map bridge: yields exactly one model for a valid record, nothing for a
    poison pill. A raising parser here fails the source chain and crash-loops
    the whole job on the same record forever (e.g. a stray
    ``{"_probe": "kafka-health-check"}`` produced into chains-raw). The data path must be poison-pill
    tolerant: log + drop, never raise.

    A rich function (not a bare generator) so drops are a REAL Flink metric:
    a WARN log line scrolls away, but ``records_dropped_total`` ticking up is
    what dashboards/alerts can see when something starts producing garbage
    into chains-raw.
    """

    def __init__(self) -> None:
        # Stub-mode fallback so the function stays directly callable in unit
        # tests (and never crashes if Flink ever invoked flat_map before
        # open()); open() swaps in the JVM-backed handle.
        self._metrics = Metrics()

    def open(self, runtime_context) -> None:
        """Bind the metrics façade to the real JVM MetricGroup (live mode)."""
        self._metrics = Metrics(runtime_context)

    def flat_map(self, raw_str: str):
        """Yield one ``ChainRaw`` for a valid record, nothing for a poison pill."""
        try:
            yield ChainRaw.model_validate_json(raw_str)
        except Exception as exc:  # noqa: BLE001 — any malformed record is dropped, not fatal
            self._metrics.inc("records_dropped_total")
            logger.warning(
                "unparseable chains-raw record dropped",
                error=str(exc)[:500],
                sample=raw_str[:200] if isinstance(raw_str, str) else repr(raw_str)[:200],
            )


def _chain_id_key(chain: ChainRaw) -> str:
    return chain.chain_id


# Worst-case single restart delay under the exponential-delay restart strategy
# configured in app/jobs/_flink_env.py (restart-strategy.exponential-delay.
# max-backoff = "2 min"). The values there are plain config strings — not
# importable — so we mirror the ceiling here as a named constant; if the
# strategy in _flink_env.py changes, update this too.
MAX_RESTART_BACKOFF_MS = 120_000

# Safety margin on top of (checkpoint timeout + restart backoff): covers the
# slack the "≫" in the rule below implies — barrier alignment, sink commit latency,
# and clock skew between the job and the broker's transaction reaper.
EOS_TIMEOUT_MARGIN_MS = 60_000


def validate_eos_timeouts(settings: Settings) -> None:
    """Fail fast on an EXACTLY_ONCE checkpoint/transaction timeout misconfiguration.

    The chains-analysed Kafka transaction is committed only when a checkpoint
    completes, and the broker aborts any transaction open longer than
    ``transaction.timeout.ms``. The rule is transaction timeout ≫ max
    checkpoint duration + max restart duration: a transaction opened just
    before a failure must survive the worst-case checkpoint AND the restart
    backoff (during which nothing commits) or the broker aborts it and the
    analysed chains in it are lost. Require

        flink_transaction_timeout_ms >
            agent_checkpoint_timeout_ms + MAX_RESTART_BACKOFF_MS + margin

    rather than ship a silent data-loss footgun.
    """
    required_ms = (
        settings.agent_checkpoint_timeout_ms + MAX_RESTART_BACKOFF_MS + EOS_TIMEOUT_MARGIN_MS
    )
    if settings.flink_transaction_timeout_ms <= required_ms:
        raise ValueError(
            "EXACTLY_ONCE misconfiguration: flink_transaction_timeout_ms "
            f"({settings.flink_transaction_timeout_ms}) must exceed "
            f"agent_checkpoint_timeout_ms ({settings.agent_checkpoint_timeout_ms}) "
            f"+ max restart backoff ({MAX_RESTART_BACKOFF_MS}, mirrors "
            "restart-strategy.exponential-delay.max-backoff in _flink_env.py) "
            f"+ margin ({EOS_TIMEOUT_MARGIN_MS}) = {required_ms} — "
            "the chains-analysed Kafka transaction is committed on checkpoint and "
            "the broker aborts transactions older than transaction.timeout.ms, so a "
            "slow checkpoint plus a restart backoff longer than the transaction "
            "timeout loses data."
        )


def build_pipeline(
    env: StreamExecutionEnvironment,
    agents_env: AgentsExecutionEnvironment,
    settings: Settings,
) -> None:
    """Wire chains-raw → ChainAnalysisAgent → chains-analysed."""
    source = create_kafka_source(
        settings,
        settings.kafka_chains_raw_topic,
        consumer_group_suffix="-agent",
        # "committed", NOT "earliest": every chains-raw record this job reads is
        # a paid LLM call, and "earliest" ignores the group's committed offsets —
        # any stateless redeploy (no checkpoint/savepoint restore) would re-read
        # the entire retained topic through the LLM. "committed" resumes where
        # the group left off, with an EARLIEST reset fallback so a brand-new
        # group still starts from the beginning exactly once (see
        # kafka_source.py). Checkpoint/savepoint state still wins on restore —
        # this initializer only applies to fresh starts.
        starting_offset_override="committed",
    )

    # Explicit uids on every addressable operator — Flink otherwise derives the
    # state handle from the operator's position in the graph, and the deployment
    # rolls with `upgradeMode: last-state`. `agent-chains-raw-source` owns the
    # chains-raw offsets: losing it makes a stateless redeploy re-read the
    # retained topic THROUGH A PAID LLM (see app/core/operator_uids.py).
    # Operator NAMES stay topic-free so the Flink UI is comparable across
    # correlation pipelines.
    raw_stream = (
        env.from_source(
            source=source,
            watermark_strategy=WatermarkStrategy.no_watermarks(),
            source_name="Agent Source (chains-raw)",
        )
        .uid(operator_uids.AGENT_CHAINS_RAW_SOURCE)
        .flat_map(ParseChainFlatMap())
        .uid(operator_uids.AGENT_CHAIN_PARSE_BRIDGE)
        .name("Parse ChainRaw")
    )

    # The flink-agents operator itself is not addressable from Python:
    # to_datastream() hands back the downstream cloudpickle-decode map, built
    # inside the Java helper CompileUtils.connectToAgent. Its id stays
    # auto-generated — acceptable because agent-job's arity is fixed (one source,
    # one topic) and correlation-pipeline membership never edits this graph.
    analysed_stream = (
        agents_env.from_datastream(input=raw_stream, key_selector=_chain_id_key)
        .apply(ChainAnalysisAgent())
        .to_datastream(output_type=Types.STRING())
        .uid(operator_uids.AGENT_OUTPUT_DECODE)
        .name("Agent Output Decode")
    )

    # AT_LEAST_ONCE (not EXACTLY_ONCE): chains-analysed output must not be gated
    # on checkpoint completion. Under EXACTLY_ONCE the sink writes inside a Kafka
    # transaction that only commits when a checkpoint succeeds — so a slow/expiring
    # checkpoint (LLM backlog stalling the barrier) hides every analysed chain and
    # a restart fences the producer (InvalidProducerEpochException), discarding the
    # uncommitted records. Duplicates are safe: chain_id is deterministic and the
    # detectflow-backend consumer dedupes via the monotonic-revision guard.
    sink = create_kafka_sink(
        settings,
        settings.kafka_chains_analysed_topic,
        delivery_guarantee=DeliveryGuarantee.AT_LEAST_ONCE,
    )
    analysed_stream.sink_to(sink).uid(operator_uids.AGENT_CHAINS_ANALYSED_SINK).name(
        "Agent Sink (chains-analysed)"
    )

    logger.info(
        "Agent pipeline wired",
        source=settings.kafka_chains_raw_topic,
        sink=settings.kafka_chains_analysed_topic,
        llm_base_url=settings.llm_base_url,
        llm_model=settings.llm_model,
    )


def run(job_id: str) -> None:
    ensure_pythonpath_for_workers()

    settings = get_settings()
    settings.job_id = job_id
    # Before any Kafka source exists. This job is the one that really pays for a
    # shared job id: its source starts from COMMITTED offsets, so a twin
    # committing to the same group makes a stateless redeploy skip chains or
    # re-read them through a paid LLM. See assert_distinct_job_identity.
    assert_distinct_job_identity(settings)

    logger.info("Job starting up...", job_name="Agent Job", job_id=job_id)

    conf = Configuration()
    # Thread mode (Pemja) — required by flink-agents.
    conf.set_string("python.execution-mode", "thread")
    conf.set_string("python.executable", sys.executable)
    conf.set_string("python.client.executable", sys.executable)
    # flink-agents' AgentsExecutionEnvironment.execute() accepts NO job-name
    # argument and forwards to StreamExecutionEnvironment.execute(), which calls
    # setJobName only when a name is passed — so `pipeline.name` is the only
    # lever for naming this job, and it must be set BEFORE
    # get_execution_environment(conf) reads the config.
    job_name = settings.flink_job_name(AGENT_JOB_BASE_NAME)
    conf.set_string("pipeline.name", job_name)
    logger.info(
        "Flink environment created",
        python_mode="thread (pemja)",
        python_executable=sys.executable,
        job_name=job_name,
    )

    # The chains-analysed sink runs AT_LEAST_ONCE (see build_pipeline), so the
    # EXACTLY_ONCE checkpoint/transaction timeout invariant does not apply here.
    # If the sink is ever switched back to EXACTLY_ONCE, re-enable the fail-fast
    # guard below — it asserts transaction.timeout.ms > checkpoint timeout +
    # restart backoff + margin, without which the broker can abort an open
    # transaction on a slow checkpoint and silently lose analysed chains:
    #     validate_eos_timeouts(settings)

    env = StreamExecutionEnvironment.get_execution_environment(conf)
    configure_flink_environment(
        env, settings, checkpoint_timeout_ms=settings.agent_checkpoint_timeout_ms
    )

    agents_env = AgentsExecutionEnvironment.get_execution_environment(env)

    # Inject ChainAnalysisAgent dependencies — module-level container is the
    # workaround for `@action @staticmethod` not having access to `self`.
    correlation_agent.configure(
        llm_client=LlmClient(settings, Metrics()),
        metrics=Metrics(),
        settings=settings,
    )

    build_pipeline(env, agents_env, settings)

    # Job-health: announce the driver transition to running on the cross-team
    # `detectflow.activity` topic right before we block in execute(). The reporter is
    # a no-op when the activity topic is unset; per-event/heartbeat emits are
    # wired worker-side in correlation_agent (the driver instance does not
    # cross the Pemja boundary).
    reporter = get_activity_reporter(ENTITY_NAME_AGENT)
    reporter.emit_started()
    reporter.flush()

    logger.info("Job starting", job_name=job_name, job_id=settings.job_id)
    agents_env.execute()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Attack Chains agent job (chains-raw -> LLM -> chains-analysed)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--job-id",
        type=str,
        default=os.getenv("JOB_ID", "local"),
        help="Job identifier — used for transactional id prefixes and metrics labels",
    )
    args = parser.parse_args()

    run(job_id=args.job_id)


if __name__ == "__main__":
    main()
