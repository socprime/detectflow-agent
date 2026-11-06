"""Shared Flink environment helpers used by correlation-job and agent-job.

Both jobs need the same boilerplate:
- locate and add the Kafka connector JAR (different paths in container vs. local);
- configure state backend (RocksDB tuning) and checkpointing;
- propagate venv site-packages into PYTHONPATH so PyFlink's Python
  workers (process mode) and Pemja's embedded interpreter (thread mode)
  can resolve installed packages.

Keep this module dependency-free aside from PyFlink + app config so it can
be imported from any job entrypoint without circular imports.
"""

import os
import site
from pathlib import Path

from pyflink.datastream import StreamExecutionEnvironment

from app.config.logging import get_logger
from app.config.settings import Settings

logger = get_logger(__name__)


def ensure_pythonpath_for_workers() -> None:
    """Make venv site-packages visible to Flink's worker subprocesses.

    PyFlink's process-mode workers (Beam SDK harness) and thread-mode
    Pemja interpreter spawn under the JVM, which inherits PYTHONPATH from
    the launching shell — not from the venv that started the parent
    Python process. Without this, workers fail with ModuleNotFoundError
    on packages the parent imports fine (e.g. ``pemja``, ``app``).

    Idempotent. Should be called before ``StreamExecutionEnvironment``
    is created (i.e. before py4j boots the JVM).
    """
    paths = list(site.getsitepackages())

    user_site = site.getusersitepackages()
    if user_site:
        paths.append(user_site)

    workspace_root = str(Path(__file__).resolve().parent.parent.parent)
    paths.append(workspace_root)

    existing = os.environ.get("PYTHONPATH", "")
    parts = [p for p in existing.split(os.pathsep) if p]
    for p in paths:
        if p and p not in parts:
            parts.append(p)
    os.environ["PYTHONPATH"] = os.pathsep.join(parts)
    logger.info("PYTHONPATH propagated to workers", entries=len(parts))


KAFKA_CONNECTOR_JAR = "flink-sql-connector-kafka-4.0.1-2.0.jar"


def add_kafka_connector_jar(env: StreamExecutionEnvironment) -> None:
    """Add the Kafka connector JAR to the Flink environment.

    In a Flink container the JAR is already on the classpath under
    ``/opt/flink/lib``; locally we resolve it relative to the repo root and
    inject it dynamically.
    """
    jar_in_classpath = Path("/opt/flink/lib") / KAFKA_CONNECTOR_JAR

    if jar_in_classpath.exists():
        logger.info(
            "Kafka connector loaded",
            jar=KAFKA_CONNECTOR_JAR,
            path=str(jar_in_classpath),
            note="already in classpath",
        )
        return

    jar_path = Path(__file__).parent.parent.parent / "lib" / KAFKA_CONNECTOR_JAR
    if jar_path.exists():
        env.add_jars(f"file://{jar_path.absolute()}")
        logger.info("Kafka connector loaded", jar=KAFKA_CONNECTOR_JAR, path=str(jar_path))
    else:
        logger.warning(
            "Kafka connector jar not found",
            jar=KAFKA_CONNECTOR_JAR,
            checked_paths=[str(jar_in_classpath), str(jar_path)],
        )


def configure_flink_environment(
    env: StreamExecutionEnvironment,
    settings: Settings,
    *,
    checkpoint_timeout_ms: int | None = None,
) -> None:
    """Configure state backend, checkpointing, and parallelism for both jobs.

    ``checkpoint_timeout_ms`` overrides ``settings.flink_checkpoint_timeout_ms``
    when provided. The agent-job passes ``settings.agent_checkpoint_timeout_ms``
    (it has no cold-start broadcast replay, so it does not need correlation's
    15-min ceiling, and its checkpoint timeout must stay below the EOS sink's
    ``transaction.timeout.ms``). The correlation-job omits it and keeps the
    longer default.
    """
    add_kafka_connector_jar(env)
    effective_checkpoint_timeout_ms = (
        checkpoint_timeout_ms
        if checkpoint_timeout_ms is not None
        else settings.flink_checkpoint_timeout_ms
    )

    j_env = env._j_stream_execution_environment
    config = j_env.getConfiguration()

    if settings.state_backend == "rocksdb":
        config.setString("state.backend.type", "rocksdb")
        config.setString("state.backend.rocksdb.localdir", "/tmp/flink-rocksdb")
        config.setString("execution.checkpointing.incremental", "true")

        config.setString(
            "state.backend.rocksdb.writebuffer.size",
            str(settings.rocksdb_writebuffer_size_mb * 1024 * 1024),
        )
        config.setString(
            "state.backend.rocksdb.writebuffer.count",
            str(settings.rocksdb_writebuffer_count),
        )
        config.setString(
            "state.backend.rocksdb.block.cache-size",
            str(settings.rocksdb_block_cache_size_mb * 1024 * 1024),
        )
        config.setString(
            "state.backend.rocksdb.block.blocksize",
            str(settings.rocksdb_block_size_kb * 1024),
        )
        config.setString(
            "state.backend.rocksdb.compaction.style",
            settings.rocksdb_compaction_style,
        )
        config.setString("state.backend.rocksdb.thread.num", str(settings.rocksdb_thread_num))

        logger.info(
            "State backend configured",
            backend="rocksdb",
            incremental=True,
            localdir="/tmp/flink-rocksdb",
            writebuffer_size_mb=settings.rocksdb_writebuffer_size_mb,
            writebuffer_count=settings.rocksdb_writebuffer_count,
            block_cache_size_mb=settings.rocksdb_block_cache_size_mb,
            block_size_kb=settings.rocksdb_block_size_kb,
            compaction_style=settings.rocksdb_compaction_style,
            thread_num=settings.rocksdb_thread_num,
        )
    else:
        config.setString("state.backend.type", "hashmap")
        logger.info("State backend configured", backend="hashmap", incremental=False)

    env.set_parallelism(settings.flink_parallelism)
    logger.info("Parallelism configured", parallelism=settings.flink_parallelism)

    config.setString("state.checkpoints.dir", settings.checkpoint_path)
    logger.info("Checkpointing storage configured", path=settings.checkpoint_path)

    # Keep checkpoints when the job is cancelled (upgrades/redeploys cancel the
    # job!) — the Flink default, NO_EXTERNALIZED_CHECKPOINTS, discards them on
    # cancel, losing the keyed buffers / broadcast index between rollouts. The
    # FlinkDeployment's `flinkConfiguration` may override this.
    config.setString(
        "execution.checkpointing.externalized-checkpoint-retention",
        "RETAIN_ON_CANCELLATION",
    )

    env.enable_checkpointing(settings.flink_checkpoint_interval_ms)
    checkpoint_config = env.get_checkpoint_config()
    checkpoint_config.set_checkpoint_timeout(effective_checkpoint_timeout_ms)
    checkpoint_config.set_min_pause_between_checkpoints(
        settings.flink_min_pause_between_checkpoints_ms
    )
    # Tolerate transient checkpoint failures instead of restarting on the first
    # one (Flink default 0). The correlation-job's cold-start broadcast replay
    # can push the first checkpoint past its timeout; with 0 tolerance that
    # single expiry restarts the job into another cold replay — a perpetual
    # loop that never commits a checkpoint (and so never commits the EOS sink).
    # See `flink_tolerable_failed_checkpoints` in settings for the rationale.
    checkpoint_config.set_tolerable_checkpoint_failure_number(
        settings.flink_tolerable_failed_checkpoints
    )
    # Unaligned checkpoints — default OFF (see `flink_unaligned_checkpoints` in
    # settings). They were enabled while chasing the cold-start checkpoint
    # expiries, but the real causes were elsewhere (O(N²) broadcast replay +
    # the process-mode keyed-bundle wedge), and detectflow-matchnode's matcher,
    # the reference PyFlink 2.2 process-mode job, runs aligned. When enabled, aligned-checkpoint-timeout keeps the happy
    # path aligned and only switches to unaligned after the barrier stalls 30s.
    if settings.flink_unaligned_checkpoints:
        config.setString("execution.checkpointing.unaligned.enabled", "true")
        config.setString("execution.checkpointing.aligned-checkpoint-timeout", "30s")
    else:
        config.setString("execution.checkpointing.unaligned.enabled", "false")
    # Restart strategy — make it explicit instead of relying on the implicit
    # default. exponential-delay backs off transient failures (the cold-start
    # recovery this job depends on) with a BOUNDED max backoff so a crash loop
    # does not hot-spin the cluster, and resets the backoff after a sustained
    # healthy period. No hard failure cap here on purpose: the team's recovery
    # model favours eventual self-heal over a terminal FAILED that needs manual
    # intervention. Operators wanting FAILED on a persistent fault can override
    # to `failure-rate` via the FlinkDeployment `flinkConfiguration`.
    config.setString("restart-strategy.type", "exponential-delay")
    config.setString("restart-strategy.exponential-delay.initial-backoff", "10 s")
    config.setString("restart-strategy.exponential-delay.max-backoff", "2 min")
    config.setString("restart-strategy.exponential-delay.backoff-multiplier", "2.0")
    config.setString("restart-strategy.exponential-delay.reset-backoff-threshold", "10 min")
    config.setString("restart-strategy.exponential-delay.jitter-factor", "0.1")

    logger.info(
        "Checkpointing configured",
        interval_ms=settings.flink_checkpoint_interval_ms,
        timeout_ms=effective_checkpoint_timeout_ms,
        min_pause_ms=settings.flink_min_pause_between_checkpoints_ms,
        tolerable_failed_checkpoints=settings.flink_tolerable_failed_checkpoints,
        unaligned=settings.flink_unaligned_checkpoints,
    )
