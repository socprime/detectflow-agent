"""Structured logging configuration using structlog.

Provides consistent, machine-parseable logging across the application
with human-readable console output for development.
"""

import builtins
import logging
import sys
from typing import Any

import structlog

# Monkey-patch print() to ALWAYS ignore flush parameter
# This is necessary because Flink's CustomPrint doesn't support it.
# Sentinel-guarded: on a module reload (importlib.reload, Pemja re-import)
# the already-installed wrapper would otherwise be captured as the
# "original", chaining a new wrapper around the old one on every reload.
if not getattr(builtins.print, "_detectflow_flink_safe", False):
    _original_print = builtins.print

    def _flink_safe_print(*args, **kwargs):
        """Print function that ignores flush parameter for Flink's CustomPrint"""
        # Remove flush parameter if present
        kwargs.pop("flush", None)
        return _original_print(*args, **kwargs)

    _flink_safe_print._detectflow_flink_safe = True  # reload sentinel

    # Apply monkey-patch globally - it's safe even if not in Flink environment
    builtins.print = _flink_safe_print


def configure_logging(log_level: str = "INFO", log_format: str = "console") -> None:
    """Configure structlog with sensible defaults.

    Features: structured key-value pairs, ISO8601 timestamps, colored console
    output (dev), JSON output (production), stdlib integration, context vars.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_format: Output format — ``"console"`` (human-readable, default)
            or ``"json"`` (Fluent Bit / Elasticsearch / Loki).
    """
    # Convert string level to logging constant
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    # Configure standard logging (for compatibility with libraries)
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=numeric_level,
    )

    # Suppress noisy libraries
    logging.getLogger("apache_beam").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("kafka").setLevel(logging.WARNING)
    logging.getLogger("flink_agents").setLevel(logging.WARNING)

    # Configure structlog processors
    shared_processors = [
        # Add log level
        structlog.stdlib.add_log_level,
        # Add logger name
        structlog.stdlib.add_logger_name,
        # Add timestamp in ISO8601 format
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        # Stack info on exceptions
        structlog.processors.StackInfoRenderer(),
        # Format exceptions
        structlog.processors.format_exc_info,
        # Decode unicode
        structlog.processors.UnicodeDecoder(),
    ]

    # Choose renderer based on format
    if log_format.lower() == "json":
        # JSON format for log aggregation (Fluent Bit, Loki, Elasticsearch)
        renderer = structlog.processors.JSONRenderer()
    else:
        # Console format. Disable colors when stdout isn't a real TTY:
        #   - Flink process-mode workers replace stdout with `CustomPrint`
        #   - Pemja (thread-mode agent-job) replaces it with `StdOutCatcher`
        # Neither implements `isatty()`, so a naive call would AttributeError
        # during agent boot. Defensive lookup keeps both paths safe.
        in_flink_env = hasattr(sys.stdout, "print") and "CustomPrint" in type(sys.stdout).__name__
        isatty = getattr(sys.stdout, "isatty", None)
        is_tty = bool(isatty and isatty())
        renderer = structlog.dev.ConsoleRenderer(
            colors=False if in_flink_env else is_tty,
            exception_formatter=structlog.dev.plain_traceback,
        )

    structlog.configure(
        processors=[
            *shared_processors,
            # Prepare for stdlib logging
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        # Logger factory
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=False,
    )

    # Configure the formatter for standard logging integration
    formatter = structlog.stdlib.ProcessorFormatter(
        # These run ONLY on `logging` entries
        foreign_pre_chain=shared_processors,
        # These run on ALL entries (structlog + logging)
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    # Update root logger handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(numeric_level)


def get_logger(name: str | None = None) -> Any:
    """Get a structlog logger instance.

    Args:
        name: Logger name (usually ``__name__``).

    Returns:
        Structlog logger with bound context.

    Example:
        >>> logger = get_logger(__name__)
        >>> logger.info("processing_started", event_count=100, window_id=5)
    """
    return structlog.get_logger(name)


def bind_context(**kwargs: Any) -> None:
    """Bind context variables to all subsequent log calls in this thread.

    Useful for adding ``instance_id``, ``key``, or ``correlation_id`` that
    should appear in all logs from this point.

    Args:
        **kwargs: Key-value pairs to bind.

    Example:
        >>> bind_context(instance_id=2, key="dc01")
        >>> logger.info("window_started")  # Will include instance_id and key
    """
    structlog.contextvars.bind_contextvars(**kwargs)


def unbind_context(*keys: str) -> None:
    """Remove context variables.

    Args:
        *keys: Keys to unbind.

    Example:
        >>> unbind_context("instance_id", "key")
    """
    structlog.contextvars.unbind_contextvars(*keys)


def clear_context() -> None:
    """Clear all context variables"""
    structlog.contextvars.clear_contextvars()


# Auto-configure logging at import time using settings.
# This ensures logging is configured before any module-level get_logger() calls,
# and works correctly in Pemja threads where the job's configure_logging() may not apply.
def _auto_configure() -> None:
    """Bootstrap logging from Settings at import time.

    Ensures logging is configured before any module-level ``get_logger()``
    calls and works in Pemja threads where the job's ``configure_logging()``
    may not have been invoked.

    Settings construction can fail with an incomplete env — e.g. no
    ``KAFKA_BOOTSTRAP_SERVERS`` and no ``.env`` in cwd (bare tooling imports,
    fresh checkouts). Letting that Pydantic ValidationError escape would make
    ANY ``import app.config.logging`` hard-fail — a confusing failure shape
    for a logging bootstrap. Fall back to safe defaults (INFO / console) and
    proceed; the job entrypoint re-runs ``configure_logging()`` once real
    settings load, so production output is unaffected.
    """
    try:
        from app.config.settings import get_settings

        s = get_settings()
        log_level, log_format = s.log_level, s.log_format
    except Exception as exc:  # noqa: BLE001 — any settings failure ⇒ defaults
        sys.stderr.write(
            f"app.config.logging: settings unavailable ({type(exc).__name__}); "
            "falling back to default logging config (INFO, console)\n"
        )
        log_level, log_format = "INFO", "console"
    configure_logging(log_level=log_level, log_format=log_format)


_auto_configure()
