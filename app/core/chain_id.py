"""Deterministic chain_id derivation.

The same
`(correlation_pipeline_id, hos_id, hostname, window_start)` MUST always yield
the same UUID. Every emitted chain revision shares the chain_id; the
`revision` counter disambiguates updates.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime


def build_chain_id(
    namespace: str | uuid.UUID,
    hos_id: str,
    hostname: str,
    window_start_iso: str,
    correlation_pipeline_id: str | None = None,
) -> str:
    """Compute deterministic chain_id, scoped to the owning correlation pipeline.

    Scoped per correlation pipeline: the id is
    ``uuid5(NS, "{correlation_pipeline_id}|{hos_id}|{hostname}|{window_start}")``.
    Two MSSP customers can each own a host called ``WKST-FIN-05`` and both be
    monitored against the same *catalogue* HoS rule; an unscoped three-part
    name would collide on exactly that pair and one customer's chain would
    overwrite the other's.

    ``correlation_pipeline_id`` empty/None ⇒ the three-part name
    ``{hos_id}|{hostname}|{window_start}`` (a single-instance deployment
    without a pipeline id).

    ``window_start_iso`` MUST be the canonical ISO-8601 ``Z`` string — use
    ``format_window_start``. ``CHAIN_ID_NAMESPACE`` stays global and identical
    across pipelines: scoping lives in the name, never in the namespace.
    """
    ns = namespace if isinstance(namespace, uuid.UUID) else uuid.UUID(namespace)
    parts = [hos_id, hostname, window_start_iso]
    if correlation_pipeline_id:
        parts.insert(0, correlation_pipeline_id)
    return str(uuid.uuid5(ns, "|".join(parts)))


def format_window_start(epoch_seconds: int) -> str:
    """Render an aligned tumbling-window start as `YYYY-MM-DDTHH:MM:SSZ`."""
    return datetime.fromtimestamp(epoch_seconds, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
