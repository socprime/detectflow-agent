"""Thin metrics façade over PyFlink's `MetricGroup`.

Two modes:

- **Live**: constructed from a `RuntimeContext` inside an operator's `open()`.
  Counters/gauges/distributions are routed to the JVM `MetricGroup`, with
  Prometheus-style labels expressed as nested metric groups
  (`group.add_group(label, value).counter(name)`). Latency observations go to
  a JVM `Distribution` (min/max/mean/percentiles exported to the reporter).
- **Stub**: constructed with `Metrics()` (no runtime context), used by unit
  tests. Operations record into in-memory dicts so tests can assert "this
  counter was incremented N times under those labels" without the JVM.

A counter is registered (and a JVM-side metric is created) the first time
it is touched — this is the same lazy-registration pattern PyFlink itself
uses, so the matcher does not need a separate `register_metrics(...)` step.

## Why there is no per-correlation-pipeline label on every metric

Labels work (`add_group` creates a Flink *user variable*, which the Prometheus
reporter renders as a label), so a pipeline label is technically available
anywhere. It is deliberately used on exactly one identity metric
(`correlation_pipeline_info`, a COUNTER incremented once in
`HosCorrelationFunction.open()` — see the thread-mode warning below):

- `RuntimeContext.get_metrics_group()` is **operator-scoped** — PyFlink has no
  API for a job-wide constant label, so "everywhere" means adding it at every
  call site, and every user variable also lengthens the scope path for
  non-Prometheus reporters (JMX, SLF4J, InfluxDB), which fold variables into
  the metric *name*.
- Each correlation pipeline is its **own Flink application cluster / own job**,
  and Flink already exports `job_name` (per-instance since
  `Settings.flink_job_name`) and `job_id` as scope variables — every series is
  already separable, so a pipeline label would be redundant cardinality.
- A constant reporter-side label is a **cluster-config** concern
  (`metrics.reporter.<name>.scope.variables.additional` in `flinkConfiguration`
  — verify the key against the Flink 2.2 metrics reference before relying on
  it), i.e. control-plane template territory, not this repo's.

## Gauges are pull-based, and that is dangerous in thread mode

`set_gauge` registers a **Python callable** (`group.gauge(name, lambda: ...)`)
that Flink's `flink-metrics-*` thread invokes through Pemja on every metrics
poll. In thread mode that callback can outlive its embedded interpreter — when a
job is cancelled or restarted mid-poll, `MetricGauge.getValue()` →
`PyObject.invokeMethod` → `PyEval_AcquireThread` dereferences a freed thread
state and **SIGSEGVs the whole TaskManager JVM** (reproduced during
cancel/resubmit tests).

`inc()` has no such exposure: the value lives in a JVM `Counter` and Python only
ever pushes into it. Prefer a counter wherever a metric does not have to be a
snapshot — the identity metric is a counter for exactly this reason. The six
gauges in `HosCorrelationFunction` still carry the risk.
"""

from __future__ import annotations

from typing import Any


def _label_key(labels: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    """Stable hashable key for a label set."""
    return tuple(sorted((k, str(v)) for k, v in labels.items()))


class Metrics:
    """Operator-scoped metrics handle. Construct in `open()`, use everywhere."""

    # Cap on the per-(name, labels) in-memory sample list. The list exists for
    # unit-test introspection (and a console-log mirror); without a cap it grows
    # unbounded for the life of a 24/7 job — a slow memory leak. We only ever
    # need recent samples, so keep the last N.
    _HISTOGRAM_SAMPLE_CAP = 1024

    def __init__(self, runtime_context: Any | None = None):
        self._root = runtime_context.get_metrics_group() if runtime_context is not None else None
        # Stub state — also populated (capped) in live mode so tests / console
        # logs can observe values; the JVM Distribution handles the real export.
        self._counters: dict[tuple[str, tuple], int] = {}
        self._gauges: dict[tuple[str, tuple], int] = {}
        self._histograms: dict[tuple[str, tuple], list[float]] = {}
        # Cache of materialized JVM counter handles — registering twice with
        # the same labels would create two metrics under the same group path.
        self._jvm_counter_cache: dict[tuple[str, tuple], Any] = {}
        # Gauges get their OWN registration cache. They used to share
        # `_jvm_counter_cache` with a `True` marker — a counter and a gauge
        # under the same (name, labels) would then collide: whichever
        # registered second found the marker/handle of the first and either
        # skipped registration or called `.inc()` on `True`, raising
        # AttributeError straight into the data path.
        self._jvm_gauge_cache: dict[tuple[str, tuple], bool] = {}
        # Cache of materialized JVM Distribution handles (one per name+labels).
        self._jvm_distribution_cache: dict[tuple[str, tuple], Any] = {}

    # ------- counters -------

    def inc(self, name: str, value: int = 1, **labels: Any) -> None:
        """Increment a counter by ``value`` (default 1) under the given label set."""
        key = (name, _label_key(labels))
        self._counters[key] = self._counters.get(key, 0) + value
        if self._root is not None:
            counter = self._jvm_counter_cache.get(key)
            if counter is None:
                group = self._root
                for lk, lv in sorted(labels.items()):
                    group = group.add_group(lk, str(lv))
                counter = group.counter(name)
                self._jvm_counter_cache[key] = counter
            counter.inc(value)

    # ------- gauges -------

    def set_gauge(self, name: str, value: float, **labels: Any) -> None:
        """Gauges are *snapshot* values: every call overwrites the prior value.

        The JVM gauge API takes a callable; we close over the gauge cell so a
        single registration keeps returning the latest value. PyFlink gauges are
        integer-only (the Java contract returns a long), so the value is stored
        and reported as ``int``.
        """
        key = (name, _label_key(labels))
        self._gauges[key] = int(value)
        if self._root is not None and key not in self._jvm_gauge_cache:
            group = self._root
            for lk, lv in sorted(labels.items()):
                group = group.add_group(lk, str(lv))
            group.gauge(name, lambda k=key: self._gauges.get(k, 0))
            self._jvm_gauge_cache[key] = True  # marker — gauge registered

    # ------- distributions (latency observations) -------

    def record(self, name: str, value: float, **labels: Any) -> None:
        """Record one observation of a distribution metric (e.g. latency).

        Live mode pushes the value to a JVM-side ``Distribution`` so min / max /
        mean / percentiles are exported to the metrics reporter (Prometheus etc.).
        PyFlink distributions are **integer-valued**, so a seconds-unit metric
        would collapse every sub-second observation to 0 or 1. The JVM export
        therefore normalizes units: a name ending in ``_seconds`` is scaled
        ×1000 and exported under the same name with ``_seconds`` replaced by
        ``_ms``; names already ending in ``_ms`` export as-is (rounded). The
        rename happens here, NOT at call sites — callers keep recording in the
        unit their name claims. (No dashboard breakage: nothing currently
        exports the affected ``*_seconds`` metric — agent-job metrics run in
        stub mode.)

        The in-memory mirror keeps the RAW float value under the CALLER's name
        (full precision for test introspection), CAPPED at the last
        ``_HISTOGRAM_SAMPLE_CAP`` samples — an unbounded list would slowly leak
        memory in a long-running job.
        """
        key = (name, _label_key(labels))
        samples = self._histograms.setdefault(key, [])
        samples.append(value)
        overflow = len(samples) - self._HISTOGRAM_SAMPLE_CAP
        if overflow > 0:
            del samples[:overflow]
        if self._root is not None:
            if name.endswith("_seconds"):
                export_name = name[: -len("_seconds")] + "_ms"
                export_value = value * 1000.0
            else:
                export_name = name
                export_value = value
            export_key = (export_name, _label_key(labels))
            dist = self._jvm_distribution_cache.get(export_key)
            if dist is None:
                group = self._root
                for lk, lv in sorted(labels.items()):
                    group = group.add_group(lk, str(lv))
                dist = group.distribution(export_name)
                self._jvm_distribution_cache[export_key] = dist
            dist.update(int(round(export_value)))

    # ------- test introspection -------

    def get_counter(self, name: str, **labels: Any) -> int:
        """Return the current stub counter value (0 if never touched). Test-only."""
        return self._counters.get((name, _label_key(labels)), 0)

    def get_gauge(self, name: str, **labels: Any) -> float | None:
        """Return the latest stub gauge value, or ``None`` if never set. Test-only."""
        return self._gauges.get((name, _label_key(labels)))

    def get_histogram(self, name: str, **labels: Any) -> list[float]:
        """Return all recorded stub histogram values as a list. Test-only."""
        return list(self._histograms.get((name, _label_key(labels)), []))
