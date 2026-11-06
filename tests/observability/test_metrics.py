"""Metrics façade — stub mode used by every operator unit test, plus
fake-JVM tests for the live-mode registration/export paths (unit-conversion
on distributions, counter/gauge registration isolation)."""

from app.observability.metrics import Metrics


class _FakeCounter:
    def __init__(self):
        self.total = 0

    def inc(self, value):
        self.total += value


class _FakeDistribution:
    def __init__(self):
        self.values = []

    def update(self, value):
        self.values.append(value)


class _FakeMetricGroup:
    """Mimics the PyFlink MetricGroup surface the façade touches."""

    def __init__(self):
        self.children: dict[tuple[str, str], _FakeMetricGroup] = {}
        self.counters: dict[str, _FakeCounter] = {}
        self.gauges: dict[str, object] = {}
        self.distributions: dict[str, _FakeDistribution] = {}

    def add_group(self, key, value):
        return self.children.setdefault((key, value), _FakeMetricGroup())

    def counter(self, name):
        return self.counters.setdefault(name, _FakeCounter())

    def gauge(self, name, obj):
        self.gauges[name] = obj

    def distribution(self, name):
        return self.distributions.setdefault(name, _FakeDistribution())


class _FakeRuntimeContext:
    def __init__(self):
        self.group = _FakeMetricGroup()

    def get_metrics_group(self):
        return self.group


def test_counter_starts_at_zero_and_increments():
    m = Metrics()
    assert m.get_counter("events_dropped_no_hits") == 0
    m.inc("events_dropped_no_hits")
    m.inc("events_dropped_no_hits")
    m.inc("events_dropped_no_hits", 3)
    assert m.get_counter("events_dropped_no_hits") == 5


def test_counters_are_isolated_per_label_set():
    m = Metrics()
    m.inc("chains_emitted_total", hos_id="hos-a")
    m.inc("chains_emitted_total", hos_id="hos-a")
    m.inc("chains_emitted_total", hos_id="hos-b")
    assert m.get_counter("chains_emitted_total", hos_id="hos-a") == 2
    assert m.get_counter("chains_emitted_total", hos_id="hos-b") == 1
    # Unlabeled lookup is its own bucket — must not collapse with labeled ones
    assert m.get_counter("chains_emitted_total") == 0


def test_label_key_is_order_insensitive():
    m = Metrics()
    m.inc("seqs_hit_total", hos_id="hos-a", seq_num=3)
    # Same labels, different keyword order — same bucket
    assert m.get_counter("seqs_hit_total", seq_num=3, hos_id="hos-a") == 1


def test_gauges_overwrite_on_each_set():
    m = Metrics()
    m.set_gauge("hos_rules_loaded", 10)
    m.set_gauge("hos_rules_loaded", 12)
    m.set_gauge("hos_rules_loaded", 7)
    assert m.get_gauge("hos_rules_loaded") == 7


def test_histogram_appends_each_observation():
    m = Metrics()
    for v in (1.5, 2.3, 0.9):
        m.record("event_processing_latency_ms", v)
    assert m.get_histogram("event_processing_latency_ms") == [1.5, 2.3, 0.9]


def test_unset_gauge_returns_none():
    m = Metrics()
    assert m.get_gauge("never_set") is None


# ------- live-mode (fake JVM) tests -------


def test_record_seconds_metric_exports_as_ms_scaled():
    """`*_seconds` distributions export ×1000 under the `*_ms` name —
    int(round(seconds)) would collapse sub-second latencies to 0/1."""
    ctx = _FakeRuntimeContext()
    m = Metrics(ctx)
    m.record("llm_latency_seconds", 0.273)
    m.record("llm_latency_seconds", 1.5)

    assert "llm_latency_seconds" not in ctx.group.distributions
    assert ctx.group.distributions["llm_latency_ms"].values == [273, 1500]
    # The stub mirror keeps the raw float under the CALLER's name — callers
    # and their tests (e.g. test_llm_client) are deliberately untouched.
    assert m.get_histogram("llm_latency_seconds") == [0.273, 1.5]


def test_record_ms_metric_exports_as_is_rounded():
    ctx = _FakeRuntimeContext()
    m = Metrics(ctx)
    m.record("event_processing_latency_ms", 12.7)
    assert ctx.group.distributions["event_processing_latency_ms"].values == [13]


def test_record_seconds_with_labels_uses_one_distribution_per_label_set():
    ctx = _FakeRuntimeContext()
    m = Metrics(ctx)
    m.record("call_duration_seconds", 0.5, provider="a")
    m.record("call_duration_seconds", 0.25, provider="a")
    labelled = ctx.group.children[("provider", "a")]
    assert labelled.distributions["call_duration_ms"].values == [500, 250]
    assert len(labelled.distributions) == 1  # registered once, reused


def test_counter_and_gauge_with_same_name_and_labels_do_not_collide():
    """Regression: gauges used to mark registration in `_jvm_counter_cache`,
    so a counter inc'd after a same-keyed gauge found `True` instead of a
    counter handle and raised AttributeError in the data path."""
    ctx = _FakeRuntimeContext()
    m = Metrics(ctx)
    m.set_gauge("records_in_flight", 7)
    m.inc("records_in_flight")  # must not blow up on the gauge marker
    m.inc("records_in_flight", 2)

    assert ctx.group.counters["records_in_flight"].total == 3
    gauge_fn = ctx.group.gauges["records_in_flight"]
    assert gauge_fn() == 7
    m.set_gauge("records_in_flight", 4)
    assert gauge_fn() == 4  # single registration keeps serving latest value
    assert len(ctx.group.gauges) == 1


def test_gauge_then_counter_order_independent():
    ctx = _FakeRuntimeContext()
    m = Metrics(ctx)
    m.inc("queue_depth", 5)
    m.set_gauge("queue_depth", 9)
    assert ctx.group.counters["queue_depth"].total == 5
    assert ctx.group.gauges["queue_depth"]() == 9
