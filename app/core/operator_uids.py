"""Frozen Flink operator uids for correlation-job and agent-job.

Flink derives an operator's state handle from its ``uid()`` when one is set and
from its position in the job graph when one is not; both jobs deploy with
``upgradeMode: last-state``, so a topology change under auto-generated ids
restores into an incompatible graph.

**These strings are a contract with on-disk state. NEVER change a released
value** — a rename is a state deletion. Adding a constant is safe. Keyed by
ROLE, never by topic name / job id / pipeline id: one image must produce the
same uids for every correlation-pipeline instance.
"""

from typing import Final, Literal

MetaRole = Literal["active_threats", "hos_rules", "chains_config"]
META_ROLES: Final[tuple[MetaRole, ...]] = ("active_threats", "hos_rules", "chains_config")

CORRELATION_TAGGED_EVENTS_SOURCE: Final = "correlation-tagged-events-source"
CORRELATION_TAGGED_EVENTS_BRIDGE: Final = "correlation-tagged-events-bridge"
CORRELATION_MATCHER: Final = "correlation-hos-matcher"
CORRELATION_CHAINS_RAW_SINK: Final = "correlation-chains-raw-sink"

CORRELATION_META_SOURCE: Final[dict[MetaRole, str]] = {
    r: f"correlation-meta-source-{r.replace('_', '-')}" for r in META_ROLES
}
CORRELATION_META_TOMBSTONE_FILTER: Final[dict[MetaRole, str]] = {
    r: f"correlation-meta-tombstone-filter-{r.replace('_', '-')}" for r in META_ROLES
}
CORRELATION_META_TAG: Final[dict[MetaRole, str]] = {
    r: f"correlation-meta-tag-{r.replace('_', '-')}" for r in META_ROLES
}

# The flink-agents operator itself is NOT addressable from Python: to_datastream()
# returns the downstream cloudpickle-decode map, not the agent operator
# (flink_agents 0.2.0, runtime/remote_execution_environment.py). Its id stays
# auto-generated — acceptable because agent-job's arity is fixed (one source, one
# topic) and correlation-pipeline membership never edits its graph.
AGENT_CHAINS_RAW_SOURCE: Final = "agent-chains-raw-source"
AGENT_CHAIN_PARSE_BRIDGE: Final = "agent-chain-parse-bridge"
AGENT_OUTPUT_DECODE: Final = "agent-output-decode"
AGENT_CHAINS_ANALYSED_SINK: Final = "agent-chains-analysed-sink"
