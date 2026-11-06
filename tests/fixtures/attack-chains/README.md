# Attack Chains — Test Fixtures

Canonical sample data for Attack Chains development and tests.

## Files

| File | What it is | Where in the flow |
|---|---|---|
| `at_envelope_apt28.json` | Active Threat envelope as published by `detectflow-backend` to `detectflow.active-threats` topic | upstream → correlation-job broadcast |
| `at_envelope_apt28_delete.json` | **Phase 1** logical-delete envelope (`{"id": "...", "deleted": true}`) — the message Flink reacts to during the cross-repo two-phase delete. The Phase 2 Kafka null-value tombstone follows on the same key for log compaction and is dropped at the deserializer | upstream → correlation-job broadcast |
| `hos_envelope_apt28.json` | HoS rule envelope as published by `detectflow-backend` to `detectflow.hos-rules` topic | upstream → correlation-job broadcast |
| `chains_config.json` | Configure dialog state envelope as published by `detectflow-backend` to `detectflow.chains-config.<correlation_pipeline_id>`. Carries `threshold_pct`, `correlation_window_seconds` (window override) and `excluded_active_threat_ids` (deny-list) — all applied hot, no restart. It does **not** carry membership: which detection pipelines feed the job is the job's `KAFKA_INPUT_TOPICS` subscription | upstream → correlation-job broadcast |
| `events_apt28.jsonl` | 5 tagged Sigma detection events from upstream `detectflow-matchnode`, covering 5/6 seqs of APT28 HoS on hostname `WKST-FIN-05`. One event per line | upstream → correlation-job main stream |
| `events_apt28_seq6.json` | Single seq-6 event (rule `5e000010-…`) at `09:55:00Z` — published **within** the 1800s window after the steady-state burst to drive a revision-2 emission (coverage 5/6 → 6/6). Used by the **window-update** e2e scenario | upstream → correlation-job main stream |
| `events_apt28_late.json` | Single seq-6 event with `timestamp=09:30:30Z` deliberately set far behind the watermark established by the steady-state burst. Drives the **late-drop** e2e scenario: must be discarded by the matcher's 60 s out-of-orderness allowance, `events_late_dropped` counter must increment, chain coverage must remain 5/6 (not 6/6 — that would mean late-drop failed silently) | upstream → correlation-job main stream |
| `events_apt28_expiry_tick.json` | Synthetic watermark-advancing tick at `10:01:00Z` on a throwaway hostname `WMK-ADVANCER` with a `sigma_rule_uuid` NOT mapped to any HoS seq. Sent after the `WKST-FIN-05` window (`09:30:00` + 1800 s) has closed: it must produce no chain and must not change the coverage of the `WKST-FIN-05` chain. Used by the **window-expiry** e2e scenario (buffer cleanup itself is processing-time driven and covered by the unit suite) | upstream → correlation-job main stream |
| `chain_raw_apt28_v1.json` | Sample chain record as emitted by `correlation-job` to `detectflow.chains-raw` (revision 1). **Includes inlined `active_threat` block** | correlation-job → agent-job |
| `chain_analysed_apt28_v1.json` | Same chain after `agent-job` LLM enrichment, as emitted to `detectflow.chains-analysed`. Includes `ai_summary`, `llm_verdict`, `llm_confidence`, `llm_review`, `analysed_at` | agent-job → detectflow-backend consumer |

## Usage

- **Unit tests** — load these as JSON / JSONL, drive operators directly without spinning up Kafka.
- **Integration tests** — feed into local Kafka via the synthetic producer to drive end-to-end scenarios.
- **Snapshot tests** — assert operator output matches `chain_raw_*` / `chain_analysed_*` shapes.

## Coverage scenario

The 5 events in `events_apt28.jsonl` hit seqs 1, 2, 3, 4, 5 (each via at least one ruleid). Seq 6 is intentionally NOT hit. With APT28 HoS having 6 seqs total → coverage = 5/6 = 83.33%, which crosses the default 60% threshold → chain fires (revision 1).

## E2E scenarios

| Scenario | Inputs | Expected on `chains-analysed` |
|---|---|---|
| **(a) steady state** | `events_apt28.jsonl` | One chain, `coverage≈83.33`, `revision=1`, AT inlined, LLM verdict present |
| **(b) window update** | `events_apt28.jsonl` + `events_apt28_seq6.json` | Same `chain_id`, `revision=2`, `coverage=100`, events list expanded |
| **(c) window expiry** | `events_apt28.jsonl` + `events_apt28_expiry_tick.json` | Revision 1 emitted; no further emissions for that window after the tick |
| **(d) late drop** | `events_apt28.jsonl` + `events_apt28_late.json` | Late event dropped, `events_late_dropped` counter ≥ 1, coverage stays at 83.33 (NOT 100 — that would mean late-drop failed) |

## Tagged-event schema

Each event carries the three matcher-pre-parsed top-level meta fields the correlation operator depends on:

| Field | Example | Purpose |
|---|---|---|
| `hostname` | `WKST-FIN-05` | Key dimension — chains are scoped by hostname. Matcher pre-parses per logsource config. Missing → drop with `events_dropped_missing_hostname`. |
| `timestamp` | `2026-04-22T09:31:11Z` | ISO-8601 UTC; drives late-drop and bucket assignment. |
| `pipeline_id` | `11111111-1111-4111-8111-111111111111` | Detection pipeline that produced the event. Copied to `events[].pipeline_id` and used as the agent prompt's `(seq, rule, pipeline_id)` grouping key. Never a correlation filter — isolation is the Kafka subscription. Missing → counter `events_missing_pipeline_id`, event still correlates. |

Some fixtures still carry a `source_topic` value. It is inert: destination topic names left the
contract entirely (they are SIEM output, not correlation input), and no operator reads the field.

Plus the detection metadata, now nested under a single `detectflow{}` block, and the ECS-shaped `parsed_event{}` (post-matcher parse). The `detectflow{}` block carries:

| Field | Example | Purpose |
|---|---|---|
| `detectflow.processed_at` | `2026-04-22T09:31:11.600Z` | ISO-8601 UTC, ms precision, `Z` — when the matcher processed the event. |
| `detectflow.matchnode_version` | `1.1.0` | Matcher (`detectflow-matchnode`) package version that produced the detection. |
| `detectflow.matches[]` | see below | One entry per matched Sigma rule. The correlation operator reads `matches[].sigma_rule_uuid` for the inverted-index lookup and `matches[].rule_name` / `matches[].mitre_techniques` for chain-event enrichment. |

Each entry in `detectflow.matches[]`:

| Field | Example | Purpose |
|---|---|---|
| `sigma_rule_uuid` | `5e000002-0000-4000-8000-000000000002` | Sigma rule UUID — **the correlation key** matched against HoS `seqs[].rule_ids`. |
| `_rule_id` | control-plane `rules.id` | ID of the rule row in the control-plane `rules` table; **not** the correlation key (in production it differs from the Sigma UUID). |
| `rule_name` | `Mimikatz Credential Dumping` | Rule title — used for chain-event enrichment. |
| `severity` | `high` | Sigma rule level. |
| `mitre_techniques` | `["T1003"]` | ATT&CK technique ids — used for chain-event enrichment. |

> Presence of the `detectflow` key distinguishes matched from unmatched events: **unmatched** events carry **no** `detectflow` key at all (there are no longer any flat top-level `sigma_rule_ids` / `sigma_detections` fields).

The fixtures use two stable detection-pipeline UUIDs, so a single `(seq, rule)` can be exercised
across more than one pipeline in the prompt-grouping tests:

- `11111111-1111-4111-8111-111111111111` — seqs 1, 2, 3, 5
- `22222222-2222-4222-8222-222222222222` — seq 4

If a future scenario needs different broadcast config values (threshold, window override, AT
deny-list), drop a sibling file like `chains_config_<scenario>.json` and load it from the producer's
`--scenario` branch instead of editing this canonical envelope.

## Stability

Treat these fixtures as a contract. If a wire schema changes (e.g., new field added to chain envelope), update fixtures in the same PR.

## Determinism

`chain_id` in `chain_raw_apt28_v1.json` is computed as `uuid5(NAMESPACE_DNS, "40500000-0000-4000-8000-000000000028|WKST-FIN-05|2026-04-22T09:30:00Z")`. Re-deriving the UUID with the same inputs MUST yield the same value — chain_id is deterministic by design.

All event timestamps are pinned absolute (no relative "now()" derivation). Scenario assertions read these fixtures verbatim — never mutate timestamps in test code.
