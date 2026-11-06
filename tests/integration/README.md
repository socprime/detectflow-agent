# Integration stack

Local docker-compose stack that runs Attack Chains end-to-end against **two separate Flink session clusters** — one per job, each with its own JM + TM + ephemeral submitter. The two clusters never share slots, so the two jobs' Python operators never share a TaskManager (correlation can be switched to process mode with `CORRELATION_PYTHON_MODE=process`; agent is always thread mode).

> Pure application-mode (`standalone-job.sh start-foreground`) would be slightly cleaner but is incompatible with our `Dockerfile.*` layout: PyFlink in venv ships duplicate flink-dist / commons-cli jars that LinkageError against `/opt/flink/lib/`. Per-cluster session + submitter is the next-best isolation that keeps the Dockerfiles unchanged and prod-aligned.

## What's in the stack

Two prod-aligned images are built from the repo-root Dockerfiles
(`Dockerfile.correlation`, `Dockerfile.agent`). Integration and production share these
two Dockerfiles; there is no third "integration-only" image.

| Service | Image | Role |
|---|---|---|
| `kafka` | `apache/kafka:4.0.0` | Single-broker KRaft Kafka — host: `19092`, in-compose: `kafka:9092` |
| `topic-init` | `apache/kafka:4.0.0` | One-shot — creates the 5 `detectflow.*` topics + 3 pipeline destination topics, then exits |
| `llm-stub` | `tests/integration/llm-stub` | FastAPI returning canned OpenAI-compatible verdicts on `:8001` |
| `flink-correlation-jm` | `Dockerfile.correlation` | JobManager for the correlation cluster. Web UI on `:8081`. |
| `flink-correlation-tm` | `Dockerfile.correlation` | TaskManager for the correlation cluster (thread mode by default). Env vars consumed by `Settings()` at worker runtime live here. |
| `correlation-job` | `Dockerfile.correlation` | One-shot submitter — `flink run -py app/jobs/correlation/__main__.py ...` then exits. Env vars consumed by `Settings()` at job-graph build time live here. |
| `flink-agent-jm` | `Dockerfile.agent` | JobManager for the agent cluster. Web UI on `:8082`. Carries `flink-agents`. |
| `flink-agent-tm` | `Dockerfile.agent` | TaskManager for the agent cluster (thread/Pemja mode) — never shared with process-mode jobs. |
| `agent-job` | `Dockerfile.agent` | One-shot submitter — `flink run -py app/jobs/agent/__main__.py ...` then exits. |

## Bring it up

From the repo root:

```bash
make integration-up        # build images + start everything
make integration-status    # docker ps + Flink job list
make integration-logs      # tail all logs
make integration-down      # stop, keep volumes
make integration-clean     # stop + drop volumes (full reset)
```

The first build pulls Flink 2.2 (both images) + the flink-agents wheel (~400 MB, agent flavor only) so allow a few minutes. Subsequent `up`s use the layer cache.

### Ollama opt-in

`make integration-up-ollama` swaps the FastAPI stub for a real Ollama container running `llama3.2:3b`. Used for richer dev validation — **not** for CI (heavy, non-deterministic). The first run pulls the model inside the container.

## Topics provisioned

| Topic | Partitions | cleanup.policy |
|---|---|---|
| `detectflow.active-threats` | 1 | compact |
| `detectflow.hos-rules` | 1 | compact |
| `detectflow.chains-config` | 1 | compact |
| `detectflow.chains-raw` | 12 | delete |
| `detectflow.chains-analysed` | 12 | delete |
| `dest-windows-events-raw` | 1 | delete |
| `dest-powershell-logs-raw` | 1 | delete |
| `dest-cloudtrail-detections` | 1 | delete |

The destination names are harness Kafka topics the producer writes to (not a matcher filter). Isolation is membership → `detectflow.tagged-events.<pipeline_id>`.

## Troubleshooting

**Submitter exited with non-zero status.** The submitter container's success means "submission accepted by JM", not "job ran to completion". If `correlation-job` / `agent-job` exits 1, run `make integration-logs` and look for that block — `flink run` output (including any `Settings()` validation error from the submitter-side env load) is captured there.

**Job missing on a Flink Web UI but submitter exited 0.** Submission accepted but graph failed at deploy. Check the corresponding TM logs (`flink-correlation-tm` / `flink-agent-tm`) — Python worker `Settings()` validation failures, `ModuleNotFoundError`, and other runtime issues land there.

**Flink Web UI shows the job as FAILED.** Click into the job for the exception. The most likely cause on first stand-up is missing flink-agents JARs on the TM classpath. `Dockerfile.agent` ships flink-agents via the python wheel install (which drops JARs into `<venv>/lib/python3.11/site-packages/flink_agents/lib/flink-2.2/`), and PyFlink uploads them on submission via `add_jars` — but if the agent TM still can't find them, copy the agent JARs into `/opt/flink/lib/` in `Dockerfile.agent` (similar to how the kafka connector JAR is copied there).

**`Settings()` ValidationError on a TM container.** Settings load inside the Python worker on the TM, **not** the JM submitter. Per-cluster env vars (`KAFKA_AUTH_METHOD`, `LLM_*`, …) MUST be set on both the TM and the submitter service in compose. Mirrors prod: `flink-deployment.yaml.j2` mounts the same `configMapRef` + `secretRef` on both pod templates.

**Kafka transactional sink fails** (only if a sink is switched to EXACTLY_ONCE; both are AT_LEAST_ONCE). The compose file sets `KAFKA_TRANSACTION_MAX_TIMEOUT_MS=900000` to admit our 600s producer timeout (Kafka 4.x default is 15min — match producer ≤ broker). Don't lower it without also touching `app/connectors/kafka_sink.py`.

**Compose volumes pile up.** `make integration-clean` is the hard reset.

## Stub vs Ollama

The default stack (`make integration-up`) is deterministic — FastAPI stub, pinned fixture timestamps, scenario-by-scenario assertions in `tests/integration/test_*.py`. Local dev can substitute Ollama or run the producer manually against the running stack to poke shapes.
