# Prime Detect Agent
[![Version](https://img.shields.io/badge/version-2.3.3-blue.svg)](pyproject.toml)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/release/python-3110/)
[![Apache Flink 2.2](https://img.shields.io/badge/Flink-2.2-green.svg)](https://flink.apache.org/)

Attack Chains for Prime Detect: two Apache Flink jobs that correlate tagged Sigma detections into attack chains and analyse each chain with an LLM.
This project is a component of Prime Detect OSS by SOC Prime. See its [README](https://github.com/socprime/detectflow-main) for more details and instructions.

## Features

- **Correlation** — matches tagged events from [Prime Detect Match Node](https://github.com/socprime/detectflow-matchnode) against Higher-Order Sigma (HoS) rules and builds a chain per rule, host and time window once enough of the rule's steps are seen.
- **LLM analysis** — each chain is sent to an OpenAI-compatible LLM (OpenAI, Ollama, vLLM, …), which returns a verdict, confidence and summary.
- **Live configuration** — Active Threats, HoS rules and chain settings (coverage threshold, window override, excluded threats) are delivered over Kafka and applied without restarting the jobs. The input pipelines of a correlation job are fixed at startup by `KAFKA_INPUT_TOPICS`.
- **Multi-tenancy** — run one job pair per correlation pipeline, each with its own `JOB_ID`, topics and `CORRELATION_PIPELINE_ID`; chain ids are scoped by the pipeline.

## How It Works

```
tagged events (from Match Node pipelines)
       │
       ▼
correlation-job ── Active Threats, HoS rules, chains config
       │
       ▼
detectflow.chains-raw
       │
       ▼
agent-job ── OpenAI-compatible LLM
       │
       ▼
detectflow.chains-analysed  →  Prime Detect Backend
```

The two jobs run as separate Flink applications. In Prime Detect both are deployed by [Prime Detect Backend](https://github.com/socprime/detectflow-backend) for each correlation pipeline.

## Project Structure

```
├── app/
│   ├── config/           # Settings, logging
│   ├── connectors/       # Kafka source/sink
│   ├── core/             # Chain id and window helpers
│   ├── jobs/
│   │   ├── correlation/  # correlation-job entry point
│   │   └── agent/        # agent-job entry point
│   ├── operators/        # Correlation, chain buffer, LLM agent and client
│   └── observability/    # Metrics
├── lib/                  # Flink Kafka connector and zstd JARs
├── tests/
├── Dockerfile.correlation
├── Dockerfile.agent
├── pyproject.toml
└── .env.example
```

## Requirements

- Python 3.11
- Java 11 or 17 (for PyFlink)
- Kafka
- An OpenAI-compatible LLM endpoint (agent-job only)

## Configuration

Copy `.env.example` to `.env` and fill in:

- **Kafka connection**: `KAFKA_BOOTSTRAP_SERVERS`, `KAFKA_AUTH_METHOD` (`SASL` / `SSL` / `PLAINTEXT`; the code default is `SASL`) and the matching credentials (`KAFKA_API_KEY` / `KAFKA_API_SECRET` for SASL, `KAFKA_SSL_*` certificate paths for SSL).
- **Input** (correlation-job only): `KAFKA_INPUT_TOPICS` — comma-separated tagged-events topics.
- **Job**: `JOB_ID` — unique per deployment; it scopes Kafka consumer groups.
- **LLM** (agent-job only): `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL`. For an endpoint with a private CA, point `SSL_CERT_FILE` at its PEM bundle.

When a job pair serves one correlation pipeline (this is how Prime Detect Backend deploys them), also set:

- `CORRELATION_PIPELINE_ID` (the pipeline's UUID) and `CORRELATION_PIPELINE_NAME`;
- the pipeline's own topics: `KAFKA_CHAINS_CONFIG_TOPIC`, `KAFKA_CHAINS_RAW_TOPIC`, `KAFKA_CHAINS_ANALYSED_TOPIC`.

All other settings (shared topics, checkpoints, parallelism, logging, LLM limits) have working defaults; see the comments in `.env.example`.

## Running

### Docker images

```bash
docker build -f Dockerfile.correlation -t detectflow-agent-correlation .
docker build -f Dockerfile.agent -t detectflow-agent-agent .
```

Prime Detect Backend uses these images for correlation pipelines.

### Locally (for development)

```bash
uv sync --all-extras    # PyFlink and flink-agents are extras
cp .env.example .env    # then fill in Kafka and the LLM endpoint

uv run python -m app.jobs.correlation --input-topics topic_a,topic_b
uv run python -m app.jobs.agent
```
