# log-analyzer

A log analyzer - an MCP component or Embeddable ambient agent that can analyze logs in a multi-agent environment.

## Project Description:

Incident management SLAs are time-bound — the faster the root cause is identified, the less damage is done. This project is both reactive and proactive: an embeddable AI ambient agent that monitors live audit logs for anomaly conditions, self-triggers the moment a threshold is crossed, and produces a fully grounded RCA report autonomously — every finding tied to an exact source span, every retrieval hypothesis verified directly against the corpus, no human needed to initiate triage.

The agent detects two classes of anomalies:
- **Error-rate spikes** — HTTP 4xx/5xx error rates exceeding a threshold (e.g. a 20% 404 spike from a vector cutoff misconfiguration)
- **Retrieval quality degradation** — clean 200 responses where the AI agent returns semantically incomplete data (e.g. a 46-point completeness drop in international travel policy answers caused by a stale RAG vector index)

### Problem:

Following the launch of an international travel discount offer, our concierge agent began streaming a 20% spike in 404 errors concentrated on multi-destination travel queries — the kind of pattern that, left undetected, escalates into a Priority 2 incident with a 15-minute initial response SLA and a 4-8 hour resolution clock. A subtler class of incident is even harder to catch: clean 200 responses where the agent silently returns incomplete policy information, with no HTTP errors to trigger conventional alerting.

### Call-To-Action:

An agent that catches both classes of incidents before they formally escalate — pinning the exact log line, tool call, or RAG retrieval failure responsible, with every claim traceable back to the exact evidence that proves it.

### User:

Any engineer who invokes the AI agent with a read-only, temporary access to our application/server log files and ADK agent audit log store via the CLI during incident triage — or whose live audit log stream triggers it autonomously the moment an anomaly threshold is crossed.

### Workflow automated:

The Log-Analyzer agent, running in ambient mode, detected the 20% spike in 404 errors directly from the concierge agent's streamed audit logs and triggered its own analysis pipeline overnight — no human intervention needed to start triage. As I signed in the next morning, a HITL approval request was waiting: the agent had assembled a complete RCA report identifying the Top-K cutoff as the root cause and was paused, pending my approval to file a Jira story. I reviewed the finding, approved, and the Jira story was filed and the incident marked triage completed. By the time I reached the office, the fix was already in progress, and I resumed my day as normal.

### Out of Scope / Known Limitations:

Compared to full-stack observability platforms (Splunk, Elastic, Datadog, Dynatrace, New Relic), this project deliberately does not attempt:
  Scale — no petabyte-scale ingestion/indexing; built for bounded sample log sets, not production-volume telemetry.
  Breadth — logs only. No metrics, traces, RUM, or infrastructure topology correlation.
  Dashboards/alerting — no visualization layer, no SLOs, no general-purpose alert/notification pipeline. The system consumes an existing incident-opened event and writes back exactly two narrow, single-purpose actions (one incident-status transition, one ticket) — it doesn't build incident management or ticketing as a platform.
  Production deployment maturity — no multi-tenancy, no long-term storage, no HA/scaling story.
  Incident-data tuning — no large historical incident corpus to tune confidence thresholds or severity heuristics against; patterns are hand-authored per skill, not learned at scale.

---

## Running Locally / Demo

### Prerequisites

```bash
# Install the agents CLI (one-time)
uv tool install google-agents-cli

# Install project dependencies
agents-cli install
```

Then choose how you want the agent to call the model:

**Option B — no GCP, Google AI Studio API key** (recommended for local demo)

Get a free key at https://aistudio.google.com → API Keys → Create, then export it:

```bash
export GOOGLE_API_KEY=<your_key>
```

**Option C — Vertex AI with GCP credentials**

```bash
gcloud auth application-default login
```

The agent auto-detects which mode to use: if `GOOGLE_API_KEY` is set it uses the Gemini API directly; otherwise it falls back to Vertex AI.

### Interactive playground (manual testing)

```bash
# Option B — no GCP (GOOGLE_API_KEY already exported)
agents-cli playground

# Option C — Vertex AI
GOOGLE_GENAI_USE_VERTEXAI=true agents-cli playground
```

#### Demo beat 1 — below threshold, no action taken

Spike (5%) is below threshold (15%). Agent logs "below threshold" and exits without RCA.

```json
{"subscription": "projects/my-project/subscriptions/audit-log-anomaly-alerts", "data": {"service_name": "concierge-agent", "error_pattern": "HTTP 404", "spike_percent": 5.0, "log_subscription": "audit-log-stream", "window_start": "2026-07-01T04:00:00Z", "window_end": "2026-07-01T04:10:00Z", "incident_id": "INC-2051", "threshold": 15.0}}
```

#### Demo beat 2 — HTTP 404 spike on concierge-agent (above threshold)

Spike (20%) exceeds threshold (15%). Agent reads 8-entry log corpus, identifies `search_flights` returning `top_k=0` across all multi-leg routes due to vector cutoff misconfiguration, emits RCA report with line citations, then **pauses for HITL approval**.

```json
{"subscription": "projects/my-project/subscriptions/audit-log-anomaly-alerts", "data": {"service_name": "concierge-agent", "error_pattern": "HTTP 404", "spike_percent": 20.0, "log_subscription": "audit-log-stream", "window_start": "2026-07-01T02:10:00Z", "window_end": "2026-07-01T02:20:00Z", "incident_id": "INC-2047", "threshold": 15.0}}
```

At the HITL pause, respond with JSON to acknowledge (file Jira) or reject (trigger retry):

```json
{"decision": "acknowledge", "score": 5, "reviewed_by": "you@example.com"}
```
```json
{"decision": "reject", "score": 2, "reviewed_by": "you@example.com"}
```

Score guide: 1=wrong, 2=right area/wrong cause, 3=partial, 4=mostly correct, 5=spot on.
If rejected, the agent collects a reason code (1–7) and retries the RCA. After 2 rejections it escalates to Jira regardless.

#### Demo beat 3 — HTTP 500 spike on booking-service (above threshold)

Spike (35%) exceeds threshold (15%). Agent reads 7-entry corpus, identifies DB connection pool exhausted (`max_pool_size=10`, `active_connections=10`), emits RCA with pool pressure warning citations, then **pauses for HITL approval**.

```json
{"subscription": "projects/my-project/subscriptions/audit-log-anomaly-alerts", "data": {"service_name": "booking-service", "error_pattern": "HTTP 500", "spike_percent": 35.0, "log_subscription": "booking-audit-log-stream", "window_start": "2026-07-01T08:00:00Z", "window_end": "2026-07-01T08:15:00Z", "incident_id": "INC-2055", "threshold": 15.0}}
```

#### Demo beat 4 — retrieval quality degradation on concierge-agent (international travel policy)

All responses are HTTP 200 — no error spike. The quality monitor detects a 46-point completeness drop (0.89 → 0.43) in international travel policy answers over 47 queries. Agent calls `read_quality_log_window`, identifies a stale RAG vector index (last reindexed 14 days ago) as root cause from retrieval score warnings and field omission patterns, then **pauses for HITL approval**.

```json
{"subscription": "projects/my-project/subscriptions/audit-log-anomaly-alerts", "data": {"service_name": "concierge-agent", "anomaly_type": "retrieval_quality", "incident_id": "INC-3001", "log_subscription": "quality-audit-log-stream", "window_start": "2026-07-03T14:00:00Z", "window_end": "2026-07-03T14:15:00Z", "threshold": 15.0, "topic_cluster": "international_travel_policy", "avg_completeness_score": 0.43, "baseline_completeness": 0.89, "affected_query_count": 47, "sample_trace_ids": ["qt0083", "qt0085", "qt0087", "qt0089", "qt0091"]}}
```

### Local HITL demo (playground — recommended for local runs)

For the full approve/reject flow locally, use the playground — it keeps everything in one interactive session:

```bash
agents-cli playground
```

Paste the anomaly payload at the prompt. When the HITL pause appears, respond with JSON:

```json
{"decision": "acknowledge", "score": 5, "reviewed_by": "you@example.com"}
```

On reject, the agent prompts for a reason code (1–7) — respond with:

```json
{"reason_code": 4, "notes": "RCA is incomplete", "reviewed_by": "you@example.com"}
```

> `agents-cli run --session-id` does **not** support HITL resume locally — `ResumabilityConfig` requires the managed session backend on Agent Runtime. Use the playground locally; use `agents-cli run --session-id` against a deployed endpoint.

### Testing against a deployed Agent Runtime endpoint

```bash
# Turn 1 — send the anomaly event (agent runs RCA, pauses at HITL, returns session ID)
agents-cli run \
  --url "https://<REGION>-aiplatform.googleapis.com/reasoningEngines/v1/<RESOURCE_NAME>" \
  --mode a2a \
  '<PAYLOAD_JSON>'

# Turn 2 — resume the paused session with your decision
agents-cli run "approve" \
  --url "https://<REGION>-aiplatform.googleapis.com/reasoningEngines/v1/<RESOURCE_NAME>" \
  --mode a2a \
  --session-id <SESSION_ID_FROM_TURN_1>
```

Replace `<RESOURCE_NAME>` with the value from `deployment_metadata.json` after deploying (`agents-cli deploy --project <GCP_PROJECT_ID>`).

### Deploying to Agent Runtime

```bash
# 1. Authenticate gcloud CLI (separate from ADC)
gcloud auth login

# 2. Deploy (takes 5–10 minutes)
agents-cli deploy --project <GCP_PROJECT_ID> --region us-east1 --no-confirm-project
```

On success the CLI prints the Agent Runtime resource name and writes `deployment_metadata.json`. Use that resource name in the `agents-cli run` commands in the section below.

```bash
# Check deployment status if the command is interrupted
agents-cli deploy --status

# Tear down when done (no gcloud CLI for Agent Runtime — use REST API)
TOKEN=$(gcloud auth print-access-token)
RESOURCE_ID=<REASONING_ENGINE_ID_FROM_deployment_metadata.json>
curl -s -X DELETE \
  "https://us-east1-aiplatform.googleapis.com/v1/projects/<PROJECT_NUMBER>/locations/us-east1/reasoningEngines/${RESOURCE_ID}?force=true" \
  -H "Authorization: Bearer $TOKEN"
```

> **Cost note:** Agent Runtime bills by vCPU-hour and memory-hour while the engine is active. Delete it when the demo is done.

### Evals

```bash
# Generate traces (runs agent on all eval cases)
EVAL_MODE=true agents-cli eval generate --project <GCP_PROJECT_ID>

# Grade traces (runs all metrics)
EVAL_MODE=true agents-cli eval grade --project <GCP_PROJECT_ID>

# Or run both in one command
EVAL_MODE=true agents-cli eval run --project <GCP_PROJECT_ID>
```

> `EVAL_MODE=true` bypasses the HITL pause **and** the deduplication check so the inference runner can complete the full workflow without being blocked by prior runs in `feedback_store.json`.
> Results land in `artifacts/traces/` and `artifacts/grade_results/`.

### Unit / integration tests

```bash
uv run pytest tests/unit tests/integration
```

### Environment variables (optional — only needed for full Jira/incident write-back)

| Variable | Purpose |
|---|---|
| `GOOGLE_CLOUD_PROJECT` | GCP project ID (auto-detected from ADC if not set) |
| `JIRA_BASE_URL` | Jira instance URL for `file_jira_ticket` |
| `JIRA_API_TOKEN` | Jira API token |
| `JIRA_PROJECT_KEY` | Jira project key (default: `ENG`) |
| `JIRA_ASSIGNEE_EMAIL` | Default Jira assignee |
| `INCIDENT_API_URL` | Incident management API base URL |
| `INCIDENT_API_TOKEN` | Incident API auth token |

If Jira/incident vars are not set, those tools return `"status": "skipped"` — the RCA pipeline and HITL flow still work fully.

---

