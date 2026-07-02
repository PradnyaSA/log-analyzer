# Log Analyzer — Capstone Project Summary

## Problem

Incident management SLAs are time-bound. A 20% spike in 404 errors on a production service opens a P2 incident with a 15-minute initial response SLA and a 4–8 hour resolution clock. Traditional triage requires an on-call engineer to manually sift through audit logs, correlate error patterns, identify a root cause, file a ticket, and update the incident tracker — all under time pressure, often overnight.

## Solution

**Log Analyzer** is an ambient AI agent that closes this gap autonomously. Deployed on Google Agent Runtime and triggered by a Pub/Sub anomaly event, it:

1. **Self-triggers** the moment an error-rate threshold is crossed — no human needed to initiate triage.
2. **Reads the relevant log window** from the audit log stream and analyzes it end-to-end.
3. **Produces a grounded RCA report** with every finding tied to an exact log line number — no hallucinated citations.
4. **Pauses for HITL approval** before taking any write action, presenting the engineer with a concise `approve / reject` decision.
5. **On approval: files a Jira story** and transitions the incident to `triage_completed` — fully hands-free.

## Architecture

```
Pub/Sub anomaly event
        │
        ▼
  parse_anomaly_event()          ← decodes base64 Pub/Sub envelope
        │
        ▼
  route_by_severity()            ← spike < threshold? exit early with log
        │
        ├── BELOW_THRESHOLD ──▶  below_threshold_agent  (acknowledges, exits)
        │
        └── ANALYZE ──────────▶  log_analysis_agent     (reads logs → RCA report + emit_rca_log)
                                         │
                                         ▼
                                 request_rca_approval()  ← HITL pause
                                         │
                                         ▼
                                  action_agent           (files Jira, updates incident on approve)
```

**Stack:** Google ADK 2.0 · Gemini 2.5 Flash · Agent Runtime (Vertex AI) · Pub/Sub trigger · Python / FastAPI · A2A protocol

## Key Design Decisions

| Decision | Rationale |
|---|---|
| **Ambient trigger via Pub/Sub** | Agent wakes only when a threshold is crossed — zero idle cost, no polling loop |
| **HITL before all write actions** | Jira tickets and incident transitions are irreversible; a false positive at 3am is worse than a 30-second human review |
| **Grounded citations required** | Every RCA claim must cite an exact log line — enforced in the agent's instruction and verified by the LLM-judge eval metric |
| **Workflow graph over ReAct loop** | Deterministic routing (below-threshold early exit, HITL pause, action branch) requires explicit edges — not emergent from a free-form loop |
| **Eval-mode bypass for HITL** | `EVAL_MODE=true` skips the `RequestInput` pause so the eval inference runner can complete the full pipeline without blocking |

## Evaluation

Three metrics run against a 4-case dataset:

| Metric | Type | Score |
|---|---|---|
| `rca_tool_sequence` | Code metric — verifies `read_log_window → emit_rca_log` order, no premature writes | **1.00** |
| `rca_rubric_quality` | LLM-as-judge — grounded citations, specific root cause, correct routing | **0.81** |
| `multi_turn_tool_use_quality` | Built-in ADK metric | 0.25 (penalizes non-standard routing paths) |

Eval cases cover: above-threshold RCA, below-threshold early exit, critical spike on a different service, and malformed Pub/Sub envelope.

## Demo Scenario

> *Following the launch of an international travel discount offer, the concierge agent begins streaming a 20% spike in 404 errors on multi-destination queries. Log Analyzer detects the anomaly overnight, reads the audit log window, and pins the root cause to an overly aggressive vector similarity cutoff (`top_k=0`) in the `search_flights` tool — citing log lines 1247, 1251, and 1289 as evidence. By morning, an HITL approval request is waiting. The engineer reviews the RCA, approves, and the Jira story is filed. The fix is in progress before the office opens.*

## Repo

`github.com/PradnyaSA/log-analyzer` · branch: `main`

**Key files:**

| File | Purpose |
|---|---|
| `app/agent.py` | Full Workflow agent — parse, route, analyze, HITL, action |
| `app/fast_api_app.py` | FastAPI app with Pub/Sub trigger endpoint |
| `tests/eval/datasets/basic-dataset.json` | 4-case eval dataset with per-case rubrics |
| `tests/eval/eval_config.yaml` | LLM-judge and code metric configuration |
| `README.md` | Prerequisites, playground, eval, and env var reference |
