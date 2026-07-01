# log-analyzer

A log analyzer - an MCP component or Embeddable ambient agent that can analyze logs in a multi-agent environment.

## Project Description:

Incident management SLAs are time-bound — the faster the root cause is identified, the less damage is done. This project is both reactive and proactive: an embeddable AI ambient agent that monitors live audit logs for anomaly conditions, self-triggers the moment a threshold is crossed, and produces a fully grounded RCA report autonomously — every finding tied to an exact source span, every retrieval hypothesis verified directly against the corpus, no human needed to initiate triage.

### Problem:

Following the launch of an international travel discount offer, our concierge agent began streaming a 20% spike in 404 errors concentrated on multi-destination travel queries — the kind of pattern that, left undetected, escalates into a Priority 2 incident with a 15-minute initial response SLA and a 4-8 hour resolution clock. 

### Call-To-Action:

An agent that catches this in the logs before it formally escalates — pinning the exact log line, tool call, and step in the chain responsible, with every claim traceable back to the exact line that proves it.

### User:

AAny engineer who invokes the AI agent with a read-only, temporary access to our application/server log files and ADK agent audit log store via the CLI during incident triage — or whose live audit log stream triggers it autonomously the moment an anomaly threshold is crossed.

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

