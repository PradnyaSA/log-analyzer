# log-analyzer

A demo repo for an MCP component or Embeddable agent that can analyze logs in a multi-agent environment

## Project Description:

Incident management SLAs are time-bound, and both reactive and proactive measures are necessary to avoid disruptions. This project is a reactive measure: an embeddable AI agent that performs root cause analysis upon invocation after an incident occurs, grounding every finding in an exact log citation and verifying retrieval-related hypotheses directly against the corpus.

### Problem:

I woke up to a Priority 2 incident last week — our concierge agent had a 20% spike in “information not found” responses. The typical SLA for resolving a Priority 2 incident is ~4-8 hours, with an initial response due in ~15 minutes to prevent further escalation.

### Call-To-Action:

Triaging that can pin down the exact log line, tool call, and step in the chain responsible — analysis starting with logs, with every claim traceable back to the exact line that proves it. Deliver a possible root cause of the problem.

### User:

Any engineer who invokes an AI agent with read-only, temporary access to our application/server log files and agent audit log store via the CLI during incident triage.

### Workflow automated:

Traditionally, pre-AI, I would have pulled a team of experts onto a triaging call, but now I can use AI. I used the incident’s reported timestamps and pointed the Log-Analyzer agent at the narrowest possible window for root cause analysis. Before I blinked, the agent pulled every relevant application/server log and agent audit log, and assembled a single, trustworthy incident report. I could clearly see the anomaly within minutes: the information existed in our corpus; it just fell outside the Top-K cutoff used by our retrieval step. I closed that Priority-2 in minutes, adding the finding to my team’s next retrieval-optimization intake, and I resumed my day as normal.

### Out of Scope / Known Limitations:

* Compared to full-stack observability platforms (Splunk, Elastic, Datadog, Dynatrace, New Relic), this project deliberately does not attempt:
  * Scale — no petabyte-scale ingestion/indexing; built for bounded sample log sets, not production-volume telemetry.
  * Breadth — logs only. No metrics, traces, RUM, or infrastructure topology correlation.
  * Dashboards/alerting — no visualization layer, no SLOs, no alert/notification pipeline.
  * Production deployment maturity — no multi-tenancy, no long-term storage, no HA/scaling story.
  * Incident-data tuning — no large historical incident corpus to tune confidence thresholds or severity heuristics against; patterns are hand-authored per skill, not learned at scale.
* This project deliberately does not attempt a proactive measure where a long-running agent can do random sampling of logs to detect issues before those become incidents. It will be doable in future scope.

---
