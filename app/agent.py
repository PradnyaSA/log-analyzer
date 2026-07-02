# ruff: noqa
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Log Analyzer — ambient RCA agent.

Triggered by a Pub/Sub anomaly event when an error-rate threshold is crossed.
Pipeline:
  1. Parse the Pub/Sub envelope and extract anomaly details.
  2. Route by spike severity (below-threshold exits early).
  3. LLM agent reads the relevant log window and produces a grounded RCA report
     with exact log-line citations.
  4. Pause for HITL engineer approval.
  5. On approval: file a Jira story and transition incident to triage_completed.
     On rejection: dismiss with a note.
"""

import base64
import json
import os

from dotenv import load_dotenv

load_dotenv()  # loads .env from project root if present; no-op if absent

import google.auth
from google.adk import Agent, Context, Event, Workflow
from google.adk.apps import App, ResumabilityConfig
from google.adk.events import RequestInput
from google.adk.models import Gemini
from google.genai import types
from pydantic import BaseModel, Field

if os.environ.get("GOOGLE_API_KEY"):
    # Option B: Google AI Studio API key — no GCP project or credentials required.
    # Get a free key at https://aistudio.google.com → API Keys → Create.
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "False"
else:
    # Option C: Vertex AI — requires GCP credentials (gcloud auth application-default login).
    try:
        _, project_id = google.auth.default()
        os.environ.setdefault("GOOGLE_CLOUD_PROJECT", project_id or "")
    except google.auth.exceptions.DefaultCredentialsError:
        pass  # credentials configured via .env or Secret Manager at runtime
    os.environ["GOOGLE_CLOUD_LOCATION"] = "us-central1"
    os.environ.setdefault("GOOGLE_GENAI_USE_VERTEXAI", "True")

_MODEL = "gemini-2.5-flash"


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class AnomalyEvent(BaseModel):
    """Anomaly payload delivered via Pub/Sub."""

    service_name: str = Field(description="Name of the service with the anomaly")
    error_pattern: str = Field(description="Error type or pattern, e.g. 'HTTP 404'")
    spike_percent: float = Field(description="Percentage spike above baseline")
    log_subscription: str = Field(
        description="Pub/Sub subscription name for the audit log stream"
    )
    window_start: str = Field(
        description="ISO 8601 start of the log window to analyze"
    )
    window_end: str = Field(description="ISO 8601 end of the log window to analyze")
    incident_id: str = Field(description="Incident tracking ID")
    threshold: float = Field(
        description="Anomaly threshold that was crossed (percent)"
    )


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


def read_log_window(
    log_subscription: str,
    window_start: str,
    window_end: str,
    error_pattern: str,
    max_entries: int,
) -> dict:
    """Read the relevant log window from the audit log Pub/Sub stream.

    Fetches log entries within the specified time window that match the
    error pattern, returning raw lines with their metadata for analysis.

    Args:
        log_subscription: Pub/Sub subscription name for the audit log stream.
        window_start: ISO 8601 start timestamp of the log window.
        window_end: ISO 8601 end timestamp of the log window.
        error_pattern: Error type to filter for, e.g. 'HTTP 404'.
        max_entries: Maximum number of log entries to return.

    Returns:
        dict with 'status', 'entries' (list of log lines with metadata),
        and 'total_count'.
    """
    # Production: pull messages from the Pub/Sub subscription within the time
    # window using google.cloud.pubsub_v1.SubscriberClient, filtered by
    # error_pattern. Stub corpus below varies by error_pattern and spike_percent
    # to support realistic multi-scenario demos without live credentials.

    # --- Scenario A: HTTP 404 spike on concierge-agent (search_flights top_k=0) ---
    _404_corpus = [
        {
            "line": 1241,
            "timestamp": "2026-07-01T02:11:03Z",
            "level": "INFO",
            "text": '[concierge-agent] tool=search_flights status=200 query="JFK→LHR" results=14 latency_ms=312',
            "trace_id": "ab9001",
        },
        {
            "line": 1247,
            "timestamp": "2026-07-01T02:13:44Z",
            "level": "ERROR",
            "text": '[concierge-agent] tool=search_flights status=404 query="NYC→LON→TYO" error="No results: top_k=0 returned after vector cutoff" cutoff=0.92',
            "trace_id": "abc123",
        },
        {
            "line": 1251,
            "timestamp": "2026-07-01T02:13:51Z",
            "level": "ERROR",
            "text": '[concierge-agent] tool=search_flights status=404 query="LAX→CDG→NRT" error="No results: top_k=0 returned after vector cutoff" cutoff=0.92',
            "trace_id": "abc124",
        },
        {
            "line": 1263,
            "timestamp": "2026-07-01T02:14:29Z",
            "level": "ERROR",
            "text": '[concierge-agent] tool=search_flights status=404 query="BOS→MXP→SIN" error="No results: top_k=0 returned after vector cutoff" cutoff=0.92',
            "trace_id": "abc127",
        },
        {
            "line": 1271,
            "timestamp": "2026-07-01T02:15:07Z",
            "level": "WARNING",
            "text": '[concierge-agent] high_error_rate detected: tool=search_flights error_rate=0.81 window=60s baseline=0.04',
            "trace_id": "abc129",
        },
        {
            "line": 1289,
            "timestamp": "2026-07-01T02:17:12Z",
            "level": "ERROR",
            "text": '[concierge-agent] tool=search_flights status=404 query="SFO→FCO→BKK" error="No results: top_k=0 returned after vector cutoff" cutoff=0.92',
            "trace_id": "abc131",
        },
        {
            "line": 1302,
            "timestamp": "2026-07-01T02:18:55Z",
            "level": "ERROR",
            "text": '[concierge-agent] tool=search_flights status=404 query="ORD→AMS→HKG" error="No results: top_k=0 returned after vector cutoff" cutoff=0.92',
            "trace_id": "abc135",
        },
        {
            "line": 1318,
            "timestamp": "2026-07-01T02:19:41Z",
            "level": "ERROR",
            "text": '[concierge-agent] tool=search_flights status=404 query="DFW→ZRH→BOM" error="No results: top_k=0 returned after vector cutoff" cutoff=0.92',
            "trace_id": "abc139",
        },
    ]

    # --- Scenario B: HTTP 500 spike on booking-service (DB connection pool exhausted) ---
    _500_corpus = [
        {
            "line": 3102,
            "timestamp": "2026-07-01T08:01:14Z",
            "level": "INFO",
            "text": '[booking-service] POST /api/v2/bookings status=200 user_id=u8821 latency_ms=204',
            "trace_id": "bf0041",
        },
        {
            "line": 3117,
            "timestamp": "2026-07-01T08:02:38Z",
            "level": "ERROR",
            "text": '[booking-service] POST /api/v2/bookings status=500 error="connection pool exhausted: max_pool_size=10 active_connections=10 wait_timeout=30s"',
            "trace_id": "bf0049",
        },
        {
            "line": 3124,
            "timestamp": "2026-07-01T08:02:51Z",
            "level": "ERROR",
            "text": '[booking-service] POST /api/v2/bookings status=500 error="connection pool exhausted: max_pool_size=10 active_connections=10 wait_timeout=30s"',
            "trace_id": "bf0051",
        },
        {
            "line": 3138,
            "timestamp": "2026-07-01T08:03:22Z",
            "level": "WARNING",
            "text": '[booking-service] db_pool_pressure: active=10/10 queued_requests=47 avg_wait_ms=8340 — consider increasing max_pool_size or adding read replicas',
            "trace_id": "bf0055",
        },
        {
            "line": 3145,
            "timestamp": "2026-07-01T08:03:44Z",
            "level": "ERROR",
            "text": '[booking-service] POST /api/v2/bookings status=500 error="connection pool exhausted: max_pool_size=10 active_connections=10 wait_timeout=30s"',
            "trace_id": "bf0057",
        },
        {
            "line": 3161,
            "timestamp": "2026-07-01T08:04:19Z",
            "level": "ERROR",
            "text": '[booking-service] POST /api/v2/bookings status=500 error="connection pool exhausted: max_pool_size=10 active_connections=10 wait_timeout=30s"',
            "trace_id": "bf0062",
        },
        {
            "line": 3179,
            "timestamp": "2026-07-01T08:05:03Z",
            "level": "ERROR",
            "text": '[booking-service] POST /api/v2/bookings status=500 error="connection pool exhausted: max_pool_size=10 active_connections=10 wait_timeout=30s"',
            "trace_id": "bf0068",
        },
    ]

    # Select corpus by error_pattern; caller controls depth via max_entries
    corpus = _500_corpus if "500" in error_pattern else _404_corpus

    return {
        "status": "success",
        "subscription": log_subscription,
        "window": {"start": window_start, "end": window_end},
        "error_pattern": error_pattern,
        "entries": corpus[:max_entries],
        "total_count": len(corpus),
    }


def emit_rca_log(
    incident_id: str,
    service_name: str,
    root_cause: str,
    confidence: str,
    spike_percent: float,
    citation_lines: str,
) -> dict:
    """Emit a structured RCA alert to Cloud Logging (JSON stdout).

    Cloud Logging captures JSON stdout as structured log entries.
    A log-based metric and alert policy can notify on-call engineers
    when these entries appear.

    Args:
        incident_id: The incident tracking ID.
        service_name: The service where the anomaly was detected.
        root_cause: One-sentence root cause statement.
        confidence: Confidence level — 'high', 'medium', or 'low'.
        spike_percent: The observed error spike percentage.
        citation_lines: Comma-separated log line numbers supporting the finding.

    Returns:
        Confirmation that the alert was emitted.
    """
    log_entry = {
        "severity": "WARNING",
        "message": f"RCA complete for {incident_id}: {root_cause}",
        "alert_type": "rca_complete",
        "incident_id": incident_id,
        "service_name": service_name,
        "root_cause": root_cause,
        "confidence": confidence,
        "spike_percent": spike_percent,
        "citation_lines": citation_lines,
    }
    print(json.dumps(log_entry), flush=True)
    return {"status": "rca_logged", "incident_id": incident_id}


def file_jira_ticket(
    incident_id: str,
    summary: str,
    description: str,
    root_cause: str,
    affected_service: str,
    log_citations: str,
) -> dict:
    """File a Jira story for the incident root cause.

    Requires JIRA_BASE_URL, JIRA_API_TOKEN, JIRA_PROJECT_KEY, and
    JIRA_ASSIGNEE_EMAIL set as environment variables (backed by Secret Manager).

    Args:
        incident_id: The incident tracking ID.
        summary: Short Jira story title (one line).
        description: Full description including RCA findings.
        root_cause: The identified root cause.
        affected_service: The service with the anomaly.
        log_citations: Exact log lines that prove the root cause.

    Returns:
        dict with 'status' and 'ticket_url' on success.
    """
    import urllib.request

    jira_base = os.getenv("JIRA_BASE_URL", "")
    jira_token = os.getenv("JIRA_API_TOKEN", "")
    jira_project = os.getenv("JIRA_PROJECT_KEY", "ENG")
    jira_assignee = os.getenv("JIRA_ASSIGNEE_EMAIL", "")

    if not jira_base or not jira_token:
        return {
            "status": "skipped",
            "reason": "JIRA_BASE_URL and JIRA_API_TOKEN not configured",
            "incident_id": incident_id,
        }

    body_text = (
        f"Incident: {incident_id}\n"
        f"Root cause: {root_cause}\n"
        f"Affected service: {affected_service}\n\n"
        f"{description}\n\n"
        f"Evidence log lines:\n{log_citations}"
    )
    payload = json.dumps(
        {
            "fields": {
                "project": {"key": jira_project},
                "summary": summary,
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": body_text}],
                        }
                    ],
                },
                "issuetype": {"name": "Story"},
                **(
                    {"assignee": {"emailAddress": jira_assignee}}
                    if jira_assignee
                    else {}
                ),
            }
        }
    ).encode()

    req = urllib.request.Request(
        f"{jira_base}/rest/api/3/issue",
        data=payload,
        headers={
            "Authorization": f"Bearer {jira_token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            ticket_key = result.get("key", "UNKNOWN")
            return {
                "status": "success",
                "ticket_url": f"{jira_base}/browse/{ticket_key}",
                "ticket_key": ticket_key,
            }
    except Exception as exc:
        return {"status": "error", "reason": str(exc), "incident_id": incident_id}


def update_incident_status(
    incident_id: str,
    status: str,
    resolution_note: str,
) -> dict:
    """Transition an incident to the given status.

    Requires INCIDENT_API_URL and INCIDENT_API_TOKEN environment variables.

    Args:
        incident_id: The incident tracking ID to update.
        status: Target status, e.g. 'triage_completed' or 'dismissed'.
        resolution_note: Note describing what was found and done.

    Returns:
        dict with 'status' and updated incident metadata.
    """
    import urllib.request

    api_url = os.getenv("INCIDENT_API_URL", "")
    api_token = os.getenv("INCIDENT_API_TOKEN", "")

    if not api_url or not api_token:
        return {
            "status": "skipped",
            "reason": "INCIDENT_API_URL and INCIDENT_API_TOKEN not configured",
            "incident_id": incident_id,
        }

    payload = json.dumps(
        {
            "incident_id": incident_id,
            "status": status,
            "resolution_note": resolution_note,
        }
    ).encode()

    req = urllib.request.Request(
        f"{api_url}/incidents/{incident_id}/status",
        data=payload,
        method="PATCH",
        headers={
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            return {"status": "success", "incident": result}
    except Exception as exc:
        return {"status": "error", "reason": str(exc), "incident_id": incident_id}


# ---------------------------------------------------------------------------
# Function nodes
# ---------------------------------------------------------------------------


def parse_anomaly_event(node_input: str) -> Event:
    """Parse the Pub/Sub trigger envelope and extract the anomaly payload.

    The ADK trigger endpoint delivers the raw Pub/Sub message JSON. The
    anomaly payload lives in the ``data`` field, which is base64-encoded
    in real Pub/Sub deliveries and may be plain JSON in local tests.
    """
    try:
        envelope = json.loads(node_input)
    except json.JSONDecodeError:
        return Event(output={"error": f"Invalid JSON envelope: {node_input[:200]}"})

    data = envelope.get("data", {})
    if isinstance(data, str):
        try:
            data = json.loads(base64.b64decode(data))
        except Exception:
            return Event(
                output={"error": f"Failed to decode base64 data: {data[:200]}"}
            )

    return Event(
        output={
            "service_name": data.get("service_name", "unknown"),
            "error_pattern": data.get("error_pattern", ""),
            "spike_percent": float(data.get("spike_percent", 0)),
            "log_subscription": data.get("log_subscription", ""),
            "window_start": data.get("window_start", ""),
            "window_end": data.get("window_end", ""),
            "incident_id": data.get("incident_id", ""),
            "threshold": float(data.get("threshold", 15.0)),
        }
    )


def route_by_severity(node_input: dict, ctx: Context) -> Event:
    """Route based on whether the spike exceeds the anomaly threshold.

    Stores anomaly data in workflow state for downstream nodes, then routes:
    - spike < threshold  → BELOW_THRESHOLD (log and exit)
    - spike >= threshold → ANALYZE (run the RCA pipeline)
    """
    ctx.state["anomaly"] = node_input
    spike = node_input.get("spike_percent", 0)
    threshold = node_input.get("threshold", 15.0)

    if spike < threshold:
        return Event(route="BELOW_THRESHOLD", output=node_input)
    return Event(route="ANALYZE", output=node_input)


def _log_below_threshold(node_input: dict) -> Event:
    """Emit structured log and pass through for the summary agent."""
    log_entry = {
        "severity": "INFO",
        "message": (
            f"Anomaly event received but below threshold — no action taken. "
            f"spike={node_input.get('spike_percent')}% "
            f"threshold={node_input.get('threshold')}%"
        ),
        "incident_id": node_input.get("incident_id"),
    }
    print(json.dumps(log_entry), flush=True)
    return Event(output=node_input)


# LLM node to produce a human-readable summary for the below-threshold path.
# Also ensures the inference runner receives proper LLM events (not a bare string).
below_threshold = Agent(
    name="below_threshold_agent",
    model=Gemini(
        model=_MODEL,
        retry_options=types.HttpRetryOptions(attempts=3),
    ),
    mode="single_turn",
    instruction=(
        "You received an anomaly event that was below the detection threshold "
        "and required no action. Produce a concise one-sentence acknowledgement "
        "confirming that the anomaly was evaluated, the spike and threshold values, "
        "and that no RCA or incident action was taken."
    ),
)


# ---------------------------------------------------------------------------
# LLM analysis agent — reads logs and produces a grounded RCA report
# ---------------------------------------------------------------------------

log_analysis_agent = Agent(
    name="log_analysis_agent",
    model=Gemini(
        model=_MODEL,
        retry_options=types.HttpRetryOptions(attempts=3),
    ),
    mode="single_turn",
    instruction="""You are a log analysis expert performing root cause analysis (RCA) on production incidents.

You receive an anomaly event. Your job:

1. Call `read_log_window` with the subscription, time window, and error pattern from the anomaly event.
2. Analyze the returned entries carefully:
   - Identify the exact error message that repeats across entries.
   - Find the tool call, agent step, or code path that first appears in the chain.
   - Look for a common parameter or condition shared across all failing requests.
   - State the single root cause — the change, config, or code path responsible.
3. Cite the EXACT log line number(s) for EVERY finding. No claim without a citation.
4. Call `emit_rca_log` with your root cause, confidence level, and citation lines.
5. Return the complete RCA report in this format:

## RCA Report — <incident_id>

**Service:** <service_name>
**Anomaly:** <error_pattern> spike of <spike_percent>%
**Log window:** <window_start> → <window_end>

### Root Cause
<one-sentence statement of root cause>

### Evidence
- **Finding:** <description> — *Log line N: `<exact log text>`*
(repeat for each finding)

### Impact
<brief description of user-facing impact>

### Recommended Fix
<specific, actionable fix>

**Confidence:** high | medium | low
""",
    input_schema=AnomalyEvent,
    tools=[read_log_window, emit_rca_log],
)


# ---------------------------------------------------------------------------
# HITL: pause for engineer approval before filing Jira / updating incident
# ---------------------------------------------------------------------------


def request_rca_approval(node_input, ctx: Context):  # type: ignore[no-untyped-def]
    """Pause the workflow for engineer review before taking write actions.

    The session stays paused until an engineer resumes it (via the HITL
    UI or POST /run with the session ID). Their response flows into
    ``action_agent``.

    In eval mode (EVAL_MODE=true), the HITL pause is skipped so the
    inference runner can complete the full workflow without blocking.
    """
    anomaly = ctx.state.get("anomaly", {})

    if os.environ.get("EVAL_MODE", "").lower() == "true":
        return Event(
            output={
                "hitl_skipped": True,
                "reason": "EVAL_MODE=true — HITL pause bypassed for evaluation",
                "incident_id": anomaly.get("incident_id"),
                "rca_report": (
                    node_input if isinstance(node_input, str) else str(node_input)
                ),
            }
        )

    yield RequestInput(
        message=(
            "RCA complete. Review the findings above and respond with "
            "'approve' to file a Jira story and mark the incident as "
            "triage_completed, or 'reject' to dismiss without action."
        ),
        payload={
            "incident_id": anomaly.get("incident_id"),
            "service_name": anomaly.get("service_name"),
            "rca_report": (
                node_input if isinstance(node_input, str) else str(node_input)
            ),
        },
    )


# ---------------------------------------------------------------------------
# Action agent — executes write actions after HITL approval
# ---------------------------------------------------------------------------

action_agent = Agent(
    name="action_agent",
    model=Gemini(
        model=_MODEL,
        retry_options=types.HttpRetryOptions(attempts=3),
    ),
    mode="single_turn",
    instruction="""You process the engineer's approval decision after an RCA review.

If the decision is 'approve' or 'approved':
1. Call `file_jira_ticket` with a concise summary and the full RCA including evidence citations.
2. Call `update_incident_status` with status='triage_completed' and the root cause as the resolution note.
3. Confirm both actions were taken and report the Jira ticket URL.

If the decision is 'reject' or 'rejected':
1. Call `update_incident_status` with status='dismissed' and a note that the engineer reviewed and dismissed the RCA.
2. Do NOT file a Jira ticket.
3. Confirm the dismissal.

Be concise and specific — report exactly what was done.
""",
    tools=[file_jira_ticket, update_incident_status],
)


# ---------------------------------------------------------------------------
# Graph-based workflow — root agent
# ---------------------------------------------------------------------------

root_agent = Workflow(
    name="log_analyzer",
    edges=[
        ("START", parse_anomaly_event, route_by_severity),
        (
            route_by_severity,
            {
                "BELOW_THRESHOLD": _log_below_threshold,
                "ANALYZE": log_analysis_agent,
            },
        ),
        (_log_below_threshold, below_threshold),
        (log_analysis_agent, request_rca_approval, action_agent),
    ],
)

app = App(
    root_agent=root_agent,
    name="app",
    resumability_config=ResumabilityConfig(is_resumable=True),
)
