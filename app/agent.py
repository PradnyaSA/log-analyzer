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
  4. HITL #1 — engineer acknowledges (with quality score 1-5) or rejects.
  5. On reject — HITL #2 collects structured rejection reason + notes + reviewer.
  6. On acknowledge: file a Jira story, transition incident to triage_completed,
     and store Phase 1 feedback (pending Jira outcome).
     On rejection: dismiss with a note and store feedback (score=0).
  7. Phase 2 feedback arrives async via /jira/webhook when the ticket closes.
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

# Path to the feedback store JSON file (project root)
_FEEDBACK_STORE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "feedback_store.json"
)

# Curated rejection reason codes shown in HITL #2
_REJECTION_REASONS = {
    1: "Wrong root cause identified",
    2: "Correct service but wrong component",
    3: "Evidence citations are inaccurate",
    4: "RCA is incomplete — missing key findings",
    5: "False positive — no real incident",
    6: "Already known issue / duplicate",
    7: "Other (use notes)",
}

_REJECTION_REASONS_TEXT = "\n".join(
    f"  {code}: {label}" for code, label in _REJECTION_REASONS.items()
)


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
    jira_user = os.getenv("JIRA_USER_EMAIL", "")
    jira_project = os.getenv("JIRA_PROJECT_KEY", "ENG")
    jira_assignee = os.getenv("JIRA_ASSIGNEE_EMAIL", "")

    if not jira_base or not jira_token or not jira_user:
        return {
            "status": "skipped",
            "reason": "JIRA_BASE_URL, JIRA_USER_EMAIL, and JIRA_API_TOKEN not configured",
            "incident_id": incident_id,
        }

    body_text = (
        f"Incident: {incident_id}\n"
        f"Root cause: {root_cause}\n"
        f"Affected service: {affected_service}\n\n"
        f"{description}\n\n"
        f"Evidence log lines:\n{log_citations}"
    )
    jira_issue_type = os.getenv("JIRA_ISSUE_TYPE", "Task")
    # Jira Cloud API v3: assignee requires accountId, not email — omit to avoid 400
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
                "issuetype": {"name": jira_issue_type},
            }
        }
    ).encode()

    import base64 as _b64
    basic = _b64.b64encode(f"{jira_user}:{jira_token}".encode()).decode()
    req = urllib.request.Request(
        f"{jira_base}/rest/api/3/issue",
        data=payload,
        headers={
            "Authorization": f"Basic {basic}",
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
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return {"status": "error", "http_status": exc.code, "reason": body, "incident_id": incident_id}
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


def store_feedback(
    incident_id: str,
    attempt_number: int,
    hitl_decision: str,
    hitl_score: int,
    reviewed_by: str,
    jira_key: str,
    rejection_reason_code: int,
    rejection_reason_label: str,
    rejection_notes: str,
    anomaly_payload: str,
) -> dict:
    """Store per-attempt feedback for an incident in the local feedback store.

    Appends one attempt record to the 'attempts' list keyed by incident_id in
    feedback_store.json at the project root. Phase 2 (Jira outcome) is written
    later by the /jira/webhook endpoint in fast_api_app.py.

    Args:
        incident_id: The incident tracking ID.
        attempt_number: Which RCA attempt this is (1, 2, or 3).
        hitl_decision: 'acknowledge', 'reject', or 'escalate'.
        hitl_score: Engineer's quality score 1-5 (0 for reject/escalate).
        reviewed_by: Engineer's email or name.
        jira_key: Jira ticket key if filed (empty string otherwise).
        rejection_reason_code: Reason code 1-7 (0 if acknowledged).
        rejection_reason_label: Human-readable label for the reason code.
        rejection_notes: Free-text notes from the engineer (max 200 chars).
        anomaly_payload: JSON string of the original anomaly event dict.

    Returns:
        dict with 'status', 'incident_id', and 'feedback_status'.
    """
    from datetime import datetime, timezone

    if os.path.exists(_FEEDBACK_STORE_PATH):
        with open(_FEEDBACK_STORE_PATH) as f:
            store = json.load(f)
    else:
        store = {}

    try:
        anomaly = json.loads(anomaly_payload)
    except Exception:
        anomaly = {}

    terminal = hitl_decision in ("acknowledge", "escalate")
    if terminal:
        final_score = None  # resolved in Phase 2 when Jira ticket closes
        feedback_status = "pending_jira"
    else:
        final_score = 0.0
        feedback_status = "rejected"

    attempt_record = {
        "attempt": attempt_number,
        "hitl_decision": hitl_decision,
        "hitl_score": hitl_score,
        "reviewed_by": reviewed_by,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if hitl_decision in ("reject", "escalate") and rejection_reason_code:
        attempt_record["rejection"] = {
            "reason_code": rejection_reason_code,
            "reason_label": rejection_reason_label,
            "notes": rejection_notes[:200],
        }

    existing = store.get(incident_id, {})
    attempts = existing.get("attempts", [])
    # Replace existing record for this attempt number if re-stored, else append.
    attempts = [a for a in attempts if a.get("attempt") != attempt_number]
    attempts.append(attempt_record)
    attempts.sort(key=lambda a: a["attempt"])

    store[incident_id] = {
        "incident_id": incident_id,
        "service_name": anomaly.get("service_name", ""),
        "error_pattern": anomaly.get("error_pattern", ""),
        "spike_percent": anomaly.get("spike_percent", 0),
        "attempts": attempts,
        "retry_count": attempt_number - 1,
        "phase_2": existing.get("phase_2"),
        "jira_key": jira_key if jira_key else existing.get("jira_key"),
        "final_accuracy_score": final_score,
        "status": feedback_status,
        "anomaly_payload": anomaly_payload,
    }

    with open(_FEEDBACK_STORE_PATH, "w") as f:
        json.dump(store, f, indent=2)

    return {
        "status": "stored",
        "incident_id": incident_id,
        "attempt_number": attempt_number,
        "feedback_status": feedback_status,
    }


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

    event_output: dict = {
        "service_name": data.get("service_name", "unknown"),
        "error_pattern": data.get("error_pattern", ""),
        "spike_percent": float(data.get("spike_percent", 0)),
        "log_subscription": data.get("log_subscription", ""),
        "window_start": data.get("window_start", ""),
        "window_end": data.get("window_end", ""),
        "incident_id": data.get("incident_id", ""),
        "threshold": float(data.get("threshold", 15.0)),
    }
    # Pass eval control keys through so route_by_severity can store them in state.
    for k, v in data.items():
        if k.startswith("eval_"):
            event_output[k] = v
    return Event(output=event_output)


def route_by_severity(node_input: dict, ctx: Context) -> Event:
    """Route based on whether the spike exceeds the anomaly threshold.

    Stores anomaly data in workflow state for downstream nodes, then routes:
    - spike < threshold  → BELOW_THRESHOLD (log and exit)
    - spike >= threshold → ANALYZE (run the RCA pipeline)
    """
    # Extract eval control params before storing the anomaly dict so they
    # don't contaminate downstream agents (e.g. log_analysis_agent input schema).
    for k, v in node_input.items():
        if k.startswith("eval_"):
            ctx.state[k] = v
    anomaly = {k: v for k, v in node_input.items() if not k.startswith("eval_")}
    ctx.state["anomaly"] = anomaly
    # Retry-loop counters — reset fresh for every new anomaly event.
    ctx.state["retry_count"] = 0
    ctx.state["attempt_number"] = 1
    ctx.state["rejection_history"] = []
    ctx.state["rejection_history_text"] = ""
    spike = anomaly.get("spike_percent", 0)
    threshold = anomaly.get("threshold", 15.0)

    if spike < threshold:
        return Event(route="BELOW_THRESHOLD", output=anomaly)
    return Event(route="ANALYZE", output=anomaly)


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
# HITL #1 — pause for engineer review; collect acknowledge/reject + score
# ---------------------------------------------------------------------------


def request_rca_approval(node_input, ctx: Context):  # type: ignore[no-untyped-def]
    """Pause the workflow for engineer review before taking write actions.

    Adjusts its message based on retry_count:
      0 → normal first-attempt review
      1 → retry #1, shows previous rejection context
      2 → escalated, warns Jira will be filed regardless

    In eval mode (EVAL_MODE=true), the HITL pause is skipped.
    """
    anomaly = ctx.state.get("anomaly", {})
    retry_count = ctx.state.get("retry_count", 0)

    rca_report = node_input if isinstance(node_input, str) else str(node_input)

    ctx.state["rca_report"] = rca_report
    ctx.state["incident_id"] = anomaly.get("incident_id", "")
    ctx.state["service_name"] = anomaly.get("service_name", "")
    ctx.state["anomaly_payload"] = json.dumps(anomaly)
    # Ensure rejection state keys always exist for action_agent template rendering.
    ctx.state.setdefault("rejection_reason_code", 0)
    ctx.state.setdefault("rejection_reason_label", "")
    ctx.state.setdefault("rejection_notes", "")
    ctx.state.setdefault("rejection_reviewed_by", "")

    if os.environ.get("EVAL_MODE", "").lower() == "true":
        # eval_hitl_sequence lets each eval case control the decision at each attempt.
        # Default ["acknowledge"] keeps existing single-pass eval cases working.
        attempt_number = ctx.state.get("attempt_number", 1)
        sequence = ctx.state.get("eval_hitl_sequence", ["acknowledge"])
        decision = sequence[min(attempt_number - 1, len(sequence) - 1)]
        if decision == "reject":
            ctx.state["hitl_decision"] = "reject"
            ctx.state["hitl_score"] = 0
        else:
            ctx.state["hitl_decision"] = "acknowledge"
            ctx.state["hitl_score"] = ctx.state.get("eval_hitl_score", 5)
        ctx.state["reviewed_by"] = "eval-mode"
        return Event(
            output={
                "hitl_skipped": True,
                "decision": decision,
                "incident_id": anomaly.get("incident_id"),
                "rca_report": rca_report,
            }
        )

    json_prompt = (
        "  Acknowledge: {\"decision\": \"acknowledge\", \"score\": <1-5>, \"reviewed_by\": \"<your email>\"}\n"
        "  Reject:      {\"decision\": \"reject\", \"reviewed_by\": \"<your email>\"}\n\n"
        "Score guide: 1=wrong, 2=right area/wrong cause, 3=partial, 4=mostly correct, 5=spot on"
    )

    if retry_count == 0:
        message = (
            "RCA complete. Review the findings above and respond with JSON:\n\n"
            + json_prompt
        )
    elif retry_count == 1:
        history = ctx.state.get("rejection_history_text", "")
        message = (
            f"⚠️  RETRY #1 — Previous rejection:\n{history}\n\n"
            "Review the improved RCA above and respond with JSON:\n\n"
            + json_prompt
        )
    else:
        history = ctx.state.get("rejection_history_text", "")
        message = (
            "⚠️  ESCALATED — 2 prior rejections. This RCA will be filed to Jira for "
            "engineering investigation regardless of your decision.\n"
            "You may still provide a quality score.\n\n"
            f"Rejection history:\n{history}\n\n"
            "Respond with JSON:\n\n"
            "  Acknowledge: {\"decision\": \"acknowledge\", \"score\": <1-5>, \"reviewed_by\": \"<your email>\"}\n"
            "  Reject:      {\"decision\": \"reject\", \"score\": <1-5>, \"reviewed_by\": \"<your email>\"}\n"
            "  (Jira will be filed regardless of acknowledge/reject)\n\n"
            "Score guide: 1=wrong, 2=right area/wrong cause, 3=partial, 4=mostly correct, 5=spot on"
        )

    yield RequestInput(
        message=message,
        payload={
            "incident_id": anomaly.get("incident_id"),
            "service_name": anomaly.get("service_name"),
            "retry_count": retry_count,
            "rca_report": rca_report,
        },
    )


def route_hitl_decision(node_input, ctx: Context) -> Event:
    """Parse the HITL response and route based on decision and retry_count.

    In ADK's 3-tuple chain (log_analysis_agent, request_rca_approval, route_hitl_decision),
    the engineer's response becomes THIS node's node_input.
    EVAL_MODE pre-sets ctx.state so we skip parsing entirely.

    Routes:
      ACKNOWLEDGE — engineer approved (any attempt)
      REJECT      — engineer rejected (attempt 1 or 2, triggers retry loop)
      ESCALATE    — 3rd attempt (retry_count >= 2); Jira filed regardless of decision
    """
    retry_count = ctx.state.get("retry_count", 0)

    # EVAL_MODE pre-set — bypass parsing
    if ctx.state.get("hitl_decision"):
        decision = ctx.state["hitl_decision"]
        if retry_count >= 2:
            # 3rd attempt: always route to ACKNOWLEDGE; hitl_decision="escalate" if rejected
            hitl_decision = "acknowledge" if decision == "acknowledge" else "escalate"
            ctx.state["hitl_decision"] = hitl_decision
            ctx.state["hitl_score"] = ctx.state.get("eval_hitl_score", 5) if decision == "acknowledge" else 0
            ctx.state["reviewed_by"] = "eval-mode"
            return Event(route="ACKNOWLEDGE", output={"decision": hitl_decision})
        route = "ACKNOWLEDGE" if decision == "acknowledge" else "REJECT"
        return Event(route=route, output={"decision": decision})

    text = node_input if isinstance(node_input, str) else str(node_input)

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        lower = text.strip().lower()
        if lower.startswith("reject"):
            parsed = {"decision": "reject", "reviewed_by": "unknown"}
        else:
            parsed = {"decision": "acknowledge", "score": 3, "reviewed_by": "unknown"}

    decision = parsed.get("decision", "acknowledge").lower().strip()
    reviewed_by = str(parsed.get("reviewed_by", "unknown")).strip()

    if retry_count >= 2:
        # 3rd attempt — always file Jira regardless of engineer's decision.
        # Route to ACKNOWLEDGE so action_agent runs; hitl_decision="escalate" when
        # engineer rejected so action_agent knows to prefix the Jira summary.
        score = max(1, min(5, int(parsed.get("score", 3)))) if decision == "acknowledge" else 0
        hitl_decision = "acknowledge" if decision == "acknowledge" else "escalate"
        ctx.state["hitl_decision"] = hitl_decision
        ctx.state["hitl_score"] = score
        ctx.state["reviewed_by"] = reviewed_by
        return Event(route="ACKNOWLEDGE", output={"decision": hitl_decision})

    if decision == "acknowledge":
        score = max(1, min(5, int(parsed.get("score", 3))))
        ctx.state["hitl_decision"] = "acknowledge"
        ctx.state["hitl_score"] = score
        ctx.state["reviewed_by"] = reviewed_by
        return Event(route="ACKNOWLEDGE", output={"decision": "acknowledge", "score": score})
    else:
        ctx.state["hitl_decision"] = "reject"
        ctx.state["hitl_score"] = 0
        ctx.state["reviewed_by"] = reviewed_by
        return Event(route="REJECT", output={"decision": "reject"})


# ---------------------------------------------------------------------------
# HITL #2 — collect structured rejection reason (only on reject path)
# ---------------------------------------------------------------------------


def request_rejection_reason(node_input, ctx: Context):  # type: ignore[no-untyped-def]
    """Pause to collect a structured rejection reason from the engineer.

    Called only when HITL #1 decision is 'reject'. The engineer selects a
    reason code from the curated list and optionally adds notes (≤200 chars).
    In ADK's 3-tuple chain the engineer's response becomes node_input for the
    next node (capture_rejection_reason), not the return value of yield.
    In EVAL_MODE the HITL is bypassed using eval_rejection_reason_code /
    eval_rejection_notes from the eval case's initial_session_state.
    """
    if os.environ.get("EVAL_MODE", "").lower() == "true":
        return Event(output=json.dumps({
            "reason_code": ctx.state.get("eval_rejection_reason_code", 1),
            "notes": ctx.state.get("eval_rejection_notes", "Eval mode rejection"),
            "reviewed_by": "eval-mode",
        }))

    yield RequestInput(
        message=(
            "Please provide the rejection reason as JSON:\n\n"
            "  {\"reason_code\": <1-7>, \"notes\": \"<up to 200 chars>\", \"reviewed_by\": \"<your email>\"}\n\n"
            f"Reason codes:\n{_REJECTION_REASONS_TEXT}"
        ),
        payload={
            "incident_id": ctx.state.get("incident_id", ""),
            "reviewed_by": ctx.state.get("reviewed_by", ""),
        },
    )


def capture_rejection_reason(node_input, ctx: Context) -> Event:
    """Receive the HITL #2 engineer response as node_input (3-tuple chain pattern).

    Parses the rejection JSON, stores fields in ctx.state, increments retry_count
    and attempt_number, and appends to rejection_history_text for retry context.
    """
    raw = node_input if isinstance(node_input, str) else str(node_input)
    try:
        parsed = json.loads(raw)
        reason_code = int(parsed.get("reason_code", 7))
        notes = str(parsed.get("notes", ""))[:200]
        reviewed_by = str(parsed.get("reviewed_by", ctx.state.get("reviewed_by", "unknown")))
    except (json.JSONDecodeError, TypeError, ValueError):
        reason_code = 7
        notes = raw[:200]
        reviewed_by = ctx.state.get("reviewed_by", "unknown")

    reason_label = _REJECTION_REASONS.get(reason_code, "Other")

    # Store current rejection fields for action_agent template rendering.
    ctx.state["rejection_reason_code"] = reason_code
    ctx.state["rejection_reason_label"] = reason_label
    ctx.state["rejection_notes"] = notes
    ctx.state["rejection_reviewed_by"] = reviewed_by

    # Append this rejection to the history list and rebuild the display text.
    attempt_number = ctx.state.get("attempt_number", 1)
    history: list = ctx.state.get("rejection_history", [])
    history.append({
        "attempt": attempt_number,
        "reason_code": reason_code,
        "reason_label": reason_label,
        "notes": notes,
        "reviewed_by": reviewed_by,
    })
    ctx.state["rejection_history"] = history
    ctx.state["rejection_history_text"] = "\n".join(
        f"  #{r['attempt']}: {r['reason_label']} — \"{r['notes']}\" (by {r['reviewed_by']})"
        for r in history
    )

    # Advance counters for the upcoming retry attempt.
    ctx.state["retry_count"] = ctx.state.get("retry_count", 0) + 1
    ctx.state["attempt_number"] = attempt_number + 1

    return Event(output=raw)


def route_after_rejection(node_input, ctx: Context) -> Event:
    """Always route to the retry analysis agent.

    Escalation is handled upstream in route_hitl_decision (when retry_count >= 2).
    By the time we reach this node the retry_count has already been incremented
    by capture_rejection_reason, so values are 1 or 2 at most.
    """
    return Event(route="RETRY", output=node_input)


# ---------------------------------------------------------------------------
# Retry analysis agent — re-runs RCA with rejection feedback as context
# ---------------------------------------------------------------------------

retry_analysis_agent = Agent(
    name="retry_analysis_agent",
    model=Gemini(
        model=_MODEL,
        retry_options=types.HttpRetryOptions(attempts=3),
    ),
    mode="single_turn",
    instruction="""You are re-analyzing a production incident after a previous RCA was rejected by an engineer.

=== ORIGINAL ANOMALY ===
{anomaly_payload}

=== PREVIOUS RCA (REJECTED) ===
{rca_report}

=== REJECTION FEEDBACK ===
{rejection_history_text}

Your task: produce an improved RCA that directly addresses the rejection feedback above.

Steps:
1. Call `read_log_window` again using the subscription, time window, and error pattern from the anomaly above.
2. Carefully re-examine the logs with the rejection feedback in mind:
   - If the feedback says the root cause was wrong, look deeper for the true cause.
   - If citations were inaccurate, re-verify every log line number you cite.
   - If the RCA was incomplete, ensure you cover all findings in the log window.
3. Cite the EXACT log line number(s) for EVERY finding. No claim without a citation.
4. Call `emit_rca_log` with your updated root cause, confidence level, and citation lines.
5. Return the complete improved RCA in this format:

## RCA Report (Retry) — <incident_id>

**Service:** <service_name>
**Anomaly:** <error_pattern> spike of <spike_percent>%
**Log window:** <window_start> → <window_end>
**Changes from previous RCA:** <brief summary of what was corrected>

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
    tools=[read_log_window, emit_rca_log],
)


# ---------------------------------------------------------------------------
# Action agent — executes write actions after HITL decisions
# ---------------------------------------------------------------------------

action_agent = Agent(
    name="action_agent",
    model=Gemini(
        model=_MODEL,
        retry_options=types.HttpRetryOptions(attempts=3),
    ),
    mode="single_turn",
    instruction="""You process the engineer's decision after an RCA review.

The RCA report and context are available below. Do NOT ask the engineer for any information.

--- RCA REPORT ---
{rca_report}
--- END RCA REPORT ---

Incident ID:    {incident_id}
Service:        {service_name}
Decision:       {hitl_decision}
HITL Score:     {hitl_score}
Reviewed by:    {reviewed_by}
Attempt number: {attempt_number}
Anomaly data:   {anomaly_payload}

==========================================================
IF {hitl_decision} is "acknowledge":
==========================================================

1. Call `file_jira_ticket` using the incident ID, service name, root cause,
   evidence citations, and full RCA description extracted from the report above.

2. Call `update_incident_status` with status='triage_completed' and the root
   cause as the resolution note.

3. Call `store_feedback` with ALL of these exact arguments:
   - incident_id            = {incident_id}
   - attempt_number         = {attempt_number}
   - hitl_decision          = "acknowledge"
   - hitl_score             = {hitl_score}
   - reviewed_by            = {reviewed_by}
   - jira_key               = the ticket key returned by file_jira_ticket (use "" if skipped)
   - rejection_reason_code  = 0
   - rejection_reason_label = ""
   - rejection_notes        = ""
   - anomaly_payload        = {anomaly_payload}

4. Confirm all actions and report the Jira ticket URL (or skipped status).

==========================================================
IF {hitl_decision} is "escalate":
==========================================================

This RCA was rejected {attempt_number} time(s) and is being escalated for engineering
investigation. File a Jira ticket regardless — prefix the summary with "[ESCALATED]".

Rejection history:
{rejection_history_text}

1. Call `file_jira_ticket` with summary starting "[ESCALATED] ..." and include
   the full rejection history in the description.

2. Call `update_incident_status` with status='escalated' and a note that this
   was escalated after {attempt_number} rejection(s).

3. Call `store_feedback` with ALL of these exact arguments:
   - incident_id            = {incident_id}
   - attempt_number         = {attempt_number}
   - hitl_decision          = "escalate"
   - hitl_score             = {hitl_score}
   - reviewed_by            = {reviewed_by}
   - jira_key               = the ticket key returned by file_jira_ticket (use "" if skipped)
   - rejection_reason_code  = {rejection_reason_code}
   - rejection_reason_label = {rejection_reason_label}
   - rejection_notes        = {rejection_notes}
   - anomaly_payload        = {anomaly_payload}

4. Confirm escalation and report the Jira ticket URL.

Be concise — report exactly what was done.
""",
    tools=[file_jira_ticket, update_incident_status, store_feedback],
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
        # First attempt: analysis → HITL → route (defines request_rca_approval→route_hitl_decision)
        (log_analysis_agent, request_rca_approval, route_hitl_decision),
        # Retry attempt(s) feed into the same HITL node (edge already defined above)
        (retry_analysis_agent, request_rca_approval),
        # HITL routing: acknowledge → action_agent, reject → retry loop
        # (3rd attempt always routes ACKNOWLEDGE with hitl_decision="escalate" in state)
        (
            route_hitl_decision,
            {
                "ACKNOWLEDGE": action_agent,
                "REJECT": request_rejection_reason,
            },
        ),
        # Rejection reason collection → increment counters → route to retry
        (request_rejection_reason, capture_rejection_reason, route_after_rejection),
        (route_after_rejection, {"RETRY": retry_analysis_agent}),
    ],
)

app = App(
    root_agent=root_agent,
    name="app",
    resumability_config=ResumabilityConfig(is_resumable=True),
)
