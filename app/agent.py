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
from typing import Literal, Optional

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

    anomaly_type: Literal["error_rate", "retrieval_quality"] = Field(
        default="error_rate",
        description="Type of anomaly: 'error_rate' for HTTP error spikes, 'retrieval_quality' for semantic quality degradation",
    )
    service_name: str = Field(description="Name of the service with the anomaly")
    error_pattern: str = Field(
        default="",
        description="Error type or pattern, e.g. 'HTTP 404' (error_rate anomalies only)",
    )
    spike_percent: float = Field(
        default=0.0, description="Percentage spike above baseline (error_rate anomalies only)"
    )
    log_subscription: str = Field(
        description="Pub/Sub subscription name for the audit log stream"
    )
    window_start: str = Field(
        description="ISO 8601 start of the log window to analyze"
    )
    window_end: str = Field(description="ISO 8601 end of the log window to analyze")
    incident_id: str = Field(description="Incident tracking ID")
    threshold: float = Field(
        default=15.0, description="Anomaly threshold that was crossed (percent)"
    )
    # retrieval_quality optional fields
    topic_cluster: Optional[str] = Field(
        default=None,
        description="Topic cluster with quality degradation, e.g. 'international_travel_policy'",
    )
    quality_signals: Optional[dict] = Field(
        default=None, description="Quality signal breakdown dict"
    )
    affected_query_count: Optional[int] = Field(
        default=None, description="Number of queries affected in the window"
    )
    avg_completeness_score: Optional[float] = Field(
        default=None, description="Average completeness score in window (0.0–1.0)"
    )
    baseline_completeness: Optional[float] = Field(
        default=None, description="Expected baseline completeness score (0.0–1.0)"
    )
    sample_trace_ids: Optional[list] = Field(
        default=None, description="Sample trace IDs of degraded queries"
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


def read_quality_log_window(
    log_subscription: str,
    window_start: str,
    window_end: str,
    topic_cluster: str,
    max_entries: int,
) -> dict:
    """Read quality-enriched audit logs from the AI agent response stream.

    Fetches quality audit log entries within the specified time window filtered
    to the given topic cluster. Entries include completeness scores,
    returned_fields vs expected_fields, and RAG retrieval signals.

    Args:
        log_subscription: Pub/Sub subscription name for the quality audit log stream.
        window_start: ISO 8601 start timestamp of the log window.
        window_end: ISO 8601 end timestamp of the log window.
        topic_cluster: Topic cluster to filter for, e.g. 'international_travel_policy'.
        max_entries: Maximum number of log entries to return.

    Returns:
        dict with 'status', 'entries' (list of quality log entries), and 'total_count'.
    """
    # Production: pull quality-enriched structured log messages from the Pub/Sub
    # subscription within the time window using google.cloud.pubsub_v1.SubscriberClient,
    # filtered by topic_cluster. Stub corpus below simulates a real degradation event
    # in the international_travel_policy cluster caused by a stale vector index.

    _intl_policy_corpus = [
        {
            "line": 4401,
            "timestamp": "2026-07-03T14:01:12Z",
            "level": "INFO",
            "trace_id": "qt0081",
            "text": (
                '[concierge-agent] query="visa requirements for Japan" '
                "topic=international_travel_policy status=200 completeness=0.91 "
                'returned_fields=["visa_type","duration","entry_requirements"] '
                'expected_fields=["visa_type","duration","entry_requirements","health_docs"] '
                "retrieval_score=0.88"
            ),
        },
        {
            "line": 4407,
            "timestamp": "2026-07-03T14:03:28Z",
            "level": "WARNING",
            "trace_id": "qt0083",
            "text": (
                '[concierge-agent] query="travel insurance for EU trip" '
                "topic=international_travel_policy status=200 completeness=0.52 "
                'returned_fields=["basic_coverage"] '
                'expected_fields=["basic_coverage","medical_evacuation","trip_cancellation","pre_existing_conditions"] '
                "retrieval_score=0.61 rag_chunks_retrieved=2 rag_chunks_expected=8"
            ),
        },
        {
            "line": 4412,
            "timestamp": "2026-07-03T14:04:55Z",
            "level": "WARNING",
            "trace_id": "qt0085",
            "text": (
                '[concierge-agent] query="international roaming policy Asia Pacific" '
                "topic=international_travel_policy status=200 completeness=0.48 "
                'returned_fields=["roaming_rates"] '
                'expected_fields=["roaming_rates","data_caps","partner_networks","emergency_numbers","sim_options"] '
                "retrieval_score=0.59 rag_chunks_retrieved=1 rag_chunks_expected=5"
            ),
        },
        {
            "line": 4419,
            "timestamp": "2026-07-03T14:06:11Z",
            "level": "WARNING",
            "trace_id": "qt0087",
            "text": (
                '[concierge-agent] query="baggage allowance for international connections" '
                "topic=international_travel_policy status=200 completeness=0.44 "
                'returned_fields=["carry_on_limit"] '
                'expected_fields=["carry_on_limit","checked_bags","oversize_fees","connection_rules","airline_specific"] '
                "retrieval_score=0.57 rag_chunks_retrieved=1 rag_chunks_expected=5"
            ),
        },
        {
            "line": 4425,
            "timestamp": "2026-07-03T14:07:33Z",
            "level": "ERROR",
            "trace_id": "qt0089",
            "text": (
                "[concierge-agent] rag_retrieval_warning: topic=international_travel_policy "
                "avg_retrieval_score=0.58 threshold=0.75 "
                "— vector index may be stale; last_reindex=2026-06-19T08:00:00Z (14 days ago)"
            ),
        },
        {
            "line": 4431,
            "timestamp": "2026-07-03T14:08:47Z",
            "level": "WARNING",
            "trace_id": "qt0091",
            "text": (
                '[concierge-agent] query="customs declaration rules South America" '
                "topic=international_travel_policy status=200 completeness=0.41 "
                'returned_fields=["declaration_form"] '
                'expected_fields=["declaration_form","prohibited_items","duty_free_limits","currency_limits","agricultural_restrictions"] '
                "retrieval_score=0.54 rag_chunks_retrieved=1 rag_chunks_expected=5"
            ),
        },
        {
            "line": 4438,
            "timestamp": "2026-07-03T14:09:59Z",
            "level": "WARNING",
            "trace_id": "qt0093",
            "text": (
                '[concierge-agent] query="health documentation for travel to malaria zones" '
                "topic=international_travel_policy status=200 completeness=0.38 "
                'returned_fields=["vaccination_required"] '
                'expected_fields=["vaccination_required","prophylaxis_options","clinic_locator","timing_before_travel","certificate_format"] '
                "retrieval_score=0.51 rag_chunks_retrieved=1 rag_chunks_expected=5"
            ),
        },
        {
            "line": 4445,
            "timestamp": "2026-07-03T14:11:22Z",
            "level": "ERROR",
            "trace_id": "qt0095",
            "text": (
                "[concierge-agent] quality_degradation_alert: topic=international_travel_policy "
                "affected_queries=47 window=60min avg_completeness=0.43 baseline_completeness=0.89 "
                "degradation_delta=-0.46 — threshold exceeded"
            ),
        },
    ]

    return {
        "status": "success",
        "subscription": log_subscription,
        "window": {"start": window_start, "end": window_end},
        "topic_cluster": topic_cluster,
        "entries": _intl_policy_corpus[:max_entries],
        "total_count": len(_intl_policy_corpus),
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
        "anomaly_type": anomaly.get("anomaly_type", "error_rate"),
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

    # Infer anomaly_type if not provided: quality events include avg_completeness_score
    anomaly_type = data.get(
        "anomaly_type",
        "retrieval_quality" if "avg_completeness_score" in data else "error_rate",
    )

    event_output: dict = {
        "anomaly_type": anomaly_type,
        "service_name": data.get("service_name", "unknown"),
        "error_pattern": data.get("error_pattern", ""),
        "spike_percent": float(data.get("spike_percent", 0)),
        "log_subscription": data.get("log_subscription", ""),
        "window_start": data.get("window_start", ""),
        "window_end": data.get("window_end", ""),
        "incident_id": data.get("incident_id", ""),
        "threshold": float(data.get("threshold", 15.0)),
        # Quality-specific fields (None when not present)
        "topic_cluster": data.get("topic_cluster"),
        "quality_signals": data.get("quality_signals"),
        "affected_query_count": data.get("affected_query_count"),
        "avg_completeness_score": data.get("avg_completeness_score"),
        "baseline_completeness": data.get("baseline_completeness"),
        "sample_trace_ids": data.get("sample_trace_ids"),
    }
    # Pass eval control keys through so route_by_anomaly_type can store them in state.
    for k, v in data.items():
        if k.startswith("eval_"):
            event_output[k] = v
    return Event(output=event_output)


def validate_event(node_input: dict, ctx: Context) -> Event:
    """Validate that the parsed event has all required fields for its anomaly_type.

    Propagates parse errors (from parse_anomaly_event) as INVALID.
    For error_rate: requires service_name, error_pattern, log_subscription,
      window_start, window_end, incident_id.
    For retrieval_quality: requires service_name, log_subscription, window_start,
      window_end, incident_id, topic_cluster, avg_completeness_score, baseline_completeness.

    Routes:
      INVALID → validation_error_agent (human-readable error, exit)
      VALID   → deduplicate_check
    """
    if "error" in node_input:
        ctx.state["validation_error"] = node_input["error"]
        return Event(route="INVALID", output=node_input)

    anomaly_type = node_input.get("anomaly_type", "error_rate")
    missing = []

    for field in ("service_name", "log_subscription", "window_start", "window_end", "incident_id"):
        if not node_input.get(field):
            missing.append(field)

    if anomaly_type == "error_rate":
        if not node_input.get("error_pattern"):
            missing.append("error_pattern")
    elif anomaly_type == "retrieval_quality":
        for field in ("topic_cluster", "avg_completeness_score", "baseline_completeness"):
            if node_input.get(field) is None:
                missing.append(field)

    if missing:
        error_msg = (
            f"Missing required fields for anomaly_type='{anomaly_type}': {', '.join(missing)}"
        )
        ctx.state["validation_error"] = error_msg
        return Event(
            route="INVALID",
            output={
                "error": error_msg,
                "anomaly_type": anomaly_type,
                "incident_id": node_input.get("incident_id", ""),
            },
        )

    return Event(route="VALID", output=node_input)


def deduplicate_check(node_input: dict, ctx: Context) -> Event:
    """Check the feedback store for an existing record with the same incident_id.

    Blocks re-processing if the incident is already in-flight (pending_jira) or
    fully closed. Allows re-triggering if a previous run was rejected (status='rejected')
    so engineers can request a fresh attempt.

    In EVAL_MODE always routes NEW to avoid store state affecting eval reproducibility.

    Routes:
      DUPLICATE → _log_duplicate (exit)
      NEW       → enrich_context
    """
    if os.environ.get("EVAL_MODE", "").lower() == "true":
        return Event(route="NEW", output=node_input)

    incident_id = node_input.get("incident_id", "")
    if os.path.exists(_FEEDBACK_STORE_PATH):
        with open(_FEEDBACK_STORE_PATH) as f:
            store = json.load(f)
    else:
        store = {}

    record = store.get(incident_id)
    if record:
        status = record.get("status", "")
        if status in ("pending_jira", "closed"):
            ctx.state["duplicate_incident_id"] = incident_id
            ctx.state["duplicate_status"] = status
            return Event(
                route="DUPLICATE",
                output={"incident_id": incident_id, "status": status},
            )

    return Event(route="NEW", output=node_input)


def _log_duplicate(node_input: dict, ctx: Context) -> Event:
    """Emit a structured log for a duplicate incident and exit early."""
    incident_id = node_input.get("incident_id", ctx.state.get("duplicate_incident_id", ""))
    status = node_input.get("status", ctx.state.get("duplicate_status", ""))
    log_entry = {
        "severity": "INFO",
        "message": (
            f"Duplicate incident detected — skipping. "
            f"incident_id={incident_id} already has status={status}"
        ),
        "incident_id": incident_id,
        "duplicate_status": status,
    }
    print(json.dumps(log_entry), flush=True)
    return Event(output=node_input)


def enrich_context(node_input: dict, ctx: Context) -> Event:
    """Enrich workflow state with historical incident data for the same service.

    Reads the feedback store and injects the 3 most recent prior incidents
    for the same service into ctx.state so downstream agents can reference
    recurrence patterns, prior rejection reasons, and resolution outcomes.
    """
    service_name = node_input.get("service_name", "")
    current_id = node_input.get("incident_id", "")

    if os.path.exists(_FEEDBACK_STORE_PATH):
        with open(_FEEDBACK_STORE_PATH) as f:
            store = json.load(f)
    else:
        store = {}

    related = [
        r for iid, r in store.items()
        if r.get("service_name") == service_name and iid != current_id
    ]
    # Sort by most recent attempt timestamp descending, keep last 3
    related.sort(
        key=lambda r: (r.get("attempts") or [{}])[-1].get("timestamp", ""),
        reverse=True,
    )
    related = related[:3]

    ctx.state["historical_context"] = related
    ctx.state["historical_context_text"] = (
        "\n".join(
            f"  - {r['incident_id']}: {r.get('anomaly_type', r.get('error_pattern', ''))} "
            f"retry_count={r.get('retry_count', 0)} status={r.get('status', '')} "
            f"score={r.get('final_accuracy_score')}"
            for r in related
        )
        if related
        else "No prior incidents for this service."
    )

    return Event(output=node_input)


def route_by_anomaly_type(node_input: dict, ctx: Context) -> Event:
    """Route based on anomaly_type and (for error_rate) spike vs threshold.

    Stores anomaly data in workflow state for downstream nodes. Extracts and
    isolates eval control keys so they don't contaminate agent input schemas.
    Resets retry-loop counters fresh for every new anomaly event.

    Routes:
      BELOW_THRESHOLD  → _log_below_threshold → below_threshold_agent (exit)
      ANALYZE_ERROR    → log_analysis_agent (error-rate RCA pipeline)
      ANALYZE_QUALITY  → quality_analysis_agent (retrieval-quality RCA pipeline)
    """
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

    anomaly_type = anomaly.get("anomaly_type", "error_rate")

    if anomaly_type == "retrieval_quality":
        return Event(route="ANALYZE_QUALITY", output=anomaly)

    spike = anomaly.get("spike_percent", 0)
    threshold = anomaly.get("threshold", 15.0)
    if spike < threshold:
        return Event(route="BELOW_THRESHOLD", output=anomaly)
    return Event(route="ANALYZE_ERROR", output=anomaly)


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

# LLM node for invalid or unparseable events — produces a human-readable error
# report and exits. No tools are called.
validation_error_agent = Agent(
    name="validation_error_agent",
    model=Gemini(
        model=_MODEL,
        retry_options=types.HttpRetryOptions(attempts=3),
    ),
    mode="single_turn",
    instruction=(
        "You received an anomaly event that failed validation. "
        "The error details are provided in your input. "
        "Produce a concise, human-readable summary that: "
        "(1) states what validation check failed, "
        "(2) identifies which fields are missing or invalid, "
        "(3) advises how to correct the upstream event publisher to fix the issue. "
        "Do not call any tools. Do not perform RCA or incident analysis."
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
# LLM quality analysis agent — reads quality logs and produces a grounded
# retrieval degradation RCA report
# ---------------------------------------------------------------------------

quality_analysis_agent = Agent(
    name="quality_analysis_agent",
    model=Gemini(
        model=_MODEL,
        retry_options=types.HttpRetryOptions(attempts=3),
    ),
    mode="single_turn",
    instruction="""You are a quality analysis expert performing root cause analysis on AI agent response degradation.

You receive a quality anomaly event indicating that the concierge-agent is returning semantically
incomplete or inaccurate responses — even though HTTP status codes are 200 OK. The degradation
is in a specific topic cluster (e.g. international travel policy questions).

Your job:

1. Call `read_quality_log_window` with the log_subscription, window_start, window_end, and
   topic_cluster from the anomaly event.
2. Analyze the returned quality log entries carefully:
   - Identify which policy fields or sections are missing (returned_fields vs expected_fields).
   - Find the queries with the lowest completeness scores and highest field omission counts.
   - Look for RAG retrieval signals: low retrieval_score, rag_chunks_retrieved << rag_chunks_expected,
     or an explicit rag_retrieval_warning entry pointing to index staleness.
   - State the single root cause — the RAG or retrieval component responsible for the degradation
     (e.g., stale vector index, chunk truncation, embedding model drift, missing policy documents).
3. Cite the EXACT trace_id(s) and log line number(s) for EVERY finding. No claim without a citation.
4. Call `emit_rca_log` with your root cause, confidence level, and citation lines.
5. Return the complete RCA report in this format:

## Quality Degradation RCA — <incident_id>

**Service:** <service_name>
**Anomaly:** Retrieval quality degradation in topic cluster: <topic_cluster>
**Log window:** <window_start> → <window_end>
**Affected queries:** <affected_query_count> queries, avg completeness <avg_completeness_score> vs baseline <baseline_completeness>

### Root Cause
<one-sentence statement of root cause naming the specific RAG component>

### Evidence
- **Finding:** <description> — *Trace <trace_id>, Log line N: `<exact log text>`*
(repeat for each finding)

### Impact
<brief description of user-facing impact — what users are getting wrong or incomplete>

### Recommended Fix
<specific, actionable fix — e.g., re-index vector store, update chunking config, refresh policy documents>

**Confidence:** high | medium | low
""",
    input_schema=AnomalyEvent,
    tools=[read_quality_log_window, emit_rca_log],
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

    incoming = node_input if isinstance(node_input, str) else str(node_input)
    if incoming.strip():
        ctx.state["rca_report"] = incoming
    rca_report = ctx.state.get("rca_report", incoming)

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
        "  Reject:      {\"decision\": \"reject\", \"score\": <1-5>, \"reviewed_by\": \"<your email>\"}\n\n"
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

    # ADK passes the adk_request_input response as a dict; handle that before JSON parsing
    if isinstance(node_input, dict):
        parsed = node_input
    else:
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
            "reason_code": ctx.state.get("eval_rejection_reason_code") or 1,
            "notes": ctx.state.get("eval_rejection_notes") or "Eval mode rejection",
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

    In EVAL_MODE, request_rejection_reason is a generator that returns Event via
    StopIteration — ADK does not forward that return value as node_input to this
    node. So in EVAL_MODE we read eval_* keys directly from ctx.state instead of
    parsing node_input.
    """
    if os.environ.get("EVAL_MODE", "").lower() == "true":
        reason_code = int(ctx.state.get("eval_rejection_reason_code") or 1)
        notes = str(ctx.state.get("eval_rejection_notes") or "Eval mode rejection")[:200]
        reviewed_by = "eval-mode"
    else:
        # ADK passes the adk_request_input response as a dict; handle before JSON parsing.
        # Also guard against json.loads returning a non-dict (e.g. bare int "1").
        if isinstance(node_input, dict):
            parsed = node_input
        else:
            text = node_input if isinstance(node_input, str) else str(node_input)
            try:
                decoded = json.loads(text)
                parsed = decoded if isinstance(decoded, dict) else {}
            except json.JSONDecodeError:
                parsed = {}
        try:
            reason_code = int(parsed.get("reason_code", 7))
            notes = str(parsed.get("notes", ""))[:200]
            reviewed_by = str(parsed.get("reviewed_by", ctx.state.get("reviewed_by", "unknown")))
        except (TypeError, ValueError, AttributeError):
            reason_code = 7
            notes = (node_input if isinstance(node_input, str) else str(node_input))[:200]
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

    # Pass rejection summary downstream so route_after_rejection / retry_analysis_agent
    # receive a structured, non-None value regardless of EVAL_MODE.
    return Event(output={"reason_code": reason_code, "notes": notes, "reviewed_by": reviewed_by})


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

First, determine the anomaly type from the original anomaly payload above:
- If anomaly_type is "retrieval_quality": call `read_quality_log_window` using the
  log_subscription, window_start, window_end, and topic_cluster from the anomaly.
- Otherwise (anomaly_type "error_rate" or not set): call `read_log_window` using
  the log_subscription, window_start, window_end, and error_pattern from the anomaly.

Steps:
1. Call the appropriate log-reading tool based on anomaly_type (see above).
2. Carefully re-examine the logs with the rejection feedback in mind:
   - If the feedback says the root cause was wrong, look deeper for the true cause.
   - If citations were inaccurate, re-verify every log line number or trace_id you cite.
   - If the RCA was incomplete, ensure you cover all findings in the log window.
3. Cite the EXACT log line number(s) or trace_id(s) for EVERY finding. No claim without a citation.
4. Call `emit_rca_log` with your updated root cause, confidence level, and citation lines.
5. Return the complete improved RCA in the same format as the original, with an added section:

**Changes from previous RCA:** <brief summary of what was corrected or added>

**Confidence:** high | medium | low
""",
    tools=[read_log_window, read_quality_log_window, emit_rca_log],
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
        # Pre-processing chain: parse → validate → dedup → enrich → route
        ("START", parse_anomaly_event, validate_event),
        (
            validate_event,
            {
                "INVALID": validation_error_agent,
                "VALID": deduplicate_check,
            },
        ),
        (
            deduplicate_check,
            {
                "DUPLICATE": _log_duplicate,
                "NEW": enrich_context,
            },
        ),
        (enrich_context, route_by_anomaly_type),
        # 3-way routing by anomaly type
        (
            route_by_anomaly_type,
            {
                "BELOW_THRESHOLD": _log_below_threshold,
                "ANALYZE_ERROR": log_analysis_agent,
                "ANALYZE_QUALITY": quality_analysis_agent,
            },
        ),
        (_log_below_threshold, below_threshold),
        # Error-rate path: analysis → HITL → route
        # (defines request_rca_approval→route_hitl_decision 3-tuple)
        (log_analysis_agent, request_rca_approval, route_hitl_decision),
        # Quality path feeds into the same HITL node
        (quality_analysis_agent, request_rca_approval),
        # Retry attempt(s) feed into the same HITL node
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
