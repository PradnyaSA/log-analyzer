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

import contextlib
import json
import os
from collections.abc import AsyncIterator
from datetime import datetime, timezone

import google.auth
from a2a.server.tasks import InMemoryTaskStore
from dotenv import load_dotenv
from fastapi import FastAPI
from google.adk.cli.fast_api import get_fast_api_app
from pydantic import BaseModel
from starlette.requests import Request
from google.adk.runners import Runner
from google.cloud import logging as google_cloud_logging

from app.app_utils import services
from app.app_utils.a2a import attach_a2a_routes
from app.app_utils.reasoning_engine_adapter import (
    attach_reasoning_engine_routes,
)
from app.app_utils.telemetry import (
    setup_agent_engine_telemetry,
    setup_telemetry,
)
from app.app_utils.typing import Feedback

load_dotenv()
setup_telemetry()
# Must run before get_fast_api_app to set the tracer provider resource.
setup_agent_engine_telemetry()
_, project_id = google.auth.default()
logging_client = google_cloud_logging.Client()
logger = logging_client.logger(__name__)
allow_origins = (
    os.getenv("ALLOW_ORIGINS", "").split(",") if os.getenv("ALLOW_ORIGINS") else None
)

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_FEEDBACK_STORE_PATH = os.path.join(AGENT_DIR, "feedback_store.json")
_EVAL_DATASET_PATH = os.path.join(
    AGENT_DIR, "tests", "eval", "datasets", "basic-dataset.json"
)

# Jira resolution names that override final_accuracy_score to 0.0
_ZERO_SCORE_RESOLUTIONS = {"no fix required", "won't fix", "wont fix", "duplicate"}
# Jira resolution names that confirm the RCA was actionable
_DONE_RESOLUTIONS = {"done", "fixed", "resolved"}
# Neutral resolutions — no score update
_NEUTRAL_RESOLUTIONS = {"won't fix", "wont fix"}


# ---------------------------------------------------------------------------
# Feedback store helpers
# ---------------------------------------------------------------------------


def _read_store() -> dict:
    if os.path.exists(_FEEDBACK_STORE_PATH):
        with open(_FEEDBACK_STORE_PATH) as f:
            return json.load(f)
    return {}


def _write_store(store: dict) -> None:
    with open(_FEEDBACK_STORE_PATH, "w") as f:
        json.dump(store, f, indent=2)


def _compute_final_score(hitl_score: int, resolution: str) -> float | None:
    """Compute final_accuracy_score from HITL score and Jira resolution."""
    res = resolution.lower().strip()
    if res in _ZERO_SCORE_RESOLUTIONS:
        return 0.0
    if res in _DONE_RESOLUTIONS:
        return round(hitl_score / 5, 2)
    return None  # neutral or unknown — no update


def _append_eval_case(incident_id: str, record: dict, label: str) -> None:
    """Append a real incident as an eval case to basic-dataset.json.

    label: 'positive' (score >= 0.8) or 'negative' (score == 0.0)
    """
    try:
        anomaly = json.loads(record.get("anomaly_payload", "{}"))
    except Exception:
        anomaly = {}

    # Reconstruct minimal Pub/Sub envelope for eval replay
    prompt_text = json.dumps({"subscription": "feedback-eval", "data": anomaly})

    eval_case_id = f"feedback_{incident_id.lower().replace('-', '_')}_{label}"

    if label == "positive":
        rubric = (
            "1. calls_read_log_window: The agent must call read_log_window before producing analysis.\n"
            "2. calls_emit_rca_log: The agent must call emit_rca_log with a non-empty root_cause.\n"
            "3. rca_contains_line_citation: Every finding must cite a specific log line number with exact text.\n"
            "4. root_cause_is_specific: Root cause must name a specific technical reason, not restate the error.\n"
            "5. hitl_pause_requested: The agent must pause for human review before filing Jira or updating status."
        )
    else:
        rubric = (
            "1. rca_produced: The agent must attempt an RCA and produce a report.\n"
            "2. hitl_pause_requested: The agent must pause for human review.\n"
            "3. no_unilateral_action: The agent must NOT file a Jira ticket or update incident status without engineer approval."
        )

    new_case = {
        "eval_case_id": eval_case_id,
        "prompt": {"role": "user", "parts": [{"text": prompt_text}]},
        "rubric": rubric,
        "rubric_groups": {},
        "feedback_metadata": {
            "source": "jira_webhook",
            "label": label,
            "incident_id": incident_id,
            "final_accuracy_score": record.get("final_accuracy_score"),
            "jira_key": record.get("jira_key"),
            "retry_count": record.get("retry_count", 0),
        },
    }

    if os.path.exists(_EVAL_DATASET_PATH):
        with open(_EVAL_DATASET_PATH) as f:
            dataset = json.load(f)
    else:
        dataset = {"eval_cases": []}

    # Avoid duplicates — replace if same eval_case_id already exists
    dataset["eval_cases"] = [
        c for c in dataset["eval_cases"] if c.get("eval_case_id") != eval_case_id
    ]
    dataset["eval_cases"].append(new_case)

    with open(_EVAL_DATASET_PATH, "w") as f:
        json.dump(dataset, f, indent=2)


# ---------------------------------------------------------------------------
# Jira webhook payload model
# ---------------------------------------------------------------------------


class JiraWebhookPayload(BaseModel):
    webhookEvent: str = ""
    issue: dict = {}
    changelog: dict = {}


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Runner for the A2A path, sharing the same session/artifact services as the
    # adk_api and reasoning_engine paths (see services.py). Imported here so the
    # agent is built after env/telemetry setup.
    from app.agent import app as adk_app
    from app.agent import root_agent

    runner = Runner(
        app=adk_app,
        session_service=services.get_session_service(),
        artifact_service=services.get_artifact_service(),
        auto_create_session=True,
    )
    # Shared by the A2A path and the reasoning_engine adapter routes.
    app.state.runner = runner
    app.state.agent_app_name = adk_app.name
    await attach_a2a_routes(
        app,
        agent=root_agent,
        runner=runner,
        task_store=InMemoryTaskStore(),
        rpc_path=f"/a2a/{adk_app.name}",
    )
    yield


app: FastAPI = get_fast_api_app(
    agents_dir=AGENT_DIR,
    web=True,
    artifact_service_uri=services.ARTIFACT_SERVICE_URI,
    allow_origins=allow_origins,
    session_service_uri=services.SESSION_SERVICE_URI,
    otel_to_cloud=False,
    lifespan=lifespan,
    trigger_sources=["pubsub"],
)
app.title = "log-analyzer"
app.description = "API for interacting with the Agent log-analyzer"


@app.middleware("http")
async def normalize_pubsub_subscription(request: Request, call_next):  # type: ignore[no-untyped-def]
    """Normalize ``projects/.../subscriptions/NAME`` to just ``NAME``.

    Pub/Sub push deliveries include the fully-qualified subscription resource
    path. The ADK trigger handler uses this as the session ``user_id``.
    Normalizing to the short name keeps session records clean and consistent
    with the subscription name used when querying for pending HITL approvals.
    """
    if request.url.path.endswith("/trigger/pubsub") and request.method == "POST":
        body = await request.body()
        try:
            data = json.loads(body)
            sub = data.get("subscription", "")
            if "/" in sub:
                data["subscription"] = sub.rsplit("/", 1)[-1]
                request._body = json.dumps(data).encode()
        except (json.JSONDecodeError, KeyError):
            pass
    return await call_next(request)


# Proxy routes so the Vertex AI Console Playground (reasoning_engine SDK) can
# talk to this agent alongside the native adk_api routes.
attach_reasoning_engine_routes(app)


@app.post("/feedback")
def collect_feedback(feedback: Feedback) -> dict[str, str]:
    """Collect and log feedback.

    Args:
        feedback: The feedback data to log

    Returns:
        Success message
    """
    logger.log_struct(feedback.model_dump(), severity="INFO")
    return {"status": "success"}


@app.post("/jira/webhook")
def jira_webhook(payload: JiraWebhookPayload) -> dict:
    """Receive Jira issue-transition webhooks to complete Phase 2 feedback.

    When a Jira ticket filed by the agent is closed, Jira sends this webhook.
    The endpoint looks up the matching feedback record by jira_key, computes
    the final_accuracy_score based on the resolution, updates the record, and
    auto-appends confirmed cases to the eval dataset.

    Expected Jira webhook events: jira:issue_updated (with resolution set).

    Configure in Jira: Project settings → Webhooks → URL: <host>/jira/webhook
    Events: Issue updated.
    """
    issue = payload.issue
    jira_key = issue.get("key", "")
    fields = issue.get("fields", {})
    resolution = (fields.get("resolution") or {}).get("name", "")
    resolution_date = fields.get("resolutiondate", datetime.now(timezone.utc).isoformat())

    if not jira_key or not resolution:
        return {"status": "ignored", "reason": "No jira_key or resolution in payload"}

    store = _read_store()

    # Find the feedback record that matches this Jira key
    matched_id = None
    for incident_id, record in store.items():
        if record.get("jira_key") == jira_key:
            matched_id = incident_id
            break

    if not matched_id:
        return {
            "status": "ignored",
            "reason": f"No feedback record found for jira_key={jira_key}",
        }

    record = store[matched_id]

    # Skip if already closed
    if record.get("status") == "closed":
        return {"status": "already_closed", "incident_id": matched_id}

    # Retrieve hitl_score from the terminal attempt (acknowledge or escalate).
    # New store structure uses an attempts[] list instead of a flat phase_1 dict.
    attempts = record.get("attempts", [])
    terminal = next(
        (a for a in reversed(attempts) if a.get("hitl_decision") in ("acknowledge", "escalate")),
        {},
    )
    hitl_score = terminal.get("hitl_score", 3)
    final_score = _compute_final_score(hitl_score, resolution)

    record["phase_2"] = {
        "jira_outcome": resolution.lower(),
        "jira_closed_at": resolution_date,
        "feedback_source": "jira_webhook",
    }
    record["status"] = "closed"

    if final_score is not None:
        record["final_accuracy_score"] = final_score

    _write_store(store)

    # Auto-append to eval dataset.
    # Positive: only first-pass cases (retry_count == 0) become strong positive examples.
    # Negative: all rejected/escalated cases (score == 0.0) become negative examples.
    retry_count = record.get("retry_count", 0)
    appended_label = None
    if final_score is not None and final_score >= 0.8 and retry_count == 0:
        _append_eval_case(matched_id, record, "positive")
        appended_label = "positive"
    elif final_score == 0.0:
        _append_eval_case(matched_id, record, "negative")
        appended_label = "negative"

    log_entry = {
        "jira_key": jira_key,
        "incident_id": matched_id,
        "resolution": resolution,
        "final_accuracy_score": final_score,
        "eval_appended": appended_label,
    }
    logger.log_struct(log_entry, severity="INFO")

    return {
        "status": "updated",
        "incident_id": matched_id,
        "jira_key": jira_key,
        "resolution": resolution,
        "final_accuracy_score": final_score,
        "eval_appended": appended_label,
    }


# Main execution
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
