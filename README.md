# log-analyzer
A demo repo for MCP component or Embeddable agent that can analyze logs in multi-agent environment

## Project Description

### Problem: 
I woke up to a Priority 2 incident last week — our concierge agent had a 20% spike in "information not found" responses. Traditionally, I would have pulled a team of experts onto a call to start triaging, but now I have AI for triaging AI that can pin down the exact log line, tool call, and step in the chain responsible — root cause analysis at machine speed, with every claim traceable back to the exact line that proves it.

### User: 
Engineer who grants the AI agent a read-only, temporary access to our application/server log files and ADK agent audit log store, then invokes it via the CLI during incident triage.

### Workflow automated: 
I used random sampling based on the incident's timestamps and pointed the log analyzer agent at that window for root cause analysis. Before I blinked, the agent pulled every relevant application/server log and agent audit log, and assembled a single trustworthy incident report. I could clearly see the anomaly within minutes: the information existed in our corpus; it just fell outside the Top-K cutoff our retrieval step was using. I closed the Priority 2 in minutes, turned that finding into the team's next retrieval-optimization task, and resumed my day as normal.
