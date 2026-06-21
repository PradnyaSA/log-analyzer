# log-analyzer
A demo repo for MCP component or Embeddable agent that can analyze logs in multi-agent environment

## Project Description

### Problem: 
I woke up to a Priority 2 incident last week — our concierge agent had a 20% spike in "information not found" responses. Typical SLA to resolving a Priority 2 incident is ~4-8hours, with initial response due in ~15mins to avoid further escalations. 

### Call-To-Action: 
Triaging that can pin down the exact log line, tool call, and step in the chain responsible — analysis starting with logs, with every claim traceable back to the exact line that proves it. Deliver a possible root cause of the problem. 

### User: 
Any engineer who invokes AI agent with a read-only, temporary access to our application/server log files and agent audit log store via the CLI during incident triage.

### Workflow automated: 
Traditionally(before AI), I would have pulled a team of experts onto a triaging call, but now I can use AI for AI. I used the incident's reported timestamps and pointed the **Log-Analyzer** agent at the narrowest possible window for root cause analysis. Before I blinked, the agent pulled every relevant application/server log and agent audit log, and assembled a single trustworthy incident report. I could clearly see the anomaly within minutes: the information existed in our corpus; it just fell outside the Top-K cutoff our retrieval step was using. I closed that Priority 2 in minutes, adding the finding to my team's next retrieval-optimization intake, and I resumed my day as normal.

---
