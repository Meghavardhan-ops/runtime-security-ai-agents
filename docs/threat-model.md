# AgentShield Threat Model

This is a planned threat model for future AgentShield capabilities. The current service only exposes a health endpoint and database setup; it does not ingest the listed sources, run an agent, or enforce the mitigations described here.

## Assets

- Confidential files
- Database records
- API credentials
- Agent tools and their permissions
- User information
- Internal system data

## Threat sources

- Malicious users
- Malicious documents
- Malicious web content
- Malicious email content
- Poisoned API responses
- Poisoned database records

## Threat categories and planned mitigations

| Threat | Attack idea | Potential impact | Planned mitigation |
| --- | --- | --- | --- |
| Direct prompt injection | A user asks the agent to ignore safeguards or reveal protected context. | Disclosure, unsafe output, or attempted policy bypass. | Separate user intent from governing policy; inspect instructions; keep authorization outside the model; restrict tools by policy. |
| Indirect prompt injection | Retrieved file, web, or email content includes instructions aimed at the agent. | Untrusted content changes the task or triggers actions. | Preserve source provenance; treat retrieved text as data; inspect it; require external policy approval for actions. |
| Data exfiltration | An instruction asks the agent to send confidential material through a tool or response. | Confidential files, records, or internal data leave the authorized boundary. | Classify data; minimize context; filter outputs and tool payloads; block destinations not allowed by policy. |
| Unauthorized tool usage | The agent invokes a tool outside the user's task or granted scope. | Unapproved reads, writes, messages, or external side effects. | Route every call through a deny-by-default Tool Gateway with per-action authorization and argument validation. |
| Privilege escalation | A request attempts to use a broader identity, capability, or tool than authorized. | Access to higher-impact operations or other users' resources. | Bind permissions to authenticated identity and task scope; prohibit model-selected privilege changes; audit decisions. |
| Credential exposure | Secrets appear in prompts, retrieved content, logs, model context, or tool results. | Account compromise and unauthorized access. | Keep secrets outside model context; use scoped secret providers; redact logs; rotate credentials after suspected exposure. |
| Excessive agency | A broad task allows the agent to take many consequential steps without review. | Cascading changes, irreversible actions, or unexpected external effects. | Limit action count and scope; require confirmation for high-impact operations; apply timeouts, budgets, and stop conditions. |

## Assumptions and boundaries

- Future integrations will identify source and user/task context accurately.
- External authorization remains authoritative even when model output requests an exception.
- Synthetic tests will use local fixtures and mock tools; this plan does not authorize testing against real systems.
- Mitigations in the table are design goals, not present-day guarantees.
