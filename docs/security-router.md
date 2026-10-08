# Security Router

## Purpose

The Security Router is a versioned control-plane API for requesting security
checks. It accepts structured requests and delegates them to internal component
interfaces. It does not run tools, transfer data, perform requested actions, or
claim that inputs are safe.

The router is available under `/api/v1/security`. `GET /health` and the Input
Gateway at `POST /api/v1/inputs` remain available.

## Implemented now

- The Security Router is registered in the FastAPI application.
- Requests are validated with Pydantic models that reject unknown fields and
  blank required labels.
- `/analyze` sends content through the existing Input Gateway, including when
  the request is a previously returned `SecurityInput`. Gateway-owned IDs,
  timestamps, trust labels, and hashes are regenerated.
- `/check-tool`, `/check-data`, and `/check-action` are decision-only endpoints.
- Unimplemented authorization checks fail closed. Tool arguments and action
  targets are not executed or returned.
- Audit logging records only a fixed event name, request ID when available,
  decision, and allow status. It omits content, arguments, and targets.
- `GET /status` distinguishes active API interfaces from unimplemented
  security components.

The `/analyze` response reports `analysis_status: "not_implemented"`,
`threat: "not_assessed"`, an unknown severity, a null risk score, and a review
action. These values explicitly do not represent a threat assessment.

## Endpoints

### `POST /api/v1/security/analyze`

Accepts either the Input Gateway request shape:

```json
{
  "source_type": "text",
  "source_name": "task.txt",
  "content": "Summarize the quarterly report.",
  "metadata": {}
}
```

or a `SecurityInput` response from `POST /api/v1/inputs`. In both cases the
request is passed through the Input Gateway again. The response is structured
and explicitly marked unimplemented:

```json
{
  "input_id": "generated-uuid",
  "analysis_status": "not_implemented",
  "risk_score": null,
  "severity": "UNKNOWN",
  "threat": "not_assessed",
  "action": "REVIEW",
  "indicators": [],
  "reason": "Threat detection and risk scoring are not implemented."
}
```

### `POST /api/v1/security/check-tool`

Request: `{"tool_name":"file_read","arguments":{}}`.

It returns the requested `tool_name`, `allowed`, `action`, `reason`, and
`policy_status`. It always denies tool access while the Policy Engine is
unavailable. It never returns arguments or calls a tool.

### `POST /api/v1/security/check-data`

Request: `{"data_type":"confidential","destination":"external"}`.

It denies data movement while authorization policy is unavailable. The
classification and destination are caller-provided labels; the Data Classifier
does not verify the underlying data.

### `POST /api/v1/security/check-action`

Request: `{"action":"send_email","target":"external@example.com"}`.

It denies the action while policy evaluation is unavailable. It does not send
email or contact the target.

### `GET /api/v1/security/status`

Returns status for the router, Input Gateway, threat detector, risk engine,
policy engine, data classifier, tool gateway, and audit logging.

## Component boundaries

The router delegates orchestration to `SecurityService`. That service calls
separate threat-detector, risk-engine, data-classifier, policy-engine,
tool-gateway, and audit-logger interfaces. The threat detector and risk engine
return explicitly unimplemented results. The policy stub denies by default.
The Tool Gateway interface only checks a request and has no execution method.

### Planned for later

- **Threat Detector:** inspect normalized untrusted inputs and return evidence.
- **Risk Engine:** calculate a documented risk score from evidence and context.
- **Policy Engine:** evaluate identity, scope, risk, data sensitivity, and rules.
- **Data Classifier:** classify content independently of caller-provided labels.
- **Tool Gateway:** mediate and execute only explicitly authorized capabilities.
- **Persistent audit system:** store access-controlled, tamper-aware records.

These capabilities are not implemented by the current stubs. The AI/LLM is not
an authorization boundary: a model may suggest actions, but only an external
policy enforcement layer should authorize them. Until that layer exists, these
check endpoints deny access and never perform the requested operations.
