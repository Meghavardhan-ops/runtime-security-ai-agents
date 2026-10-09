# Security Router

## Purpose and limits

The versioned Security API at `/api/v1/security` provides deterministic, check-only security decisions. It does not execute tools, transfer data, run requested actions, or authenticate synthetic agent IDs. The dashboard displays decisions and component state returned by this API.

## Request paths

- `POST /analyze`: Input Gateway normalization → Threat Detector → Risk Engine → Policy Engine risk evaluation → metadata-only audit record. Unknown assessments fail closed. The final action uses the strongest risk/policy result.
- `POST /check-tool`: Tool Gateway validates bounded, JSON-like inert arguments and consults the Policy Engine. Arguments are never executed or logged.
- `POST /check-data`: evaluates caller-provided labels only. This endpoint cannot verify those labels and forces unknown classification for unverified external transfers.
- `POST /check-data-content`: DLP scans supplied text and returns indicator names and scan status, never matched secret values. DLP findings can raise the effective classification before Policy Engine evaluation. Since DLP no-match cannot verify the caller's label, a policy-allowed content flow returns `REVIEW` while the Data Classifier is incomplete. Existing policy `BLOCK` results remain `BLOCK`.
- `POST /check-action`: policy check only; it does not contact its target.
- `GET /monitoring` and `/monitoring/summary`: return safe event metadata held in a bounded in-process buffer. Events are lost on process restart and are not shared across workers.
- `GET /status`: reports active implemented controls and marks the label-carrying Data Classifier `incomplete`.

## Synthetic agent permissions

- `GET /agent-permissions` returns the local registry, allowed tools and data classifications, and recent/denied decisions drawn from the actual in-process audit buffer.
- `POST /check-agent-tool` first checks the local synthetic agent scope and then the existing Tool Gateway and Policy Engine. It never executes a tool.
- `POST /check-agent-data-content` scans supplied content, checks the resulting effective classification against the agent scope, then applies the Policy Engine. Because the current Data Classifier is a label-carrying placeholder and DLP no-match is not proof of public content, an otherwise-allowed in-scope request returns `REVIEW` until a trusted classifier is implemented. Policy or scope `BLOCK` decisions remain `BLOCK`.

The registry contains only `agent-research` and `agent-analyst`. Their IDs are caller-supplied demonstration labels, **not authenticated identity claims**. This application has no authentication or trusted agent execution context. A client can claim either registered ID, so these permissions demonstrate deterministic scope checks only and must not be used as production identity enforcement. Integrate IDs from a verified server-side principal before relying on them.

Agent audit events retain only a registered ID (or `unknown_agent`), request kind, a small allow-listed resource label, decision, and timestamp. Raw prompts, DLP matches, secrets, and tool arguments are never placed in the monitoring record.

## Component status

The Threat Detector and Risk Engine operate deterministically on request content and typed detector results. The Policy Engine evaluates local validated YAML rules. DLP uses bounded deterministic pattern scanning and does not certify that unmatched content is safe. The Data Classifier only carries labels; it does not independently inspect content, so it remains incomplete. The Tool Gateway only authorizes requests and has no execution method. Audit events are metadata-only, bounded, and in memory.

If the local policy configuration cannot be loaded, policy status is unavailable and policy decisions fail closed. The agent registry does not authenticate identities and does not replace the Policy Engine.

## Response compatibility

Response fields and the `ALLOW` / `REVIEW` / `BLOCK` action vocabulary remain unchanged. `SecurityDecision.allowed` is true only for `ALLOW`; `REVIEW` and `BLOCK` both deny immediate access. For `/check-data-content` and `/check-agent-data-content`, requests that could previously have returned `ALLOW` solely from a caller-supplied label now return `REVIEW` when the configured policy allows them but content classification is unverified; existing policy or agent-scope `BLOCK` results remain `BLOCK`. DLP responses contain scan status, classification metadata, and indicator names, never matched values or source content. `/status` reports policy availability as `active` or `unavailable` and keeps the current placeholder Data Classifier as `incomplete`.

`SecurityDecision.policy_status` now reports `available` or `unavailable` for decisions produced by the configured Policy Engine and Tool Gateway; older direct model construction using `not_implemented` remains accepted for compatibility. Consumers should handle all three values during migration and should use `/status` or a runtime decision for current availability. `ThreatAssessment.status` likewise continues accepting the legacy `not_implemented` value, while `ThreatDetector.analyze()` emits `analyzed` and the runtime `/analyze` response uses `analysis_status: analyzed` or `fail_closed`.

`POST /analyze` continues to use the existing response model. Runtime service responses set `analysis_status` to `analyzed` or `fail_closed`, and `threat` to a detector category or `not_assessed`; the legacy model defaults (`not_implemented` and `not_assessed`) remain for callers that directly construct the response model without runtime analysis. The `action` enum has not changed.
