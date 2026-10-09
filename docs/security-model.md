# AgentShield Security Model

The principles below describe the current deterministic check-only controls and their limits. Agent permission profiles are synthetic examples, DataClassifier carries unverified labels, audit events are in-process, and no tool or external data transfer is executed.

## Least privilege

Give each user, agent task, and tool only the minimum permissions needed for a defined operation. Prefer narrow, short-lived capabilities over broad credentials.

## Deny by default

Reject actions when a policy is absent, ambiguous, expired, or cannot be evaluated. Require explicit permission for consequential operations.

## Defense in depth

Use multiple independent controls: input provenance, threat inspection, policy evaluation, tool validation, output checks, and audit records. A detector alone must not be treated as a complete security boundary.

## External authorization

The model can propose actions but cannot grant itself permission. A deterministic policy component outside the model authorizes each sensitive action.

## Tool isolation

Keep tools behind a gateway that validates scope and bounded inert arguments. The current Tool Gateway only checks authorization; it does not execute tools. Synthetic agent IDs are caller-supplied and are not authenticated identities. Do not give an agent direct database, shell, filesystem, or network access by default.

## Data classification

The current DLP scanner detects a bounded set of sensitive patterns and raises effective labels before policy checks. No-pattern results do not prove content is public. DataClassifier carries caller labels but does not independently inspect or classify content.

## Auditability

Record allow-listed decision metadata and timestamps in a bounded in-process buffer. Events are not durable or shared across workers; define retention and access controls before adding persistent evidence storage.

## Secure logging

Use structured logs, restrict access, and avoid logging secrets or full sensitive payloads. Sanitize untrusted strings to prevent log injection.

## Secret management

Keep credentials out of source control, prompts, and general logs. Use scoped credentials and an appropriate secret store when integrations are implemented. Local `.env` files are ignored by Git; `.env.example` contains placeholders only.

## Fail-safe behavior

On policy, detector, or gateway errors, fail closed for sensitive actions, preserve service availability where safe, and emit a sanitized operational event.
