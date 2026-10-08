# AgentShield Security Model

The principles below guide future security modules. They describe intended design behavior; the current backend foundation does not enforce them beyond keeping configuration separate from code and ignoring local environment files in Git.

## Least privilege

Give each user, agent task, and tool only the minimum permissions needed for a defined operation. Prefer narrow, short-lived capabilities over broad credentials.

## Deny by default

Reject actions when a policy is absent, ambiguous, expired, or cannot be evaluated. Require explicit permission for consequential operations.

## Defense in depth

Use multiple independent controls: input provenance, threat inspection, policy evaluation, tool validation, output checks, and audit records. A detector alone must not be treated as a complete security boundary.

## External authorization

The model can propose actions but cannot grant itself permission. A deterministic policy component outside the model authorizes each sensitive action.

## Tool isolation

Keep tools behind a gateway that validates identity, scope, arguments, and impact. Do not give an agent direct database, shell, filesystem, or network access by default.

## Data classification

Label data by sensitivity and purpose. Minimize information sent to the model and prevent restricted data from flowing to unapproved tools or recipients.

## Auditability

Record the relevant source, policy version, decision, tool action, and outcome with timestamps and access controls. Define retention and redaction before storing sensitive evidence.

## Secure logging

Use structured logs, restrict access, and avoid logging secrets or full sensitive payloads. Sanitize untrusted strings to prevent log injection.

## Secret management

Keep credentials out of source control, prompts, and general logs. Use scoped credentials and an appropriate secret store when integrations are implemented. Local `.env` files are ignored by Git; `.env.example` contains placeholders only.

## Fail-safe behavior

On policy, detector, or gateway errors, fail closed for sensitive actions, preserve service availability where safe, and emit a sanitized operational event.
