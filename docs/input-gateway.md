# Input Gateway

## Purpose

The Input Gateway is the normalization boundary between external content and future AgentShield security components. It accepts content labeled as `file`, `email`, `web`, `api`, `database`, or `text`, validates its shape and configured limits, normalizes text, records metadata, assigns an ID and UTC receive time, and computes a SHA-256 digest.

All submitted content is untrusted by default. The gateway does not interpret instructions or execute code, commands, URLs, files, or external services. It performs no file reads, network requests, database queries, or tool calls.

## Architecture

```text
Files / Email / Web / APIs / Database / Text
                    |
                    v
              Input Gateway
                    |
                    v
             Normalized Input
                    |
                    v
        Future Threat Detector (planned)
```

The gateway is available at `POST /api/v1/inputs`. A successful response uses HTTP 201 and returns the normalized record. Invalid input receives HTTP 422; a configured size or length limit violation receives HTTP 413.

## Validation and normalization

- `source_type` must be one of the six allowed values.
- `source_name` is Unicode NFC-normalized, trimmed, non-empty, limited by `INPUT_MAX_SOURCE_NAME_LENGTH`, and rejects control characters.
- `content` is Unicode NFC-normalized and line endings are converted to LF. Empty or whitespace-only content is rejected.
- Content length is measured in UTF-8 bytes and bounded by `INPUT_MAX_CONTENT_BYTES`.
- `metadata` must be JSON-serializable and is size-checked using its compact UTF-8 JSON representation against `INPUT_MAX_METADATA_BYTES`.
- Oversized data is rejected, never silently truncated.
- Caller-supplied gateway-owned fields such as `id`, `received_at`, `content_hash`, or `trusted` are rejected by the request schema.

Defaults are 65,536 content bytes, 255 source-name characters, and 16,384 metadata bytes. The limits are loaded from environment variables and can be tuned for the deployment.

## Security assumptions

- Every source is untrusted, including internal APIs and database records.
- `trusted` is generated as `false` and cannot be set by the caller.
- Normalization is a representation step only; it does not make content safe or determine whether instructions are malicious.
- A SHA-256 digest supports integrity comparison and correlation. It does not authenticate the source or prove that content is safe.
- The current endpoint is stateless and does not persist the input.

## Hashing

`content_hash` is the lowercase hexadecimal SHA-256 digest of the normalized UTF-8 content. Equivalent line endings and canonically equivalent Unicode text therefore produce the same digest after normalization.

## Logging

For each accepted input, the gateway logs only the ID, source type, escaped source name, UTC timestamp, trusted status, normalized content size in bytes, and content hash. It never logs content or metadata. Source names are JSON-escaped in the log message to reduce log-injection risk.

## Future integration

The normalized `SecurityInput` record is the intended handoff contract for a future threat detector. That detector is not implemented yet. The gateway does not assign a risk score, make policy decisions, grant tool access, or claim that submitted content is safe.
