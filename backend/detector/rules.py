"""Pure regular-expression rules for analyzing untrusted text as data."""

import re

# The input has already been case-folded and punctuation-normalized. Rules are
# deliberately bounded so matches stay local to a phrase instead of matching
# unrelated words far apart in a long document.
INSTRUCTION_OVERRIDE = re.compile(
    r"\b(?:ignore|disregard|forget|override|bypass|discard|supersede|"
    r"set aside|stop following)\b.{0,80}\b(?:instructions?|rules?|"
    r"polic(?:y|ies)|directives?|guidelines?|system message)\b"
    r"|\bfollow\b.{0,35}\b(?:these|new|different)\b.{0,25}\b"
    r"(?:instructions?|rules?|directives?)\b.{0,20}\binstead\b"
    r"|\bnew\b.{0,25}\b(?:instructions?|rules?)\b.{0,30}\b"
    r"(?:supersede|override|replace|take precedence over)\b.{0,35}\b"
    r"(?:previous|prior|old|existing)\b.{0,25}\b(?:instructions?|rules?)\b"
)

SYSTEM_PROMPT_EXTRACTION = re.compile(
    r"(?:\b(?:reveal|show|print|display|repeat|output|provide|disclose|"
    r"expose|share|tell me|give me|what is|what are)\b.{0,50}\b"
    r"(?:your\s+)?(?:hidden\s+|internal\s+|developer\s+|system\s+)?"
    r"(?:system prompt|hidden prompt|hidden instructions?|system message|"
    r"internal instructions?|developer instructions?|internal prompt)\b"
    r"|\b(?:system prompt|hidden instructions?|internal instructions?|"
    r"developer instructions?)\b.{0,45}\b(?:reveal|show|print|output|"
    r"disclose|expose|repeat)\b)"
)

CREDENTIAL_TERMS = re.compile(
    r"\b(?:api keys?|access tokens?|authentication tokens?|auth tokens?|"
    r"credentials?|database passwords?|passwords?|private keys?|"
    r"environment secrets?|secrets?)\b"
)
API_KEY_TERMS = re.compile(r"\bapi keys?\b")
PASSWORD_TERMS = re.compile(r"\b(?:database )?passwords?\b")
TOKEN_TERMS = re.compile(r"\b(?:access|authentication|auth) tokens?\b")
SECRET_FILE_TERMS = re.compile(
    r"(?:\b(?:company )?(?:credentials?|secrets?|passwords?)\s*\.\s*"
    r"(?:txt|text|json|yaml|yml|env|key|pem)\b|"
    r"(?:^|\s)\.\s*env\b|\b(?:secret|credential|password) files?\b|"
    r"\bprivate keys?\b)"
)
ACCESS_INTENT = re.compile(
    r"\b(?:read|open|get|extract|retrieve|access|steal|dump|print|show|"
    r"reveal|copy|find|locate|list|load|fetch|obtain|expose|search for|"
    r"look up|view|grab)\b"
)

TRANSFER_INTENT = re.compile(
    r"\b(?:send|transmit|exfiltrate|share|forward|"
    r"transfer|publish|export|deliver)\b"
    r"|\b(?:send|transfer|copy)\b.{0,35}\boutside\b"
    r"|\b(?:e?mail)\s+(?:(?:the|this|that|all|these|those|our|their|my|your)\s+)?"
    r"(?:confidential|proprietary|private|sensitive|secret|secrets|"
    r"api keys?|credentials?|access tokens?|authentication tokens?|"
    r"passwords?|database contents?|data|files?|documents?|reports?)\b"
    r"|\bupload\s+(?:(?:the|this|that|all|these|those|our|their|my|your)\s+)?"
    r"(?:it|them|secrets?|confidential|sensitive|private|api keys?|"
    r"credentials?|access tokens?|authentication tokens?|passwords?|"
    r"database contents?|data|files?|documents?|reports?)\b"
    r"|\bpost\s+(?:(?:the|this|that|all|these|those|our|their|my|your)\s+)?"
    r"(?:confidential|proprietary|private|sensitive|secret|secrets|"
    r"api keys?|credentials?|access tokens?|authentication tokens?|"
    r"passwords?|database contents?|data|files?|documents?|reports?)\b"
)
EMAIL_TRANSFER = re.compile(
    r"\b(?:e?mail)\s+(?:(?:the|this|that|all|these|those|our|their|my|your)\s+)?"
    r"(?:confidential|proprietary|private|sensitive|secret|secrets|api keys?|"
    r"credentials?|access tokens?|authentication tokens?|passwords?|"
    r"database contents?|data|files?|documents?|reports?)\b"
)
UPLOAD_TRANSFER = re.compile(
    r"\bupload\s+(?:(?:the|this|that|all|these|those|our|their|my|your)\s+)?"
    r"(?:it|them|secrets?|confidential|sensitive|private|api keys?|"
    r"credentials?|access tokens?|authentication tokens?|passwords?|"
    r"database contents?|data|files?|documents?|reports?)\b"
)
HTTP_TRANSFER = re.compile(
    r"\b(?:post|http|https|url|webhook|external server|external api|"
    r"remote server|external service)\b"
)
SENSITIVE_DATA_TERMS = re.compile(
    r"\b(?:confidential|proprietary|private|sensitive|secret|secrets|"
    r"credentials?|api keys?|access tokens?|authentication tokens?|"
    r"auth tokens?|passwords?|private keys?|environment secrets?|"
    r"company data|database contents?|customer records?|personal data)\b"
    r"|\b(?:company )?(?:secrets?|credentials?|passwords?)\s*\.\s*"
    r"(?:txt|text|json|yaml|yml|env|key|pem)\b"
    r"|(?:^|\s)\.\s*env\b"
)

TOOL_INVOCATION = re.compile(
    r"\b(?:use|invoke|call|run|execute)\b.{0,35}\b(?:email|shell|"
    r"database|file|browser|command|api|http|network)\s+tool\b"
    r"|\b(?:use|invoke|call|run|execute)\b.{0,30}\b(?:tool|function)\b"
)
EXTERNAL_API_REQUEST = re.compile(
    r"\b(?:call|invoke|query|connect to|request|access|make)\b.{0,35}\b"
    r"(?:external|remote)\s+(?:http\s+)?api\b"
    r"|\bcall\b.{0,20}\b(?:this|the)\s+api\b"
)
RESTRICTED_RESOURCE = re.compile(
    r"\b(?:restricted|unauthorized|protected|privileged|off limits|"
    r"outside (?:the )?(?:allowed|permitted|approved))\b.{0,45}\b"
    r"(?:database|records?|files?|directory|folder|resource|system|"
    r"account|path)\b"
    r"|\b(?:database|records?|files?|directory|folder|resource|system|"
    r"account|path)\b.{0,45}\b(?:restricted|unauthorized|protected|"
    r"privileged|off limits)\b"
    r"|\b(?:access|read|open|list|write|search|traverse)\b.{0,35}\b"
    r"(?:files?|folders?|directories|paths?)\b.{0,35}\boutside\b.{0,25}\b"
    r"(?:allowed|permitted|approved)\b"
)
SHELL_EXECUTION_REQUEST = re.compile(
    r"\b(?:use|invoke|run|execute|call)\b.{0,40}\b(?:shell|terminal|"
    r"command line|command prompt)\b"
    r"|\b(?:shell|terminal|command line)\s+tool\b"
)

INSTRUCTION_CONTEXT = re.compile(
    r"\b(?:important\s+ai\s+instruction|ai\s+instruction|"
    r"system\s+(?:message|instruction|directive)|developer\s+"
    r"(?:message|instruction|directive)|administrator\s+instruction|"
    r"trusted\s+administrator|for\s+the\s+ai\s+(?:agent|assistant)|"
    r"to\s+the\s+ai\s+(?:agent|assistant)|for\s+the\s+assistant|"
    r"assistant\s+must)\b"
)

UNTRUSTED_SOURCES = frozenset({"file", "email", "web", "api", "database"})


def detect_indicators(normalized_text: str, source_type: str | None = None) -> set[str]:
    """Return stable indicators found in normalized untrusted text."""
    indicators: set[str] = set()

    override = bool(INSTRUCTION_OVERRIDE.search(normalized_text))
    extraction = bool(SYSTEM_PROMPT_EXTRACTION.search(normalized_text))
    if override:
        indicators.add("instruction_override")
    if extraction:
        indicators.add("system_prompt_extraction")

    has_credential = bool(CREDENTIAL_TERMS.search(normalized_text))
    access_attempt = bool(ACCESS_INTENT.search(normalized_text))
    has_secret_file = bool(SECRET_FILE_TERMS.search(normalized_text))
    has_transfer = bool(TRANSFER_INTENT.search(normalized_text))
    if has_credential and (access_attempt or has_transfer):
        indicators.add("credential_access")
    if API_KEY_TERMS.search(normalized_text) and (access_attempt or has_transfer):
        indicators.add("api_key_access")
    if PASSWORD_TERMS.search(normalized_text) and (access_attempt or has_transfer):
        indicators.add("password_access")
    if TOKEN_TERMS.search(normalized_text) and (access_attempt or has_transfer):
        indicators.add("authentication_token_access")
    if has_secret_file and (access_attempt or has_transfer):
        indicators.add("sensitive_file_access")

    sensitive_data = bool(SENSITIVE_DATA_TERMS.search(normalized_text) or has_secret_file)
    exfiltration = sensitive_data and has_transfer
    if exfiltration:
        indicators.add("external_data_exfiltration")
        if EMAIL_TRANSFER.search(normalized_text):
            indicators.add("email_exfiltration")
        if UPLOAD_TRANSFER.search(normalized_text):
            indicators.add("upload_exfiltration")
        if HTTP_TRANSFER.search(normalized_text):
            indicators.add("http_exfiltration")

    tool_invocation = bool(TOOL_INVOCATION.search(normalized_text))
    external_api = bool(EXTERNAL_API_REQUEST.search(normalized_text))
    restricted_access = bool(RESTRICTED_RESOURCE.search(normalized_text))
    shell_request = bool(SHELL_EXECUTION_REQUEST.search(normalized_text))
    if tool_invocation or shell_request:
        indicators.add("tool_invocation")
    if external_api:
        indicators.add("external_api_request")
    if restricted_access:
        indicators.add("restricted_resource_access")

    contextual_instruction = bool(INSTRUCTION_CONTEXT.search(normalized_text))
    contextual_command = bool(
        re.search(
            r"\b(?:ignore|disregard|override|bypass|reveal|read|access|"
            r"send|email|upload|post|export|execute|run|retrieve|delete)\b",
            normalized_text,
        )
    )
    has_attack_evidence = bool(
        override
        or extraction
        or exfiltration
        or tool_invocation
        or external_api
        or restricted_access
        or shell_request
        or "credential_access" in indicators
        or "sensitive_file_access" in indicators
        or (contextual_instruction and contextual_command)
    )
    source_is_untrusted = (source_type or "").casefold() in UNTRUSTED_SOURCES
    if has_attack_evidence and (contextual_instruction or source_is_untrusted):
        indicators.add("indirect_instruction")
    if has_attack_evidence and contextual_instruction:
        indicators.add("suspicious_instruction_context")

    return indicators

