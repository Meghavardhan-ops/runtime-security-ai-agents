from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(tags=["security"])


class PromptRequest(BaseModel):
    prompt: str


class PromptResponse(BaseModel):
    safe: bool
    risk: str
    reason: str


@router.post("/security/check", response_model=PromptResponse)
def check_prompt(request: PromptRequest):
    prompt = request.prompt.lower()

    suspicious_patterns = [
        "ignore previous instructions",
        "ignore all previous instructions",
        "system prompt",
        "reveal your instructions",
        "bypass security",
        "disable security",
        "send the data",
        "show me the secret",
    ]

    for pattern in suspicious_patterns:
        if pattern in prompt:
            return PromptResponse(
                safe=False,
                risk="high",
                reason=f"Suspicious instruction detected: {pattern}",
            )

    return PromptResponse(
        safe=True,
        risk="low",
        reason="No known prompt-injection pattern detected.",
    )
