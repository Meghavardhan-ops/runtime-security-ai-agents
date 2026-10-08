"""Versioned API endpoint for normalized untrusted inputs."""

from fastapi import APIRouter, HTTPException

from backend.gateway.input_gateway import (
    InputGateway,
    InputTooLargeError,
    InputValidationError,
    SecurityInput,
    SecurityInputRequest,
)

router = APIRouter(prefix="/api/v1/inputs", tags=["inputs"])
input_gateway = InputGateway()


@router.post("", response_model=SecurityInput, status_code=201)
def create_input(request: SecurityInputRequest) -> SecurityInput:
    """Return a normalized record; submitted content is never executed."""
    try:
        return input_gateway.normalize(request)
    except InputTooLargeError as error:
        raise HTTPException(status_code=413, detail=str(error)) from error
    except InputValidationError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
