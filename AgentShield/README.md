# AgentShield

AgentShield is the backend foundation for an AI-agent runtime security platform. This first step provides a modular FastAPI service, environment-based settings, SQLAlchemy SQLite setup, logging, and a health check. Prompt-injection detection, policy enforcement, agent execution, and a dashboard are not part of this foundation yet.

## Project structure

```text
AgentShield/
├── backend/
│   ├── __init__.py
│   ├── api/
│   │   ├── __init__.py
│   │   └── health.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py
│   │   └── logging_config.py
│   ├── database/
│   │   ├── __init__.py
│   │   └── database.py
│   └── main.py
├── demo_data/
├── docs/
├── tests/
│   └── test_health.py
├── .env.example
├── .gitignore
├── README.md
└── requirements.txt
```

## Requirements

- Python 3.12 or newer

## Setup and run (Windows PowerShell)

Run these commands from the project root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --reload
```

The service listens at `http://127.0.0.1:8000`. Interactive API documentation is available at `http://127.0.0.1:8000/docs`.

## Health check

```http
GET /health
```

Example response:

```json
{
  "status": "healthy",
  "service": "AgentShield"
}
```

## Configuration

Copy `.env.example` to `.env` and adjust values as needed:

- `SERVICE_NAME`: service name returned by the health endpoint.
- `DATABASE_URL`: SQLAlchemy database URL; defaults to a local SQLite file.
- `LOG_LEVEL`: one of `CRITICAL`, `ERROR`, `WARNING`, `INFO`, or `DEBUG`.

The database module exports a SQLAlchemy engine, declarative base, session factory, and `get_db` request dependency for future persistence features.

## Run tests

From the project root:

```powershell
.\.venv\Scripts\python.exe -m pytest
```
