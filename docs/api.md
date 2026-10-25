# GhostTrace API

The FastAPI service is started from the repository root with:

```powershell
python -m uvicorn backend.main:app --reload --port 8000
```

Interactive OpenAPI documentation is available at `http://localhost:8000/docs`.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/health` | Service and dataset mode check |
| `GET` | `/api/summary` | Live status counts and evidence count |
| `GET` | `/api/cases` | Paginated, searchable, status-filtered case summaries |
| `GET` | `/api/cases/{case_id}` | Sanitized case detail, observations, steps, and references |
| `GET` | `/api/evidence` | Manifest browsing and extracted-text search |
| `GET` | `/api/evidence/{evidence_id}` | Sanitized excerpt and provenance |
| `POST` | `/api/audits` | Start one background audit job |
| `GET` | `/api/audits/{job_id}` | Poll job progress and result counts |
| `DELETE` | `/api/audits/{job_id}` | Request cancellation between case evaluations |
| `GET` | `/api/audits/{job_id}/download` | Download completed `output.csv` |

Example requests:

```powershell
Invoke-RestMethod http://localhost:8000/api/summary
Invoke-RestMethod 'http://localhost:8000/api/cases?status=INCOMPLETE&page=1&page_size=10'
Invoke-RestMethod -Method Post http://localhost:8000/api/audits
```

The response schema is generated from Pydantic models in `backend/models.py`. Evidence responses expose allowlisted IDs, origin metadata, and sanitized excerpts. They do not expose arbitrary local paths or raw file uploads.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `GHOSTTRACE_ROOT` | Repository root | Dataset/output root for the backend |
| `GHOSTTRACE_ALLOWED_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Explicit frontend CORS origins |

No credentials are required for the local application. Do not add secrets to these values or commit `.env` files.
