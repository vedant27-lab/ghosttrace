from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, HTTPException, Path as ApiPath, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

from .models import (
    AuditJob,
    AuditRunRequest,
    CaseDetail,
    CasePage,
    DeletionStatus,
    EvidenceDetail,
    EvidencePage,
    SummaryResponse,
)
from .services import AuditJobManager, AuditRepository


class SimpleRateLimiter:
    def __init__(self, limit: int = 120, window_seconds: int = 60):
        self.limit = limit
        self.window_seconds = window_seconds
        self._requests: dict[str, deque[float]] = defaultdict(deque)

    def allowed(self, key: str) -> bool:
        now = time.monotonic()
        bucket = self._requests[key]
        while bucket and now - bucket[0] > self.window_seconds:
            bucket.popleft()
        if len(bucket) >= self.limit:
            return False
        bucket.append(now)
        return True


def create_app(repository: AuditRepository | None = None) -> FastAPI:
    repo = repository or AuditRepository(os.getenv("GHOSTTRACE_ROOT", Path(__file__).resolve().parents[1]))
    jobs = AuditJobManager(repo)
    limiter = SimpleRateLimiter()
    allowed_origins = [
        origin.strip()
        for origin in os.getenv(
            "GHOSTTRACE_ALLOWED_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173",
        ).split(",")
        if origin.strip()
    ]

    app = FastAPI(
        title="GhostTrace API",
        version="1.0.0",
        description="Evidence-based privacy deletion audit and exploration API.",
    )
    app.state.repository = repo
    app.state.jobs = jobs
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Content-Type"],
    )

    @app.middleware("http")
    async def request_safety(request: Request, call_next):
        if request.url.path.startswith("/api"):
            client = request.client.host if request.client else "unknown"
            if not limiter.allowed(client):
                return JSONResponse({"detail": "Rate limit exceeded"}, status_code=429)
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    too_large = int(content_length) > 1_000_000
                except ValueError:
                    return JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)
                if too_large:
                    return JSONResponse({"detail": "Request body too large"}, status_code=413)
        return await call_next(request)

    @app.get("/api/health")
    def health() -> dict[str, object]:
        return {
            "status": "ok",
            "service": "ghosttrace-api",
            "mode": "demo" if repo.demo else "dataset",
            "dataset_available": repo.dataset_available,
            "cases": repo.total_cases,
        }

    @app.get("/api/summary", response_model=SummaryResponse)
    def summary() -> SummaryResponse:
        return repo.summary()

    @app.get("/api/cases", response_model=CasePage)
    def cases(
        status_filter: DeletionStatus | None = Query(default=None, alias="status"),
        q: str | None = Query(default=None, min_length=1, max_length=120),
        case_id: str | None = Query(default=None, min_length=1, max_length=128),
        requested_from: str | None = Query(default=None, max_length=40),
        requested_to: str | None = Query(default=None, max_length=40),
        page: int = Query(default=1, ge=1, le=100_000),
        page_size: int = Query(default=25, ge=1, le=100),
    ) -> CasePage:
        try:
            return CasePage(**repo.list_cases(status_filter.value if status_filter else None, q, case_id, requested_from, requested_to, page, page_size))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/cases/{case_id}", response_model=CaseDetail)
    def case_detail(case_id: str = ApiPath(..., min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")) -> CaseDetail:
        detail = repo.case_detail(case_id)
        if detail is None:
            raise HTTPException(status_code=404, detail="Case not found")
        return detail

    @app.get("/api/evidence", response_model=EvidencePage)
    def evidence(
        search: str | None = Query(default=None, min_length=1, max_length=120),
        file_type: str | None = Query(default=None, min_length=1, max_length=12),
        page: int = Query(default=1, ge=1, le=100_000),
        page_size: int = Query(default=25, ge=1, le=100),
    ) -> EvidencePage:
        return repo.list_evidence(search, file_type, page, page_size)

    @app.get("/api/evidence/{evidence_id}", response_model=EvidenceDetail)
    def evidence_detail(evidence_id: str = ApiPath(..., min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_-]+$")) -> EvidenceDetail:
        detail = repo.evidence_detail(evidence_id)
        if detail is None:
            raise HTTPException(status_code=404, detail="Evidence not found")
        return detail

    @app.post("/api/audits", response_model=AuditJob, status_code=status.HTTP_202_ACCEPTED)
    def start_audit(_: AuditRunRequest = AuditRunRequest()) -> AuditJob:
        try:
            return jobs.start().to_model()
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/api/audits/{job_id}", response_model=AuditJob)
    def audit_status(job_id: str = ApiPath(..., min_length=8, max_length=64, pattern=r"^[a-f0-9]+$")) -> AuditJob:
        record = jobs.get(job_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Audit job not found")
        return record.to_model()

    @app.delete("/api/audits/{job_id}", response_model=AuditJob)
    def cancel_audit(job_id: str = ApiPath(..., min_length=8, max_length=64, pattern=r"^[a-f0-9]+$")) -> AuditJob:
        record = jobs.cancel(job_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Audit job not found")
        return record.to_model()

    @app.get("/api/audits/{job_id}/download")
    def download_audit(job_id: str = ApiPath(..., min_length=8, max_length=64, pattern=r"^[a-f0-9]+$")):
        record = jobs.get(job_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Audit job not found")
        if record.status != "completed":
            raise HTTPException(status_code=409, detail="Audit is not complete")
        path, content = repo.download_csv()
        if record.output_path:
            path = Path(record.output_path)
        if path is not None:
            safe_path = path.resolve()
            if not safe_path.is_relative_to(repo.root) or not safe_path.is_file():
                raise HTTPException(status_code=404, detail="Audit output is unavailable")
            return FileResponse(safe_path, media_type="text/csv", filename="ghosttrace-output.csv")
        return StreamingResponse(
            iter([content]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=ghosttrace-demo-output.csv"},
        )

    @app.get("/")
    def root() -> dict[str, str]:
        return {"service": "GhostTrace API", "docs": "/docs", "health": "/api/health"}

    return app


app = create_app()
