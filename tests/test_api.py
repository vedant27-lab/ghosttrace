from __future__ import annotations

import time

from fastapi.testclient import TestClient

from backend.main import create_app
from backend.services import AuditRepository


def client() -> TestClient:
    return TestClient(create_app(AuditRepository(force_demo=True)))


def test_health_and_summary_expose_demo_mode() -> None:
    with client() as api:
        health = api.get("/api/health")
        summary = api.get("/api/summary")

    assert health.status_code == 200
    assert health.json()["mode"] == "demo"
    assert summary.json()["total_requests"] == 3
    assert summary.json()["demo"] is True


def test_case_listing_filters_and_case_detail() -> None:
    with client() as api:
        listing = api.get("/api/cases", params={"status": "INCOMPLETE", "page_size": 10})
        detail = api.get("/api/cases/demo_002")
        missing = api.get("/api/cases/not-a-real-case")

    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    assert listing.json()["items"][0]["case_id"] == "demo_002"
    assert detail.status_code == 200
    assert detail.json()["steps"][0]["operation"] == "REPORT_ACTIVE_DATA_FLOW"
    assert missing.status_code == 404


def test_evidence_search_returns_sanitized_excerpt() -> None:
    with client() as api:
        listing = api.get("/api/evidence", params={"search": "data_flow_demo_002"})
        detail = api.get("/api/evidence/demo_evidence_002")

    assert listing.status_code == 200
    assert listing.json()["items"][0]["evidence_id"] == "demo_evidence_002"
    assert detail.status_code == 200
    assert "sam@example.test" not in detail.json()["excerpt"]
    assert "[email]" in detail.json()["excerpt"]


def test_audit_job_is_single_flight_and_downloadable() -> None:
    with client() as api:
        first = api.post("/api/audits")
        assert first.status_code == 202
        second = api.post("/api/audits")
        assert second.status_code in {202, 409}
        job_id = first.json()["job_id"]
        for _ in range(20):
            current = api.get(f"/api/audits/{job_id}").json()
            if current["status"] == "completed":
                break
            time.sleep(0.02)
        download = api.get(f"/api/audits/{job_id}/download")

    assert current["status"] == "completed"
    assert download.status_code == 200
    assert "case_id,deletion_status,steps_json" in download.text
