"""Small synthetic fixtures used only when the participant dataset is absent."""

from __future__ import annotations

import json


DEMO_CASES = [
    {
        "case_id": "demo_001",
        "email": "alex@example.test",
        "requested_at": "2026-10-01T09:00:00Z",
        "reported_status": "COMPLETE",
        "reported_at": "2026-10-02T09:00:00Z",
        "audit_at": "2026-10-03T09:00:00Z",
        "request_text": "Please permanently delete my account and personal data.",
    },
    {
        "case_id": "demo_002",
        "email": "sam@example.test",
        "requested_at": "2026-10-04T09:00:00Z",
        "reported_status": "COMPLETE",
        "reported_at": "2026-10-05T09:00:00Z",
        "audit_at": "2026-10-06T09:00:00Z",
        "request_text": "Delete my account and stop any synchronization that can recreate it.",
    },
    {
        "case_id": "demo_003",
        "email": "jordan@example.test",
        "requested_at": "2026-10-07T09:00:00Z",
        "reported_status": "NOT_STARTED",
        "reported_at": "2026-10-08T09:00:00Z",
        "audit_at": "2026-10-09T09:00:00Z",
        "request_text": "Please send me a copy of my account information.",
    },
]


def demo_steps(case_id: str) -> list[dict[str, object]]:
    if case_id == "demo_001":
        return [
            {
                "step_no": 1,
                "phase": "VERIFICATION",
                "system_id": "account_service",
                "resource_id": "account_demo_001",
                "operation": "VERIFY_RECORD_ABSENT",
                "state": "ABSENT",
                "evidence_id": "demo_evidence_001",
            }
        ]
    if case_id == "demo_002":
        return [
            {
                "step_no": 1,
                "phase": "FINDING",
                "system_id": "integration_service",
                "resource_id": "data_flow_demo_002",
                "operation": "REPORT_ACTIVE_DATA_FLOW",
                "state": "ACTIVE",
                "evidence_id": "demo_evidence_002",
            },
            {
                "step_no": 2,
                "phase": "REMEDIATION",
                "system_id": "integration_service",
                "resource_id": "data_flow_demo_002",
                "operation": "DISABLE_DATA_FLOW",
                "state": "DISABLED",
                "evidence_id": "",
            },
            {
                "step_no": 3,
                "phase": "VERIFICATION",
                "system_id": "integration_service",
                "resource_id": "data_flow_demo_002",
                "operation": "VERIFY_DATA_FLOW_DISABLED",
                "state": "DISABLED",
                "evidence_id": "",
            },
        ]
    return []


DEMO_RESULTS = {
    "demo_001": {"deletion_status": "COMPLETE", "steps_json": json.dumps(demo_steps("demo_001"))},
    "demo_002": {"deletion_status": "INCOMPLETE", "steps_json": json.dumps(demo_steps("demo_002"))},
    "demo_003": {"deletion_status": "NOT_APPLICABLE", "steps_json": "[]"},
}


DEMO_EVIDENCE = [
    {
        "evidence_id": "demo_evidence_001",
        "file_type": "json",
        "origin": "synthetic_demo",
        "captured_at": "2026-10-03T08:00:00Z",
        "extraction_method": "synthetic",
        "extraction_error": "",
        "content": '{"resource_id":"account_demo_001","status":"absent","email":"alex@example.test"}',
    },
    {
        "evidence_id": "demo_evidence_002",
        "file_type": "log",
        "origin": "synthetic_demo",
        "captured_at": "2026-10-06T08:00:00Z",
        "extraction_method": "synthetic",
        "extraction_error": "",
        "content": "2026-10-06T08:00:00Z service=integration_service resource_id=data_flow_demo_002 enabled=true customer_email=sam@example.test",
    },
]
