from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "code"))

import main as agent
import state_reconstructor as recon
from evidence_loader import EvidenceDocument
from identity_resolver import IdentityResolver


def test_identity_history_uses_exact_email_matches() -> None:
    resolver = IdentityResolver(
        identities=[
            {
                "user_id": "user_18",
                "name": "A. Example",
                "email": "current@example.test",
                "phone": "+1 202 555 0100",
                "email_hash": "hash18",
                "updated_at": "2026-01-01T00:00:00Z",
            },
            {
                "user_id": "user_189",
                "name": "B. Example",
                "email": "other@example.test",
                "phone": "+1 202 555 0190",
                "email_hash": "hash189",
                "updated_at": "2026-01-01T00:00:00Z",
            },
        ],
        audit_log=[
            {
                "audit_id": "audit_old_18",
                "user_id": "user_18",
                "event_time": "2025-12-01T00:00:00Z",
                "field_name": "email",
                "old_value": "old@example.test",
                "new_value": "current@example.test",
            }
        ],
    )

    matches = resolver.resolve("old@example.test", "2026-02-01T00:00:00Z")

    assert [match.user_id for match in matches] == ["user_18"]
    assert "old@example.test" in matches[0].emails
    assert "historical_audit:audit_old_18" in matches[0].matched_by


def test_future_observation_is_excluded_at_audit_cutoff() -> None:
    identity = {
        "user_id": "user_1",
        "requested_email": "person@example.test",
        "emails": ["person@example.test"],
        "phones": [],
        "email_hashes": [],
        "names": [],
    }
    document = EvidenceDocument(
        file_id="evidence_future",
        path="future.json",
        origin="test",
        captured_at="2026-01-01T00:00:00Z",
        file_type="json",
        content=json.dumps(
            {
                "captured_at": "2026-01-01T00:00:00Z",
                "records": [
                    {
                        "resource_id": "account_1",
                        "email": "person@example.test",
                        "observed_at": "2026-03-01T00:00:00Z",
                    }
                ],
            }
        ),
    )

    observations = recon._json_observations(
        document,
        "case_test",
        recon._utc("2026-02-01T00:00:00Z"),
        recon._identity_values(identity),
    )

    assert observations == []


def test_non_deletion_intent_has_precedence() -> None:
    assert not agent.is_deletion_request(
        {"request_text": "Please unsubscribe me from marketing and keep my account."}
    )
    assert not agent.is_deletion_request(
        {"request_text": "Please send me a copy of my personal data."}
    )
    assert agent.is_deletion_request(
        {"request_text": "Please permanently erase my account and personal data."}
    )


def test_support_attachment_is_deleted_not_redacted() -> None:
    category = recon._category(
        "support_platform",
        "delivery_correction_attachment.pdf",
        {
            "resource_id": "support_1",
            "attachment": True,
            "document_text": "Customer support attachment with contact details",
        },
    )

    assert category == "SUPPORT_ATTACHMENT"


def test_catalog_link_only_does_not_claim_resource_presence() -> None:
    with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
        dataset = Path(temp_dir) / "dataset"
        dataset.mkdir()
        (dataset / "system_activity.csv").write_text(
            "activity_id,event_time,event_type,source_system,target_system,resource_id,reported_result,details\n"
            "activity_1,2026-01-01T00:00:00Z,LINK_RESOURCE_IDENTITY,data_catalog,object_storage,object_1,SUCCESS,Linked object_1 to person@example.test and user_1.\n",
            encoding="utf-8",
        )
        case = {"case_id": "case_test", "audit_at": "2026-01-02T00:00:00Z"}
        identity = {
            "user_id": "user_1",
            "requested_email": "person@example.test",
            "emails": ["person@example.test"],
            "phones": [],
            "email_hashes": [],
            "names": [],
        }

        observations = recon.reconstruct_case_observations(dataset, case, identity, documents=[])

        assert observations == []


def test_tombstone_state_requires_direct_identifier_redaction() -> None:
    clean = {
        "resource_id": "tombstone_1",
        "account_status": "DELETED",
        "name": None,
        "email": None,
        "phone": None,
        "email_hash": None,
    }
    exposed = {**clean, "email": "person@example.test"}

    assert recon._state("identity_service", "ACCOUNT_TOMBSTONE", clean, []) == "REDACTED"
    assert recon._state("identity_service", "ACCOUNT_TOMBSTONE", exposed, []) == "PRESENT"


def test_malformed_json_is_fail_closed() -> None:
    document = EvidenceDocument(
        file_id="evidence_bad",
        path="bad.json",
        origin="test",
        captured_at="2026-01-01T00:00:00Z",
        file_type="json",
        content="{not valid json",
    )

    assert recon._json_observations(
        document,
        "case_test",
        recon._utc("2026-01-02T00:00:00Z"),
        {"email": {"person@example.test"}},
    ) == []


def test_step_numbering_and_future_evidence_contract() -> None:
    steps = [
        agent._step("VERIFICATION", "account_service", "account_1", "VERIFY_RECORD_ABSENT", "ABSENT", "evidence_1"),
        agent._step("FINDING", "search_service", "search_1", "REPORT_REMAINING_RECORD", "PRESENT", "evidence_2"),
    ]

    ordered = agent._sort_steps(steps, "INCOMPLETE")

    assert [step["step_no"] for step in ordered] == [1, 2]
    assert [step["phase"] for step in ordered] == ["FINDING", "VERIFICATION"]
    assert ordered[-1]["evidence_id"] == ""
