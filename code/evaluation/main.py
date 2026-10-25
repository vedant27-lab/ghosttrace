"""Public-sample and custom regression evaluation.

Run from the repository root with:
    python code/evaluation/main.py

The public sample is used only for evaluation; it is never used to generate the
full-dataset predictions.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "code"))

import main as agent
from evidence_loader import load_all_evidence
from identity_resolver import IdentityResolver


def read_csv(path: Path):
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def norm_steps(raw: str):
    steps = json.loads(raw)
    return [
        tuple(step.get(k) for k in (
            "phase", "system_id", "resource_id", "operation", "state", "evidence_id"
        ))
        for step in steps
    ]


def evaluate_public_sample():
    dataset = ROOT / "dataset"
    requests = read_csv(dataset / "sample_deletion_requests.csv")
    gold = {r["case_id"]: r for r in read_csv(dataset / "sample_output.csv")}
    resolver = IdentityResolver.from_dataset(dataset)
    documents = load_all_evidence(dataset)
    predicted = [agent.process_request(r, resolver, documents) for r in requests]

    status_correct = 0
    exact_rows = 0
    exact_sequences = 0
    field_correct = 0
    field_total = 0
    step_correct = 0
    step_total = 0
    total_gold_steps = 0
    total_pred_steps = 0

    for row in predicted:
        expected = gold[row["case_id"]]
        expected_steps = json.loads(expected["steps_json"])
        predicted_steps = json.loads(row["steps_json"])
        status_correct += row["deletion_status"] == expected["deletion_status"]
        exact_rows += row["deletion_status"] == expected["deletion_status"] and norm_steps(row["steps_json"]) == norm_steps(expected["steps_json"])
        exact_sequences += norm_steps(row["steps_json"]) == norm_steps(expected["steps_json"])
        total_gold_steps += len(expected_steps)
        total_pred_steps += len(predicted_steps)
        for i in range(max(len(expected_steps), len(predicted_steps))):
            es = expected_steps[i] if i < len(expected_steps) else {}
            ps = predicted_steps[i] if i < len(predicted_steps) else {}
            step_total += 1
            if i < len(expected_steps) and i < len(predicted_steps) and norm_steps(json.dumps([ps])) == norm_steps(json.dumps([es])):
                step_correct += 1
            for field in ("phase", "system_id", "resource_id", "operation", "state", "evidence_id"):
                field_total += 1
                field_correct += i < len(expected_steps) and i < len(predicted_steps) and es.get(field) == ps.get(field)

    n = len(requests)
    metrics = {
        "cases": n,
        "status_accuracy": status_correct / n if n else 0,
        "exact_row_accuracy": exact_rows / n if n else 0,
        "exact_sequence_accuracy": exact_sequences / n if n else 0,
        "step_accuracy": step_correct / step_total if step_total else 0,
        "step_field_accuracy": field_correct / field_total if field_total else 0,
        "gold_steps": total_gold_steps,
        "predicted_steps": total_pred_steps,
    }
    return metrics, predicted, gold


def custom_tests():
    from evidence_loader import EvidenceDocument
    import state_reconstructor as recon

    tests = []
    # 1. English deletion request must be in scope.
    tests.append(("English account deletion", agent.is_deletion_request({
        "request_text": "Please permanently delete my account and all personal data."
    }), True))
    # 2. Korean deletion intent must survive Unicode normalization.
    tests.append(("Korean account deletion", agent.is_deletion_request({
        "request_text": "이 이메일 주소에 연결된 계정의 영구 삭제를 요청합니다."
    }), True))
    # 3. Marketing opt-out must not be treated as account deletion.
    tests.append(("Marketing-only opt-out", agent.is_deletion_request({
        "request_text": "Please remove me from marketing lists only. Keep my account active."
    }), False))
    # 4. Data access/export request must not be treated as deletion.
    tests.append(("Data-copy request", agent.is_deletion_request({
        "request_text": "Please send me a copy of my account information."
    }), False))
    # 5. Step sorting respects phase and operation order.
    example = [
        agent._step("VERIFICATION", "search_service", "search_1", "VERIFY_RECORD_ABSENT", "ABSENT"),
        agent._step("FINDING", "search_service", "search_1", "REPORT_REMAINING_RECORD", "PRESENT", "evidence_01"),
        agent._step("REMEDIATION", "integration_service", "data_flow_1", "DISABLE_DATA_FLOW", "DISABLED"),
    ]
    ordered = agent._sort_steps(example, "INCOMPLETE")
    tests.append(("Phase/operation ordering", [x["phase"] for x in ordered] == ["FINDING", "REMEDIATION", "VERIFICATION"], True))

    # 6. A historical email still resolves to its stable subject.
    dataset = ROOT / "dataset"
    resolver = IdentityResolver.from_dataset(dataset)
    sample_requests = read_csv(dataset / "sample_deletion_requests.csv")
    historical_case = next(row for row in sample_requests if row["case_id"] == "case_10")
    historical_matches = resolver.resolve(historical_case["email"], historical_case["audit_at"])
    historical_ok = len(historical_matches) == 1 and historical_matches[0].user_id == "user_10" and any(
        str(source).startswith("historical_audit:") for source in historical_matches[0].matched_by
    )
    tests.append(("Historical email resolution", historical_ok, True))

    # 7. Exact user-ID matching must not confuse user_18 with user_189.
    identity_case = next(row for row in sample_requests if row["case_id"] == "case_30")
    identity = resolver.resolve(identity_case["email"], identity_case["audit_at"])[0]
    ids = recon._identity_values(identity)
    tests.append(("No substring identity collision", recon._match_scalar("user_id", "user_189", ids) is None, True))

    # 8. Evidence captured after audit_at must be ignored.
    future_case = dict(next(row for row in sample_requests if row["case_id"] == "case_01"))
    future_identity = resolver.resolve(future_case["email"], future_case["audit_at"])[0]
    future_case["audit_at"] = "2026-09-03T00:00:00Z"
    future_doc = EvidenceDocument(
        file_id="synthetic_future_evidence",
        path=str(dataset / "future_test.json"),
        origin="custom_test",
        captured_at="2026-09-15T00:00:00Z",
        file_type="json",
        content=json.dumps({
            "account_service": {"records": [{
                "resource_id": "account_99999",
                "email": future_case["email"],
                "observed_at": "2026-09-15T00:00:00Z"
            }]}
        }),
    )
    future_observations = recon.reconstruct_case_observations(
        dataset, future_case, future_identity, documents=[future_doc]
    )
    tests.append(("Post-cutoff evidence excluded", future_observations == [], True))
    return tests


def main():
    metrics, predicted, gold = evaluate_public_sample()
    print("=== Public sample evaluation ===")
    for key, value in metrics.items():
        print(f"{key}: {value:.4f}" if isinstance(value, float) else f"{key}: {value}")
    print("\n=== Custom regression tests ===")
    failed = 0
    tests = custom_tests()
    for name, actual, expected in tests:
        passed = actual == expected
        failed += not passed
        print(f"{'PASS' if passed else 'FAIL'}: {name} (actual={actual!r}, expected={expected!r})")
    print(f"\nCustom tests: {len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
