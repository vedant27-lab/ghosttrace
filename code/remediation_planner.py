"""Build ordered findings, remediation, and verification steps."""

from dataclasses import dataclass, asdict
from typing import Any


@dataclass
class PlanStep:
    step_no: int
    phase: str
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


FINDING_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
}

REMEDIATION_ORDER = {
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
}

VERIFICATION_ORDER = {
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}


def _step_key(step: PlanStep):
    order_map = {
        "FINDING": FINDING_ORDER,
        "REMEDIATION": REMEDIATION_ORDER,
        "VERIFICATION": VERIFICATION_ORDER,
    }
    return (
        {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}[step.phase],
        order_map[step.phase].get(step.operation, 999),
        step.system_id,
        step.resource_id,
    )


class RemediationPlanner:
    """Convert policy decisions into the required step schema."""

    def plan(self, decisions, case_id: str | None = None) -> list[PlanStep]:
        findings = []
        remediation = []
        verification = []

        unique = {}
        for decision in decisions:
            key = (
                decision.system_id,
                decision.resource_id,
                decision.data_category,
            )
            current = unique.get(key)
            if current is None or (
                current.decision_status == "REVIEW"
                and decision.decision_status != "REVIEW"
            ):
                unique[key] = decision

        for decision in unique.values():
            if decision.decision_status == "REVIEW":
                continue

            if decision.required_action == "DISABLE":
                findings.append(self._finding(
                    decision, "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"
                ))
                remediation.append(self._remediation(
                    decision, "DISABLE_DATA_FLOW", "DISABLED"
                ))
                verification.append(self._verification(
                    decision, "VERIFY_DATA_FLOW_DISABLED", "DISABLED"
                ))

            elif decision.required_action == "BLOCK_RESTORE":
                findings.append(self._finding(
                    decision, "REPORT_RESTORE_RISK", "ACTIVE"
                ))
                remediation.append(self._remediation(
                    decision, "BLOCK_RESTORE", "BLOCKED"
                ))
                verification.append(self._verification(
                    decision, "VERIFY_RESTORE_BLOCKED", "BLOCKED"
                ))

            elif decision.required_action == "DELETE":
                findings.append(self._finding(
                    decision, "REPORT_REMAINING_RECORD", "PRESENT"
                ))
                remediation.append(self._remediation(
                    decision, "DELETE_RECORD", "ABSENT"
                ))
                verification.append(self._verification(
                    decision, "VERIFY_RECORD_ABSENT", "ABSENT"
                ))

            elif decision.required_action == "REDACT":
                findings.append(self._finding(
                    decision, "REPORT_EXPOSED_PII", "PRESENT"
                ))
                remediation.append(self._remediation(
                    decision, "REDACT_RECORD", "REDACTED"
                ))
                verification.append(self._verification(
                    decision, "VERIFY_RECORD_REDACTED", "REDACTED"
                ))

            elif decision.required_action == "ANONYMIZE":
                findings.append(self._finding(
                    decision, "REPORT_EXPOSED_PII", "PRESENT"
                ))
                remediation.append(self._remediation(
                    decision, "ANONYMIZE_RECORD", "ANONYMIZED"
                ))
                verification.append(self._verification(
                    decision, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
                ))

            elif decision.required_action == "RETAIN":
                continue

        all_steps = findings + remediation + verification
        all_steps.sort(key=_step_key)

        for number, step in enumerate(all_steps, start=1):
            step.step_no = number

        return all_steps

    @staticmethod
    def _finding(decision, operation: str, state: str) -> PlanStep:
        return PlanStep(
            step_no=0,
            phase="FINDING",
            system_id=decision.system_id,
            resource_id=decision.resource_id,
            operation=operation,
            state=state,
            evidence_id=decision.evidence_id,
        )

    @staticmethod
    def _remediation(decision, operation: str, state: str) -> PlanStep:
        return PlanStep(
            step_no=0,
            phase="REMEDIATION",
            system_id=decision.system_id,
            resource_id=decision.resource_id,
            operation=operation,
            state=state,
            evidence_id="",
        )

    @staticmethod
    def _verification(decision, operation: str, state: str) -> PlanStep:
        return PlanStep(
            step_no=0,
            phase="VERIFICATION",
            system_id=decision.system_id,
            resource_id=decision.resource_id,
            operation=operation,
            state=state,
            evidence_id="",
        )


if __name__ == "__main__":
    import csv
    import json
    from pathlib import Path

    from identity_resolver import IdentityResolver
    from policy_engine import PolicyEngine
    from state_reconstructor import reconstruct_case_observations

    root = Path(__file__).resolve().parent.parent
    dataset = root / "dataset"

    with (dataset / "sample_deletion_requests.csv").open(
        "r", encoding="utf-8-sig", newline=""
    ) as handle:
        cases = list(csv.DictReader(handle))

    case = next(row for row in cases if row["case_id"] == "case_30")
    resolver = IdentityResolver.from_dataset(dataset)
    matches = resolver.resolve(case["email"], case["audit_at"])

    if len(matches) != 1:
        raise RuntimeError(
            f"Expected exactly one identity for {case['case_id']}; "
            f"got {len(matches)}"
        )

    observations = reconstruct_case_observations(
        dataset, case, matches[0]
    )
    decisions = PolicyEngine(
        dataset / "deletion_rules.csv"
    ).evaluate(observations)

    steps = RemediationPlanner().plan(decisions, case["case_id"])
    print(json.dumps(
        [step.to_dict() for step in steps],
        indent=2,
    ))
