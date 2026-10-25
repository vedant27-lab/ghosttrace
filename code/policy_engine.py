"""Apply deletion policy rules to reconstructed evidence observations."""

import csv
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any


VALID_ACTIONS = {"DELETE", "REDACT", "ANONYMIZE", "RETAIN"}

SYSTEM_CATEGORY_MAP = {
    "account_service": "USER_PROFILE",
    "identity_service": "SECONDARY_IDENTIFIER",
    "search_service": "SEARCH_INDEX_ENTRY",
    "cache_service": "CACHE_ENTRY",
    "support_platform": "SUPPORT_MESSAGE",
    "analytics_platform": "ANALYTICS_PROFILE",
    "marketing_platform": "MARKETING_PROFILE",
    "export_service": "USER_EXPORT",
    "object_storage": "SUPPORT_ATTACHMENT",
    "security_service": "SECURITY_AUDIT_LOG",
}


@dataclass
class PolicyDecision:
    case_id: str
    evidence_id: str
    system_id: str
    resource_id: str
    data_category: str
    required_action: str
    condition: str
    decision_status: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PolicyEngine:
    """Load supplied rules and evaluate reconstructed observations."""

    def __init__(self, rules_path: str | Path):
        self.rules_path = Path(rules_path)
        self.rules = self._load_rules(self.rules_path)

    @staticmethod
    def _load_rules(path: Path) -> dict[str, dict[str, str]]:
        if not path.is_file():
            raise FileNotFoundError(f"Rules file not found: {path}")

        required_columns = {
            "rule_id", "data_category", "condition", "required_action"
        }
        rules = {}

        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames or not required_columns.issubset(
                reader.fieldnames
            ):
                raise ValueError(
                    f"Rules CSV must contain columns: "
                    f"{sorted(required_columns)}"
                )

            for row in reader:
                category = row["data_category"].strip().upper()
                action = row["required_action"].strip().upper()

                if not category or action not in VALID_ACTIONS:
                    raise ValueError(f"Invalid policy row: {row}")
                if category in rules:
                    raise ValueError(f"Duplicate policy category: {category}")

                rules[category] = {
                    "rule_id": row["rule_id"].strip(),
                    "condition": row["condition"].strip(),
                    "required_action": action,
                }

        return rules

    @staticmethod
    def _record_text(record: dict[str, Any]) -> str:
        return str(record).casefold()

    def _infer_category(self, observation) -> str:
        system = observation.system_id.casefold()
        path = observation.json_path.casefold()
        record = observation.record or {}

        if system == "integration_service":
            return "DATA_FLOW"
        if system == "support_platform":
            if "attachment" in path or "attachment" in str(
                record.get("resource_type", "")
            ).casefold():
                return "SUPPORT_ATTACHMENT"
            return "SUPPORT_MESSAGE"
        if system == "security_service":
            text = self._record_text(record)
            if "legal_hold" in path or "legal hold" in text:
                return "LEGAL_HOLD_RECORD"
            if "tombstone" in path or "tombstone" in text:
                return "ACCOUNT_TOMBSTONE"
            return "SECURITY_AUDIT_LOG"
        if system == "object_storage":
            if "backup" in path or "archive" in path:
                return "BACKUP_ARCHIVE"
            return "SUPPORT_ATTACHMENT"

        if "telemetry" in path:
            return "PRODUCT_TELEMETRY"
        if "delivery" in path and "email" in path:
            return "EMAIL_DELIVERY_LOG"
        if "tombstone" in path:
            return "ACCOUNT_TOMBSTONE"
        if "backup" in path or "archive" in path:
            return "BACKUP_ARCHIVE"

        return SYSTEM_CATEGORY_MAP.get(system, "UNKNOWN")

    def _condition_met(self, category: str, condition: str, observation):
        if condition.casefold() == "always":
            return True, "The supplied rule applies unconditionally."

        record = observation.record or {}
        text = self._record_text(record)

        if category == "ANALYTICS_PROFILE":
            attributable = any(
                value not in (None, "")
                for key, value in record.items()
                if key.casefold() in {
                    "email", "email_hash", "phone", "user_id",
                    "customer_reference", "customer_email"
                }
            )
            return attributable, (
                "Personal identifiers remain in the observed record."
                if attributable else
                "The available record does not establish attribution."
            )

        if category == "PRODUCT_TELEMETRY":
            attributable = any(
                key.casefold() in {
                    "email", "email_hash", "phone", "user_id",
                    "customer_reference"
                } and value not in (None, "")
                for key, value in record.items()
            )
            return attributable, (
                "Identifiers indicate the telemetry may remain attributable."
                if attributable else
                "The available record does not establish attribution."
            )

        if category == "SUPPORT_MESSAGE":
            has_context = any(
                record.get(key) not in (None, "")
                for key in ("message_excerpt", "message", "body", "content")
            )
            return has_context, (
                "Message context is present; redact personal details while "
                "preserving necessary conversation context."
                if has_context else
                "Shared conversation context is not established by this record."
            )

        if category == "SUPPORT_ATTACHMENT":
            return False, (
                "The evidence does not establish that the attachment belongs "
                "only to the deletion subject."
            )

        if category == "EMAIL_DELIVERY_LOG":
            contains_email = any(
                "email" in key.casefold() and value not in (None, "")
                for key, value in record.items()
            )
            return contains_email, (
                "An email field is present in the delivery-log record."
                if contains_email else
                "No email field was identified in this record."
            )

        if category == "SECURITY_AUDIT_LOG":
            return False, (
                "The supplied record does not yet establish whether it falls "
                "within the required retention period."
            )

        if category == "LEGAL_HOLD_RECORD":
            active = any(
                record.get(key) is True
                for key in ("active", "is_active", "legal_hold_active")
            )
            return active, (
                "An active legal hold is explicitly indicated."
                if active else
                "An active legal hold has not been established."
            )

        if category == "BACKUP_ARCHIVE":
            return False, (
                "Whether restore access can be blocked must be established "
                "from additional evidence."
            )

        if category == "ACCOUNT_TOMBSTONE":
            return False, (
                "The evidence does not yet establish that the account is "
                "deleted and only a stable internal identifier remains."
            )

        return False, (
            f"The condition '{condition}' requires evidence that this "
            "observation does not establish."
        )

    def evaluate_observation(self, observation) -> PolicyDecision:
        category = self._infer_category(observation)

        if category == "DATA_FLOW":
            active = observation.observed_state == "ACTIVE"
            return PolicyDecision(
                case_id=observation.case_id,
                evidence_id=observation.evidence_id,
                system_id=observation.system_id,
                resource_id=observation.resource_id,
                data_category=category,
                required_action="DISABLE" if active else "NONE",
                condition="Disable an active flow that could recreate data",
                decision_status="ACTION_REQUIRED" if active else "REVIEW",
                reason=(
                    "The observed connector is active and may recreate data."
                    if active else
                    "The observation does not establish an active data flow."
                ),
            )

        rule = self.rules.get(category)
        if rule is None:
            return PolicyDecision(
                case_id=observation.case_id,
                evidence_id=observation.evidence_id,
                system_id=observation.system_id,
                resource_id=observation.resource_id,
                data_category=category,
                required_action="NONE",
                condition="No matching supplied rule",
                decision_status="REVIEW",
                reason="The resource category could not be matched to a policy.",
            )

        met, reason = self._condition_met(
            category, rule["condition"], observation
        )

        if not met:
            status = "REVIEW"
            action = "NONE"
        elif observation.observed_state == "PRESENT":
            action = rule["required_action"]
            status = "ACTION_REQUIRED" if action != "RETAIN" else "RETAIN"
        elif observation.observed_state == "ACTIVE":
            action = rule["required_action"]
            status = "ACTION_REQUIRED" if action != "RETAIN" else "RETAIN"
        else:
            action = "NONE"
            status = "REVIEW"
            reason += " The observed state does not establish that action is needed."

        return PolicyDecision(
            case_id=observation.case_id,
            evidence_id=observation.evidence_id,
            system_id=observation.system_id,
            resource_id=observation.resource_id,
            data_category=category,
            required_action=action,
            condition=rule["condition"],
            decision_status=status,
            reason=reason,
        )

    def evaluate(self, observations) -> list[PolicyDecision]:
        """Evaluate observations and deduplicate repeated views of one resource."""
        decisions = {}
        for observation in observations:
            decision = self.evaluate_observation(observation)
            key = (
                decision.case_id,
                decision.system_id,
                decision.resource_id,
                decision.data_category,
            )
            existing = decisions.get(key)

            if existing is None or (
                existing.decision_status == "REVIEW"
                and decision.decision_status != "REVIEW"
            ):
                decisions[key] = decision

        return sorted(
            decisions.values(),
            key=lambda item: (
                item.system_id, item.resource_id, item.data_category
            ),
        )


if __name__ == "__main__":
    import sys
    from pathlib import Path
    from evidence_loader import load_all_evidence
    from identity_resolver import IdentityResolver
    from state_reconstructor import reconstruct_case_observations

    root = Path(__file__).resolve().parent.parent
    dataset = root / "dataset"

    requests = list(csv.DictReader(
        (dataset / "sample_deletion_requests.csv").open(
            "r", encoding="utf-8-sig", newline=""
        )
    ))
    case = next(row for row in requests if row["case_id"] == "case_30")

    resolver = IdentityResolver.from_dataset(dataset)
    matches = resolver.resolve(case["email"], case["audit_at"])
    if len(matches) != 1:
        sys.exit(f"Expected one identity match, got {len(matches)}")

    observations = reconstruct_case_observations(dataset, case, matches[0])
    engine = PolicyEngine(dataset / "deletion_rules.csv")
    for decision in engine.evaluate(observations):
        print(decision.to_dict())
