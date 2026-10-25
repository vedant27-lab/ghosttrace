
import argparse
import csv
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


OUTPUT_COLUMNS = ["case_id", "deletion_status", "steps_json"]
ROOT = Path(__file__).resolve().parent.parent

STEP_FIELDS = {
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
}

VALID_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}

PHASE_ORDER = {
    "FINDING": 0,
    "REMEDIATION": 1,
    "VERIFICATION": 2,
}

VALID_STEP_STATES = {
    ("FINDING", "REPORT_REMAINING_RECORD"): "PRESENT",
    ("FINDING", "REPORT_EXPOSED_PII"): "PRESENT",
    ("FINDING", "REPORT_ACTIVE_DATA_FLOW"): "ACTIVE",
    ("FINDING", "REPORT_RESTORE_RISK"): "ACTIVE",
    ("REMEDIATION", "DISABLE_DATA_FLOW"): "DISABLED",
    ("REMEDIATION", "BLOCK_RESTORE"): "BLOCKED",
    ("REMEDIATION", "DELETE_RECORD"): "ABSENT",
    ("REMEDIATION", "REDACT_RECORD"): "REDACTED",
    ("REMEDIATION", "ANONYMIZE_RECORD"): "ANONYMIZED",
    ("VERIFICATION", "VERIFY_RECORD_ABSENT"): "ABSENT",
    ("VERIFICATION", "VERIFY_RECORD_PRESENT"): "PRESENT",
    ("VERIFICATION", "VERIFY_RECORD_REDACTED"): "REDACTED",
    ("VERIFICATION", "VERIFY_RECORD_ANONYMIZED"): "ANONYMIZED",
    ("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED"): "DISABLED",
    ("VERIFICATION", "VERIFY_RESTORE_BLOCKED"): "BLOCKED",
}

OPERATION_ORDER = {
    "FINDING": [
        "REPORT_REMAINING_RECORD",
        "REPORT_EXPOSED_PII",
        "REPORT_ACTIVE_DATA_FLOW",
        "REPORT_RESTORE_RISK",
    ],
    "REMEDIATION": [
        "DISABLE_DATA_FLOW",
        "BLOCK_RESTORE",
        "DELETE_RECORD",
        "REDACT_RECORD",
        "ANONYMIZE_RECORD",
    ],
    "VERIFICATION": [
        "VERIFY_RECORD_ABSENT",
        "VERIFY_RECORD_PRESENT",
        "VERIFY_RECORD_REDACTED",
        "VERIFY_RECORD_ANONYMIZED",
        "VERIFY_DATA_FLOW_DISABLED",
        "VERIFY_RESTORE_BLOCKED",
    ],
}

OPERATION_RANK = {
    phase: {operation: rank for rank, operation in enumerate(operations)}
    for phase, operations in OPERATION_ORDER.items()
}


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    """Load a UTF-8 CSV and preserve its header order."""
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        headers = reader.fieldnames or []
        rows = list(reader)

    return headers, rows


def parse_timestamp(value: str | None) -> datetime | None:
    """Parse an ISO timestamp and normalize it to UTC."""
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def load_evidence_timestamps(
    manifest_path: Path,
    audit_path: Path,
    activity_path: Path,
) -> tuple[set[str], dict[str, list[tuple[datetime, str]]], list[str]]:
    """Collect recognized evidence IDs and their available timestamps.

    The challenge permits evidence references from manifest file IDs, audit
    IDs, and activity IDs. Some activity schemas may use different timestamp
    column names, so known candidates are checked dynamically.
    """
    evidence_ids: set[str] = set()
    timestamps: dict[str, list[tuple[datetime, str]]] = {}
    warnings: list[str] = []

    def add(evidence_id: str, timestamp_value: str, source: str) -> None:
        evidence_id = (evidence_id or "").strip()
        if not evidence_id:
            return

        evidence_ids.add(evidence_id)
        parsed = parse_timestamp(timestamp_value)

        if parsed is not None:
            timestamps.setdefault(evidence_id, []).append((parsed, source))
        elif timestamp_value:
            warnings.append(
                f"{source}: timestamp could not be parsed for {evidence_id!r}"
            )

    _, manifest_rows = read_csv(manifest_path)
    for row in manifest_rows:
        add(
            row.get("file_id", ""),
            row.get("captured_at", ""),
            "evidence manifest",
        )

    if audit_path.is_file():
        _, audit_rows = read_csv(audit_path)
        for row in audit_rows:
            add(
                row.get("audit_id", ""),
                row.get("event_time", ""),
                "user audit log",
            )

    if activity_path.is_file():
        _, activity_rows = read_csv(activity_path)

        id_columns = (
            "activity_id",
            "event_id",
            "log_id",
        )
        time_columns = (
            "event_time",
            "occurred_at",
            "activity_time",
            "activity_at",
            "timestamp",
            "created_at",
            "recorded_at",
            "logged_at",
        )

        for row in activity_rows:
            evidence_id = next(
                (
                    row.get(column, "").strip()
                    for column in id_columns
                    if row.get(column, "").strip()
                ),
                "",
            )
            timestamp_value = next(
                (
                    row.get(column, "").strip()
                    for column in time_columns
                    if row.get(column, "").strip()
                ),
                "",
            )

            if evidence_id:
                add(evidence_id, timestamp_value, "system activity")

    return evidence_ids, timestamps, warnings


def report_error(errors: list[str], case_id: str, message: str) -> None:
    errors.append(f"{case_id}: {message}")


def validate_steps(
    case_id: str,
    status: str,
    steps: Any,
    audit_at: datetime | None,
    known_evidence_ids: set[str],
    evidence_timestamps: dict[str, list[tuple[datetime, str]]],
    errors: list[str],
) -> None:
    """Validate step fields, states, phase order, citations, and timestamps."""
    if not isinstance(steps, list):
        report_error(errors, case_id, "steps_json must decode to a JSON array.")
        return

    if status == "NOT_APPLICABLE":
        if steps:
            report_error(
                errors,
                case_id,
                "NOT_APPLICABLE requests must have steps_json=[].",
            )
        return

    if status == "COMPLETE":
        if not steps:
            report_error(
                errors,
                case_id,
                "COMPLETE requests require evidence-backed verification steps.",
            )
    elif status == "INCOMPLETE":
        if not steps:
            report_error(
                errors,
                case_id,
                "INCOMPLETE requests require findings and a remediation plan.",
            )

    normalized_steps: list[dict[str, Any]] = []

    for index, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            report_error(
                errors,
                case_id,
                f"Step {index} must be a JSON object.",
            )
            continue

        actual_fields = set(step.keys())
        if actual_fields != STEP_FIELDS:
            missing = sorted(STEP_FIELDS - actual_fields)
            extra = sorted(actual_fields - STEP_FIELDS)
            report_error(
                errors,
                case_id,
                f"Step {index} has incorrect fields; missing={missing}, "
                f"extra={extra}.",
            )

        step_no = step.get("step_no")
        if (
            not isinstance(step_no, int)
            or isinstance(step_no, bool)
            or step_no != index
        ):
            report_error(
                errors,
                case_id,
                f"Step {index} must have integer step_no={index}.",
            )

        for field in STEP_FIELDS - {"step_no"}:
            if not isinstance(step.get(field), str):
                report_error(
                    errors,
                    case_id,
                    f"Step {index}: {field} must be a string.",
                )

        phase = step.get("phase")
        operation = step.get("operation")
        state = step.get("state")
        system_id = step.get("system_id")
        resource_id = step.get("resource_id")
        evidence_id = step.get("evidence_id")

        for field, value in (
            ("phase", phase),
            ("operation", operation),
            ("state", state),
            ("system_id", system_id),
            ("resource_id", resource_id),
        ):
            if isinstance(value, str) and not value.strip():
                report_error(
                    errors,
                    case_id,
                    f"Step {index}: {field} cannot be blank.",
                )

        if phase not in PHASE_ORDER:
            report_error(
                errors,
                case_id,
                f"Step {index}: invalid phase {phase!r}.",
            )
        elif operation not in OPERATION_RANK[phase]:
            report_error(
                errors,
                case_id,
                f"Step {index}: operation {operation!r} is not valid "
                f"for phase {phase!r}.",
            )
        else:
            expected_state = VALID_STEP_STATES.get((phase, operation))
            if state != expected_state:
                report_error(
                    errors,
                    case_id,
                    f"Step {index}: {phase}/{operation} requires state "
                    f"{expected_state!r}, not {state!r}.",
                )

        if status == "COMPLETE":
            if phase != "VERIFICATION":
                report_error(
                    errors,
                    case_id,
                    f"Step {index}: COMPLETE output may contain only "
                    "VERIFICATION steps.",
                )
            if not isinstance(evidence_id, str) or not evidence_id.strip():
                report_error(
                    errors,
                    case_id,
                    f"Step {index}: COMPLETE verification must cite evidence.",
                )
        elif status == "INCOMPLETE":
            if phase == "FINDING":
                if not isinstance(evidence_id, str) or not evidence_id.strip():
                    report_error(
                        errors,
                        case_id,
                        f"Step {index}: FINDING must cite evidence.",
                    )
            elif phase in {"REMEDIATION", "VERIFICATION"}:
                if evidence_id != "":
                    report_error(
                        errors,
                        case_id,
                        f"Step {index}: future {phase} steps must have "
                        "an empty evidence_id.",
                    )

        if isinstance(evidence_id, str) and evidence_id.strip():
            evidence_id = evidence_id.strip()

            if evidence_id not in known_evidence_ids:
                report_error(
                    errors,
                    case_id,
                    f"Step {index}: unknown evidence_id {evidence_id!r}.",
                )
            else:
                refs = evidence_timestamps.get(evidence_id, [])
                if refs and audit_at is not None:
                    after_cutoff = [
                        (timestamp, source)
                        for timestamp, source in refs
                        if timestamp > audit_at
                    ]
                    eligible = [
                        (timestamp, source)
                        for timestamp, source in refs
                        if timestamp <= audit_at
                    ]

                    if not eligible and after_cutoff:
                        later_timestamp, source = min(
                            after_cutoff, key=lambda item: item[0]
                        )
                        report_error(
                            errors,
                            case_id,
                            f"Step {index}: evidence {evidence_id!r} "
                            f"({source}, {later_timestamp.isoformat()}) "
                            f"is after audit_at {audit_at.isoformat()}.",
                        )
                elif not refs:
                    pass

        normalized_steps.append(step)

    phases = [
        step.get("phase")
        for step in normalized_steps
        if step.get("phase") in PHASE_ORDER
    ]
    phase_ranks = [PHASE_ORDER[phase] for phase in phases]

    if phase_ranks != sorted(phase_ranks):
        report_error(
            errors,
            case_id,
            "Phases must be ordered FINDING, REMEDIATION, VERIFICATION.",
        )

    phase_steps: dict[str, list[dict[str, Any]]] = {
        phase: [] for phase in PHASE_ORDER
    }
    for step in normalized_steps:
        phase = step.get("phase")
        if phase in phase_steps:
            phase_steps[phase].append(step)

    for phase, phase_items in phase_steps.items():
        def sort_key(step: dict[str, Any]) -> tuple[int, str, str]:
            operation = step.get("operation", "")
            rank = OPERATION_RANK[phase].get(operation, 999)
            return (
                rank,
                str(step.get("system_id", "")),
                str(step.get("resource_id", "")),
            )

        expected_order = sorted(phase_items, key=sort_key)
        if phase_items != expected_order:
            report_error(
                errors,
                case_id,
                f"{phase} steps are not sorted by operation order, "
                "system_id, then resource_id.",
            )

    seen: set[tuple[str, str, str, str]] = set()
    for step in normalized_steps:
        signature = (
            str(step.get("phase", "")),
            str(step.get("system_id", "")),
            str(step.get("resource_id", "")),
            str(step.get("operation", "")),
        )
        if signature in seen:
            report_error(
                errors,
                case_id,
                f"Duplicate step for phase/system/resource/operation: "
                f"{signature}.",
            )
        seen.add(signature)


def validate_output(
    output_path: Path,
    requests_path: Path,
    manifest_path: Path,
    audit_path: Path,
    activity_path: Path,
) -> tuple[list[str], list[str], dict[str, int]]:
    errors: list[str] = []
    warnings: list[str] = []

    output_headers, output_rows = read_csv(output_path)
    _, request_rows = read_csv(requests_path)

    if output_headers != OUTPUT_COLUMNS:
        errors.append(
            f"Output columns must be exactly {OUTPUT_COLUMNS}; "
            f"found {output_headers}."
        )

    if not request_rows:
        errors.append(f"No request rows found in {requests_path}.")
    if not output_rows:
        errors.append(f"No output rows found in {output_path}.")

    request_ids = [r.get("case_id", "") for r in request_rows]
    output_ids = [r.get("case_id", "") for r in output_rows]

    if any(not value for value in request_ids):
        errors.append("The requests file contains a blank case_id.")
    if any(not value for value in output_ids):
        errors.append("The output file contains a blank case_id.")

    request_counts = Counter(request_ids)
    output_counts = Counter(output_ids)

    for case_id, count in request_counts.items():
        if count != 1:
            errors.append(
                f"Input requests contain {count} rows for case_id {case_id!r}."
            )

    for case_id, count in output_counts.items():
        if count != 1:
            errors.append(
                f"Output contains {count} rows for case_id {case_id!r}."
            )

    missing = sorted(set(request_ids) - set(output_ids))
    unexpected = sorted(set(output_ids) - set(request_ids))

    if missing:
        errors.append(f"Missing output cases ({len(missing)}): {missing[:20]}")
    if unexpected:
        errors.append(
            f"Unexpected output cases ({len(unexpected)}): {unexpected[:20]}"
        )

    if output_ids != sorted(output_ids):
        errors.append("Output rows must be sorted by case_id ascending.")

    request_by_id = {r.get("case_id", ""): r for r in request_rows}
    evidence_ids, evidence_timestamps, evidence_warnings = (
        load_evidence_timestamps(manifest_path, audit_path, activity_path)
    )
    warnings.extend(evidence_warnings)

    status_counts: Counter[str] = Counter()

    for row in output_rows:
        case_id = row.get("case_id", "")
        status = row.get("deletion_status", "")

        if status not in VALID_STATUSES:
            report_error(
                errors,
                case_id or "<blank>",
                f"Invalid deletion_status {status!r}.",
            )
            continue

        status_counts[status] += 1
        request = request_by_id.get(case_id)
        if request is None:
            continue

        audit_at = parse_timestamp(request.get("audit_at", ""))
        if audit_at is None:
            report_error(
                errors,
                case_id,
                f"Invalid or missing audit_at value: "
                f"{request.get('audit_at')!r}.",
            )

        try:
            steps = json.loads(row.get("steps_json", ""))
        except json.JSONDecodeError as exc:
            report_error(
                errors,
                case_id,
                f"steps_json is invalid JSON: {exc.msg} at character "
                f"{exc.pos}.",
            )
            continue

        validate_steps(
            case_id=case_id,
            status=status,
            steps=steps,
            audit_at=audit_at,
            known_evidence_ids=evidence_ids,
            evidence_timestamps=evidence_timestamps,
            errors=errors,
        )

    stats = {
        "requests": len(request_rows),
        "output_rows": len(output_rows),
        "complete": status_counts["COMPLETE"],
        "incomplete": status_counts["INCOMPLETE"],
        "not_applicable": status_counts["NOT_APPLICABLE"],
        "errors": len(errors),
        "warnings": len(warnings),
    }

    return errors, warnings, stats


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate Ghost Data Still Exists output CSV."
    )
    parser.add_argument(
        "--output",
        default=str(ROOT / "output.csv"),
        help="Output CSV to validate (default: repository output.csv).",
    )
    parser.add_argument(
        "--requests",
        default=str(ROOT / "dataset" / "deletion_requests.csv"),
        help="Request CSV corresponding to the output.",
    )
    parser.add_argument(
        "--manifest",
        default=str(ROOT / "dataset" / "evidence_files.csv"),
        help="Evidence manifest CSV.",
    )
    parser.add_argument(
        "--audit-log",
        default=str(ROOT / "dataset" / "user_audit_log.csv"),
        help="Historical identity audit CSV.",
    )
    parser.add_argument(
        "--activity-log",
        default=str(ROOT / "dataset" / "system_activity.csv"),
        help="System activity CSV.",
    )
    args = parser.parse_args()

    try:
        errors, warnings, stats = validate_output(
            output_path=Path(args.output),
            requests_path=Path(args.requests),
            manifest_path=Path(args.manifest),
            audit_path=Path(args.audit_log),
            activity_path=Path(args.activity_log),
        )
    except (FileNotFoundError, OSError, csv.Error) as exc:
        print(f"VALIDATION COULD NOT RUN: {exc}", file=sys.stderr)
        return 2

    print("=== Output Validation Summary ===")
    for key, value in stats.items():
        print(f"{key}: {value}")

    if warnings:
        print("\n=== Warnings ===")
        for warning in warnings[:50]:
            print(f"- {warning}")
        if len(warnings) > 50:
            print(f"- ... and {len(warnings) - 50} additional warnings.")

    if errors:
        print("\n=== Errors ===")
        for error in errors[:100]:
            print(f"- {error}")
        if len(errors) > 100:
            print(f"- ... and {len(errors) - 100} additional errors.")
        print("\nVALIDATION FAILED")
        return 1

    print("\nVALIDATION PASSED")
    if warnings:
        print(
            "Note: warnings indicate evidence timestamps that this validator "
            "could not fully verify."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
