"""Deterministic deletion-audit pipeline for Ghost Data Still Exists.

Run from any working directory:
    python code/main.py

Evidence is loaded once, each request is evaluated at its audit cutoff, and the
root-level output.csv is written with the challenge's exact schema.
"""
from __future__ import annotations

import csv
import json
import re
import sys
import unicodedata
from pathlib import Path
from typing import Any

from evidence_loader import load_all_evidence
from identity_resolver import IdentityResolver, parse_timestamp
from state_reconstructor import StateObservation, reconstruct_case_observations

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "dataset"
OUTPUT_PATH = ROOT / "output.csv"
OUTPUT_COLUMNS = ["case_id", "deletion_status", "steps_json"]

PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
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
ACTION_STEPS = {
    "DISABLE": ("REPORT_ACTIVE_DATA_FLOW", "ACTIVE", "DISABLE_DATA_FLOW", "DISABLED", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
    "BLOCK_RESTORE": ("REPORT_RESTORE_RISK", "ACTIVE", "BLOCK_RESTORE", "BLOCKED", "VERIFY_RESTORE_BLOCKED", "BLOCKED"),
    "DELETE": ("REPORT_REMAINING_RECORD", "PRESENT", "DELETE_RECORD", "ABSENT", "VERIFY_RECORD_ABSENT", "ABSENT"),
    "REDACT": ("REPORT_EXPOSED_PII", "PRESENT", "REDACT_RECORD", "REDACTED", "VERIFY_RECORD_REDACTED", "REDACTED"),
    "ANONYMIZE": ("REPORT_EXPOSED_PII", "PRESENT", "ANONYMIZE_RECORD", "ANONYMIZED", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
}
PII_FIELDS = {
    "email", "customer_email", "requester_email", "owner_email", "email_address",
    "phone", "customer_phone", "requester_phone", "owner_phone", "email_hash",
    "name", "full_name", "requester_name", "display_name",
}
LINK_FIELDS = {"user_id", "customer_reference", "subject_reference"}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def _normalise_text(value: str) -> str:
    text = unicodedata.normalize("NFKD", str(value or "").casefold())
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return re.sub(r"\s+", " ", text).strip()


def is_deletion_request(request: dict[str, str]) -> bool:
    """Recognize deletion intent while prioritizing explicit non-deletion requests."""
    raw_text = str(request.get("request_text", "") or "").casefold()
    text = _normalise_text(raw_text)
    # Keep the original Unicode text as well: NFKD decomposes Hangul syllables.
    text = text + " " + raw_text

    non_deletion_patterns = (
        r"\b(?:not|never) (?:asking for |requesting )?(?:a )?(?:data )?delet(?:ion|e)\b",
        r"\bnot a request to (?:erase|delete|remove)\b",
        r"\b(?:do not|don't|dont|please do not) (?:delete|erase|remove|close)\b",
        r"\bno estoy solicitando (?:la )?(?:eliminacion|supresion)\b",
        r"\bnao estou pedindo (?:a )?exclusao\b",
        r"\bne demande pas la suppression\b",
        r"\bnot asking for dele(?:tion|ting)\b",
        r"\b(?:access|subject access|data access|information) request\b",
        r"\b(?:correct|correction|rectify|update|change|fix|amend) (?:my |the )?(?:personal )?(?:data|details|information|email|surname|address)\b",
        r"\b(?:download|get|send|provide|request) (?:me )?(?:a copy(?: of)?|my account information|last year's invoices)\b",
        r"\b(?:marketing opt[- ]?out|opt[- ]?out of marketing|unsubscribe|stop (?:sending me )?marketing|remove me from marketing)\b",
        r"\b(?:reset|recover) (?:my )?(?:login|password|access)\b",
        r"\b(?:please )?(?:leave|keep) (?:my )?(?:account|profile|purchase history|records) (?:as it is|in place|unchanged)\b",
        r"\bmy account is still active and i want to keep it\b",
        r"\b(?:don't|dont|do not|never) want (?:my )?(?:account|profile|data|records) (?:deleted|removed|erased)\b",
    )
    if any(re.search(pattern, text) for pattern in non_deletion_patterns):
        return False

    deletion_patterns = (
        r"\bdelet(?:e|ion|ing|ed)\b", r"\bdeletion\b",
        r"\beras(?:e|ure|ing|ed)\b", r"\bclose (?:my|this|the) account\b",
        r"\bremove (?:my|this|the) account\b", r"\bremove my personal (?:data|information)\b",
        r"\bright to be forgotten\b", r"\bright to erasure\b",
        r"\bremove\b", r"\bremoved\b", r"\bremoval\b",
        r"\bprofile (?:still )?(?:appears|exists|is gone|was removed)\b",
        r"\baccount (?:and|or) identifiable (?:analytics )?data (?:have been )?removed\b",
        r"\bremaining records cannot identify me\b",
        r"\bclean (?:my )?(?:personal )?(?:details|data|information) out\b",
        r"\bclose it\b", r"\bclosed\b", r"\bclose the account completely\b",
        r"\b(?:account|profile|records|copies) (?:have been |were |already )?(?:deleted|removed|erased|gone)\b",
        r"\bpermanent(?:ly)? account deletion\b", r"\bpersonal[- ]data deletion\b",
        # Spanish
        r"\b(?:eliminacion|eliminar|elimine|borrar|borrado|supresion|suprimir)\b",
        r"\bdar de baja (?:mi )?(?:cuenta|perfil)\b",
        # French
        r"\b(?:suppression|supprimer|effacer|effacement|resilier mon compte|cloturer mon compte)\b",
        # Portuguese
        r"\b(?:exclusao|excluir|apagar|eliminacao|eliminar)\b",
        # Italian and German
        r"\b(?:cancellazione|cancellare|eliminazione|eliminare|loschen|löschung|konto loschen)\b",
        # Dutch
        r"\b(?:verwijderen|verwijdering)\b",
        # Korean, Japanese, and Chinese
        r"삭제", r"アカウント削除", r"削除", r"删除", r"刪除",
    )
    return any(re.search(pattern, text) for pattern in deletion_patterns)


def _direct_pii(record: dict[str, Any]) -> bool:
    for key, value in record.items():
        if str(key).casefold() in PII_FIELDS and value not in (None, "", "null", "NULL"):
            return True
    return False


def _attributable(record: dict[str, Any]) -> bool:
    if _direct_pii(record):
        return True
    for key, value in record.items():
        if str(key).casefold() in LINK_FIELDS and value not in (None, "", "null", "NULL"):
            return True
    return False


def _action_for(obs: StateObservation) -> str | None:
    category, state = obs.data_category, obs.observed_state
    record = obs.record or {}

    if category == "DATA_FLOW":
        return "DISABLE" if state == "ACTIVE" else None
    if category == "BACKUP_ARCHIVE":
        # An archive is a restore path unless evidence explicitly proves access
        # is already blocked or the archive is absent.
        return "BLOCK_RESTORE" if state in {"ACTIVE", "PRESENT"} else None
    if category in {
        "USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY",
        "CACHE_ENTRY", "SUPPORT_ATTACHMENT", "USER_EXPORT", "MARKETING_PROFILE",
    }:
        return "DELETE" if state == "PRESENT" else None
    linked_to_subject = bool(obs.matched_identifiers)
    if category == "SUPPORT_MESSAGE":
        return "REDACT" if state == "PRESENT" and (_attributable(record) or linked_to_subject) else None
    if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        return "ANONYMIZE" if state == "PRESENT" and (_attributable(record) or linked_to_subject) else None
    if category == "EMAIL_DELIVERY_LOG":
        contains_email = any("email" in str(k).casefold() and v not in (None, "", "null", "NULL") for k, v in record.items())
        return "REDACT" if state == "PRESENT" and contains_email else None
    if category == "ACCOUNT_TOMBSTONE":
        if state == "PRESENT" and _direct_pii(record):
            return "REDACT"
        return None
    if category == "LEGAL_HOLD_RECORD":
        active = any(record.get(k) is True or str(record.get(k, "")).casefold() == "true" for k in ("active", "is_active", "legal_hold_active"))
        return None if active else ("DELETE" if state == "PRESENT" else None)
    # Security audit records are retained by the supplied rule. The observed
    # record itself is still a required verification target.
    return None


def _verification_for(obs: StateObservation) -> tuple[str, str] | None:
    category, state = obs.data_category, obs.observed_state
    if state == "ABSENT" and category in {"USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY", "SUPPORT_ATTACHMENT", "USER_EXPORT", "MARKETING_PROFILE"}:
        return "VERIFY_RECORD_ABSENT", "ABSENT"
    if category in {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"} and state == "PRESENT":
        return "VERIFY_RECORD_PRESENT", "PRESENT"
    if category == "ACCOUNT_TOMBSTONE" and state == "REDACTED":
        return "VERIFY_RECORD_REDACTED", "REDACTED"
    if category == "SUPPORT_MESSAGE" and state == "REDACTED":
        return "VERIFY_RECORD_REDACTED", "REDACTED"
    if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"} and state == "ANONYMIZED":
        return "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
    if category == "DATA_FLOW" and state == "DISABLED":
        return "VERIFY_DATA_FLOW_DISABLED", "DISABLED"
    if category == "BACKUP_ARCHIVE" and state == "BLOCKED":
        return "VERIFY_RESTORE_BLOCKED", "BLOCKED"
    if category == "EMAIL_DELIVERY_LOG" and state == "REDACTED":
        return "VERIFY_RECORD_REDACTED", "REDACTED"
    return None


def _collapse_observations(observations: list[StateObservation]) -> list[StateObservation]:
    severity = {"UNKNOWN": 0, "ABSENT": 1, "REDACTED": 2, "ANONYMIZED": 3, "PRESENT": 4, "DISABLED": 4, "BLOCKED": 4, "ACTIVE": 5}
    grouped: dict[tuple[str, str, str], StateObservation] = {}
    for obs in observations:
        key = (obs.system_id, obs.resource_id, obs.data_category)
        old = grouped.get(key)
        new_time = parse_timestamp(obs.observed_at)
        old_time = parse_timestamp(old.observed_at) if old else None
        new_key = (new_time, severity.get(obs.observed_state, 0), obs.evidence_id)
        old_key = (old_time, severity.get(old.observed_state, 0), old.evidence_id) if old else None
        if old is None or (new_key > old_key):
            grouped[key] = obs
    return sorted(grouped.values(), key=lambda o: (o.system_id, o.resource_id, o.data_category))


def _step(phase: str, system_id: str, resource_id: str, operation: str, state: str, evidence_id: str = "") -> dict[str, Any]:
    return {
        "step_no": 0,
        "phase": phase,
        "system_id": system_id,
        "resource_id": resource_id,
        "operation": operation,
        "state": state,
        "evidence_id": evidence_id,
    }


def _sort_steps(steps: list[dict[str, Any]], status: str) -> list[dict[str, Any]]:
    def key(step):
        phase = step["phase"]
        ranks = {"FINDING": FINDING_ORDER, "REMEDIATION": REMEDIATION_ORDER, "VERIFICATION": VERIFICATION_ORDER}[phase]
        return (PHASE_ORDER[phase], ranks.get(step["operation"], 999), step["system_id"], step["resource_id"])
    ordered = sorted(steps, key=key)
    for i, item in enumerate(ordered, 1):
        item["step_no"] = i
        if status == "INCOMPLETE" and item["phase"] in {"REMEDIATION", "VERIFICATION"}:
            item["evidence_id"] = ""
    return ordered


def _build_steps(observations: list[StateObservation], status: str, user_id: str) -> list[dict[str, Any]]:
    findings, remediations, verifications = [], [], []
    action_by_resource = {}
    for obs in observations:
        action = _action_for(obs)
        if action:
            action_by_resource[(obs.system_id, obs.resource_id, obs.data_category)] = action
            finding_op, finding_state, remediation_op, remediation_state, verify_op, verify_state = ACTION_STEPS[action]
            findings.append(_step("FINDING", obs.system_id, obs.resource_id, finding_op, finding_state, obs.evidence_id))
            remediations.append(_step("REMEDIATION", obs.system_id, obs.resource_id, remediation_op, remediation_state))
            verifications.append(_step("VERIFICATION", obs.system_id, obs.resource_id, verify_op, verify_state))
            continue
        verification = _verification_for(obs)
        if verification:
            op, state = verification
            verifications.append(_step("VERIFICATION", obs.system_id, obs.resource_id, op, state, obs.evidence_id if status == "COMPLETE" else ""))

    if status == "INCOMPLETE" and not verifications:
        # Evidence was insufficient to name a concrete resource. This is a
        # future check, not a claim that the resource currently exists.
        verifications.append(_step("VERIFICATION", "account_service", user_id, "VERIFY_RECORD_ABSENT", "ABSENT"))

    return _sort_steps(findings + remediations + verifications, status)


def process_request(request: dict[str, str], resolver: IdentityResolver, documents) -> dict[str, str]:
    case_id = request["case_id"]
    if not is_deletion_request(request):
        return {"case_id": case_id, "deletion_status": "NOT_APPLICABLE", "steps_json": "[]"}

    matches = resolver.resolve(request.get("email", ""), request.get("audit_at", ""))
    if len(matches) != 1:
        # Keep the request in scope; without a unique identity, require follow-up.
        steps = [_step("VERIFICATION", "account_service", request.get("email", "unresolved_subject"), "VERIFY_RECORD_ABSENT", "ABSENT")]
        ordered = _sort_steps(steps, "INCOMPLETE")
        return {"case_id": case_id, "deletion_status": "INCOMPLETE", "steps_json": json.dumps(ordered, separators=(",", ":"), ensure_ascii=False)}

    identity = matches[0]
    observations = reconstruct_case_observations(DATASET, request, identity, documents=documents)
    observations = _collapse_observations(observations)
    actions = [_action_for(obs) for obs in observations]
    has_violation = any(actions)
    account_absence = any(
        obs.system_id == "account_service" and obs.data_category == "USER_PROFILE" and obs.observed_state == "ABSENT"
        for obs in observations
    )
    unresolved = any(
        obs.observed_state == "UNKNOWN" or obs.data_category == "UNKNOWN"
        for obs in observations
    )
    status = "COMPLETE" if (not has_violation and account_absence and not unresolved) else "INCOMPLETE"

    steps = _build_steps(observations, status, identity.user_id)
    # If the case is incomplete solely because the core account state was not
    # observed, make that missing verification explicit without inventing a finding.
    if status == "INCOMPLETE" and not any(s["phase"] == "FINDING" for s in steps):
        has_account_check = any(s["system_id"] == "account_service" for s in steps)
        if not has_account_check:
            steps.append(_step("VERIFICATION", "account_service", identity.user_id, "VERIFY_RECORD_ABSENT", "ABSENT"))
            steps = _sort_steps(steps, status)

    return {
        "case_id": case_id,
        "deletion_status": status,
        "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":")),
    }


def main() -> int:
    requests_path = DATASET / "deletion_requests.csv"
    if not requests_path.is_file():
        print(f"ERROR: requests file not found: {requests_path}", file=sys.stderr)
        return 2
    requests = read_csv(requests_path)
    if not requests:
        print("ERROR: deletion_requests.csv is empty.", file=sys.stderr)
        return 2
    required = {"case_id", "email", "audit_at", "request_text"}
    missing = required - set(requests[0])
    if missing:
        print(f"ERROR: missing required request columns: {sorted(missing)}", file=sys.stderr)
        return 2
    case_ids = [r.get("case_id", "") for r in requests]
    if any(not x for x in case_ids) or len(case_ids) != len(set(case_ids)):
        print("ERROR: blank or duplicate case IDs in requests.", file=sys.stderr)
        return 2

    print("Loading evidence (PDF/OCR/JSON/SQL/log/text) once...")
    documents = load_all_evidence(DATASET)
    extraction_errors = sum(bool(d.extraction_error) for d in documents)
    print(f"Evidence documents loaded: {len(documents)}; extraction errors: {extraction_errors}")
    resolver = IdentityResolver.from_dataset(DATASET)
    rows = []
    failures = []
    for i, request in enumerate(requests, 1):
        try:
            rows.append(process_request(request, resolver, documents))
        except Exception as exc:
            failures.append((request.get("case_id", "?"), f"{type(exc).__name__}: {exc}"))
            # A deterministic fail-closed result remains valid JSON and keeps the row.
            user_id = request.get("email", "unresolved_subject") or "unresolved_subject"
            fallback = [_step("VERIFICATION", "account_service", user_id, "VERIFY_RECORD_ABSENT", "ABSENT")]
            fallback = _sort_steps(fallback, "INCOMPLETE")
            rows.append({"case_id": request.get("case_id", ""), "deletion_status": "INCOMPLETE",
                         "steps_json": json.dumps(fallback, separators=(",", ":"), ensure_ascii=False)})
        if i % 50 == 0 or i == len(requests):
            print(f"Processed {i}/{len(requests)} requests.")

    rows.sort(key=lambda row: row["case_id"])
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    counts = {s: sum(row["deletion_status"] == s for row in rows) for s in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE")}
    print(f"\nOutput written: {OUTPUT_PATH}")
    print(f"Rows: {len(rows)}; status counts: {counts}; runtime exceptions: {len(failures)}")
    if failures:
        for case_id, message in failures[:20]:
            print(f"ERROR {case_id}: {message}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
