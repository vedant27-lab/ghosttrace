"""Evidence reconstruction across structured, SQL, log, text, PDF, and OCR evidence.

The module only emits observations whose identifiers can be linked exactly to the
resolved subject and whose evidence timestamps are no later than audit_at.
"""
from __future__ import annotations

import csv
import json
import re
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from .evidence_loader import EvidenceDocument, load_all_evidence
    from .identity_resolver import IdentityMatch, normalize_value, parse_timestamp
except ImportError:  # Supports direct execution from the code directory.
    from evidence_loader import EvidenceDocument, load_all_evidence
    from identity_resolver import IdentityMatch, normalize_value, parse_timestamp

SYSTEM_ALIASES = {
    "account_service": "account_service",
    "identity_service": "identity_service",
    "search_service": "search_service",
    "search_replica": "search_service",
    "support_platform": "support_platform",
    "support_replica": "support_platform",
    "analytics_platform": "analytics_platform",
    "integration_service": "integration_service",
    "security_service": "security_service",
    "marketing_platform": "marketing_platform",
    "export_service": "export_service",
    "object_storage": "object_storage",
    "cache_service": "cache_service",
    "backup_service": "backup_service",
    "email_delivery_service": "email_delivery_service",
}
RESOURCE_RE = re.compile(
    r"\b((?:account|identity|search|support|analytics|data_flow|audit_record|"
    r"backup|tombstone|export|cache|attachment|delivery|telemetry|marketing|object)"
    r"_\d+[A-Za-z0-9-]*)\b",
    re.I,
)
KV_RE = re.compile(r"([A-Za-z_][\w.-]*)=(\"([^\"]*)\"|'([^']*)'|\S+)")
IDENTIFIER_KEYS = {
    "email", "customer_email", "requester_email", "owner_email",
    "email_address", "requested_email", "lookup_key", "match_key", "query",
    "phone", "customer_phone", "requester_phone", "owner_phone",
    "email_hash", "user_id", "customer_reference", "subject_reference",
    "full_name", "name", "requester_name", "display_name",
}
PII_KEYS = {"email", "customer_email", "requester_email", "owner_email",
            "email_address", "phone", "customer_phone", "requester_phone",
            "owner_phone", "email_hash", "full_name", "name",
            "requester_name", "display_name"}
SYSTEM_KEYS = {"data_store", "system_id", "system", "service", "origin_system", "target_system"}
TIME_KEYS = ("observed_at", "captured_at", "recorded_at", "event_time", "updated_at", "timestamp", "created_at")


@dataclass
class StateObservation:
    case_id: str
    evidence_id: str
    evidence_path: str
    json_path: str
    captured_at: str
    observed_at: str
    system_id: str
    resource_id: str
    matched_identifiers: list[dict[str, str]] = field(default_factory=list)
    observed_state: str = "UNKNOWN"
    record: dict[str, Any] = field(default_factory=dict)
    data_category: str = "UNKNOWN"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _utc(value: str) -> datetime | None:
    try:
        return parse_timestamp(value)
    except (ValueError, TypeError):
        return None


def _identity_values(identity: IdentityMatch | dict[str, Any]) -> dict[str, set[str]]:
    data = identity.to_dict() if isinstance(identity, IdentityMatch) else identity
    values = {
        "email": set(data.get("emails", [])) | {data.get("requested_email", "")},
        "phone": set(data.get("phones", [])),
        "email_hash": set(data.get("email_hashes", [])),
        "user_id": {data.get("user_id", "")},
        "name": set(data.get("names", [])),
    }
    return {
        key: {normalize_value(key, str(v)) for v in vals if v and normalize_value(key, str(v))}
        for key, vals in values.items()
    }


def _match_scalar(key: str, value: Any, ids: dict[str, set[str]]) -> dict[str, str] | None:
    if value is None or isinstance(value, (dict, list, bool)):
        return None
    text = str(value).strip()
    if not text:
        return None
    k = key.casefold()
    if "hash" in k:
        kinds = ("email_hash",)
    elif "phone" in k:
        kinds = ("phone",)
    elif "email" in k or k in {"query", "lookup_key", "match_key"}:
        kinds = ("email",)
    elif k in {"name", "full_name", "requester_name", "display_name"}:
        kinds = ("name",)
    elif k in {"user_id", "customer_reference", "subject_reference"}:
        kinds = ("user_id", "email")
    elif k == "resource_id":
        kinds = ("resource_id",)
    else:
        # Some generic subject_reference/lookup fields contain email or user id.
        kinds = ("email", "user_id", "phone", "email_hash", "name")
    for kind in kinds:
        norm = normalize_value(kind, text)
        if norm and norm in ids.get(kind, set()):
            return {"field": key, "value": text, "match_type": kind}
    return None


def _flatten_scalars(value: Any, stop_at_resource: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {}
    def walk(node: Any, root: bool = False) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if not root and isinstance(v, dict) and v.get("resource_id"):
                    continue
                if not root and isinstance(v, list):
                    # Keep list content when it is contextual text, but not nested resource records.
                    for item in v:
                        if isinstance(item, dict) and item.get("resource_id"):
                            continue
                        walk(item)
                elif isinstance(v, (dict, list)):
                    walk(v)
                else:
                    out[k] = v
        elif isinstance(node, list):
            for item in node:
                walk(item)
    walk(value, True)
    return out


def _collect_matches(value: Any, ids: dict[str, set[str]]) -> list[dict[str, str]]:
    matches = []
    def walk(node: Any):
        if isinstance(node, dict):
            for k, v in node.items():
                m = _match_scalar(k, v, ids)
                if m:
                    matches.append(m)
                if isinstance(v, (dict, list)):
                    walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)
    walk(value)
    # stable de-duplication
    seen = set()
    result = []
    for m in matches:
        sig = (m["field"], m["value"], m["match_type"])
        if sig not in seen:
            seen.add(sig); result.append(m)
    return result



def _document_matches(text: str, ids: dict[str, set[str]]) -> list[dict[str, str]]:
    matches = []
    for value in re.findall(r"[A-Za-z0-9.!#$%&'*+/?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text):
        m = _match_scalar("email", value, ids)
        if m: matches.append(m)
    for value in re.findall(r"\buser_\d+\b", text, re.I):
        m = _match_scalar("user_id", value, ids)
        if m: matches.append(m)
    for value in re.findall(r"\b[a-fA-F0-9]{64}\b", text):
        m = _match_scalar("email_hash", value, ids)
        if m: matches.append(m)
    for value in re.findall(r"\+?\d[\d\s().-]{7,}\d", text):
        m = _match_scalar("phone", value, ids)
        if m: matches.append(m)
    normalized_text = " ".join(text.casefold().split())
    for name in ids.get("name", set()):
        if name and re.search(r"(?<!\w)" + re.escape(name) + r"(?!\w)", normalized_text):
            matches.append({"field": "name", "value": name, "match_type": "name"})
    return matches

def _system(value: str, inherited: str = "") -> str:
    v = (value or inherited or "").strip().casefold()
    if v in SYSTEM_ALIASES:
        return SYSTEM_ALIASES[v]
    for alias, canonical in SYSTEM_ALIASES.items():
        if alias in v:
            return canonical
    return inherited or "unknown"


def _category(system: str, path: str, record: dict[str, Any]) -> str:
    system = (system or "").casefold()
    rec_text = str(record).casefold()
    path_text = (path or "").casefold()
    collection = " ".join(str(record.get(k, "")) for k in ("collection_name", "collection", "record_type")).casefold()
    hay = f"{collection} {rec_text} {path_text}"
    if system == "identity_service" or "tombstone" in collection or "tombstone" in rec_text:
        return "ACCOUNT_TOMBSTONE" if ("tombstone" in hay or "deleted_customer_reference" in hay) else "SECONDARY_IDENTIFIER"
    if "legal_hold" in hay or "legal hold" in rec_text:
        return "LEGAL_HOLD_RECORD"
    if system == "backup_service" or "backup_archive" in collection or "restore_entries" in collection or "archive" in collection:
        return "BACKUP_ARCHIVE"
    if system == "integration_service" or "data_flow" in collection or "connector" in collection:
        return "DATA_FLOW"
    if system == "analytics_platform" or "analytics_profile" in collection or "customer_analytics" in collection:
        return "ANALYTICS_PROFILE"
    if "telemetry" in collection or "product_telemetry" in collection:
        return "PRODUCT_TELEMETRY"
    if system == "email_delivery_service" or ("delivery" in collection and "email" in collection):
        return "EMAIL_DELIVERY_LOG"
    if system == "security_service" or "security_audit" in collection or "audit_record" in str(record.get("resource_id", "")):
        return "SECURITY_AUDIT_LOG"
    if system == "search_service" or "search_index" in collection or "search_document" in collection:
        return "SEARCH_INDEX_ENTRY"
    if system == "cache_service" or "cache" in collection:
        return "CACHE_ENTRY"
    if system == "export_service" or "user_export" in collection or "export_job" in collection:
        return "USER_EXPORT"
    if system == "marketing_platform" or "marketing_profile" in collection:
        return "MARKETING_PROFILE"
    if system == "object_storage" or "attachment" in collection:
        return "SUPPORT_ATTACHMENT"
    if system == "support_platform":
        # A support export can contain both a shared conversation and an
        # uploaded document.  The explicit attachment marker is stronger than
        # the word "attachment" in the OCR text: attachment metadata must be
        # deleted, while shared conversation text is retained and redacted.
        resource_type = str(record.get("resource_type", "")).casefold()
        attachment_marker = record.get("attachment") is True or resource_type in {
            "attachment", "support_attachment", "document"
        }
        if attachment_marker:
            return "SUPPORT_ATTACHMENT"
        # Keep shared conversation context but delete bare contact/attachment copies.
        return "SUPPORT_MESSAGE" if (
            "message_pii_scan" in rec_text
            or (any(k in record for k in ("message", "message_excerpt", "body", "content"))
                and "attachment" not in rec_text)
            or ("message" in rec_text and "attachment" not in rec_text and "contact_query" not in rec_text)
            or ("ticket" in rec_text or "conversation" in rec_text)
        ) else "SUPPORT_ATTACHMENT"
    if system == "account_service" or "user_profile" in collection or "customer_profile" in collection:
        return "USER_PROFILE"
    return "UNKNOWN"


def _state(system: str, category: str, record: dict[str, Any], matches: list[dict[str, str]]) -> str:
    low = {str(k).casefold(): v for k, v in record.items()}
    text = str(record).casefold()
    if category == "DATA_FLOW":
        enabled = low.get("enabled")
        if enabled is True or str(enabled).casefold() in {"true", "1", "yes"}:
            return "ACTIVE"
        if enabled is False or str(enabled).casefold() in {"false", "0", "no"}:
            return "DISABLED"
        if "active" in text or "delivered" in text:
            return "ACTIVE"
        if "disabled" in text or "stopped" in text:
            return "DISABLED"
    if category == "BACKUP_ARCHIVE":
        allowed = low.get("restore_allowed")
        if allowed is False or str(allowed).casefold() in {"false", "0", "no"}:
            return "BLOCKED"
        if allowed is True or str(allowed).casefold() in {"true", "1", "yes"}:
            return "ACTIVE"
        if "blocked" in text:
            return "BLOCKED"
        if "restore_allowed=true" in text or "restore allowed" in text:
            return "ACTIVE"
    status = str(low.get("result", low.get("status", low.get("account_status", "")))).casefold()
    if status in {"not_found", "absent", "deleted", "404", "miss", "no_hit"} or low.get("http_status") == 404 or low.get("status_code") == 404 or low.get("rows") == 0:
        if category == "ACCOUNT_TOMBSTONE":
            return "REDACTED" if not any(low.get(k) not in (None, "") for k in PII_KEYS) else "PRESENT"
        return "ABSENT"
    if status in {"anonymized", "anonymous"}:
        return "ANONYMIZED"
    if status in {"redacted", "masked"}:
        return "REDACTED"
    if category == "ACCOUNT_TOMBSTONE":
        if str(low.get("account_status", "")).casefold() == "deleted":
            return "REDACTED" if not any(low.get(k) not in (None, "") for k in PII_KEYS) else "PRESENT"
    if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        direct = any(low.get(k) not in (None, "", "null", "NULL") for k in PII_KEYS | {"user_id", "customer_reference"})
        directly_matched = any(m.get("match_type") in {"email", "phone", "email_hash", "user_id", "name"} for m in matches)
        return "PRESENT" if direct or directly_matched else "ANONYMIZED"
    if category == "SECURITY_AUDIT_LOG" or category == "LEGAL_HOLD_RECORD":
        return "PRESENT"
    if category == "SUPPORT_MESSAGE":
        return "PRESENT" if any(low.get(k) not in (None, "") for k in PII_KEYS) else "REDACTED"
    if category == "EMAIL_DELIVERY_LOG":
        return "PRESENT" if any("email" in str(k).casefold() and v not in (None, "") for k, v in low.items()) else "REDACTED"
    if category in {"USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY", "SUPPORT_ATTACHMENT", "USER_EXPORT", "MARKETING_PROFILE"}:
        return "PRESENT"
    if matches:
        return "PRESENT"
    return "UNKNOWN"


def _make_obs(case_id, doc, path, observed_at, system, resource_id, record, matches, inherited_collection=""):
    flat = _flatten_scalars(record)
    flat.update({k: v for k, v in record.items() if not isinstance(v, (dict, list))})
    if inherited_collection:
        flat.setdefault("collection_name", inherited_collection)
    if not system or system == "unknown":
        system = _system_from_resource(str(resource_id), doc.path)
    category = _category(system, path, flat)
    state = _state(system, category, flat, matches)
    return StateObservation(
        case_id=case_id,
        evidence_id=doc.file_id,
        evidence_path=doc.path,
        json_path=path,
        captured_at=doc.captured_at,
        observed_at=observed_at or doc.captured_at,
        system_id=system or "unknown",
        resource_id=str(resource_id),
        matched_identifiers=matches,
        observed_state=state,
        record=flat,
        data_category=category,
    )


def _json_observations(doc, case_id, cutoff, ids):
    try:
        payload = json.loads(doc.content)
    except (json.JSONDecodeError, TypeError):
        return []
    out = []
    def walk(node, path="$", inherited_time="", inherited_system="", collection=""):
        if isinstance(node, dict):
            local_time = next((str(node[k]) for k in TIME_KEYS if node.get(k)), inherited_time or doc.captured_at)
            dt = _utc(local_time)
            if dt is None or dt > cutoff:
                return
            sys_hint = next((str(node[k]) for k in SYSTEM_KEYS if node.get(k)), inherited_system)
            sys_id = _system(sys_hint, inherited_system)
            coll = str(node.get("collection", node.get("collection_name", node.get("record_type", collection))) or collection)
            rid = node.get("resource_id")
            if rid:
                matches = _collect_matches(node, ids)
                if matches:
                    out.append(_make_obs(case_id, doc, path, local_time, sys_id, rid, node, matches, coll))
            for k, v in node.items():
                if k in SYSTEM_ALIASES:
                    child_sys = _system(k, sys_id)
                elif k in SYSTEM_KEYS and isinstance(v, str):
                    child_sys = _system(v, sys_id)
                else:
                    child_sys = sys_id
                walk(v, f"{path}.{k}", local_time, child_sys, coll)
        elif isinstance(node, list):
            for i, child in enumerate(node):
                walk(child, f"{path}[{i}]", inherited_time, inherited_system, collection)
    walk(payload)
    return out


_SQL_CACHE: dict[str, list[tuple[str, dict[str, Any], str]]] = {}


def _sql_observations(doc, case_id, cutoff, ids):
    out = []
    if doc.file_id not in _SQL_CACHE:
        parsed_rows: list[tuple[str, dict[str, Any], str]] = []
        db = sqlite3.connect(":memory:")
        try:
            db.executescript(doc.content)
            tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            for table in tables:
                safe = table.replace('"', '""')
                try:
                    cur = db.execute(f'SELECT * FROM "{safe}"')
                    cols = [x[0] for x in cur.description or []]
                    rows = cur.fetchall()
                except sqlite3.Error:
                    continue
                for row in rows:
                    rec = dict(zip(cols, row))
                    record_json = rec.get("record_json")
                    if record_json:
                        try:
                            nested = json.loads(record_json)
                            if isinstance(nested, dict):
                                rec.update(nested)
                        except (json.JSONDecodeError, TypeError):
                            pass
                    observed = next((str(rec[k]) for k in TIME_KEYS if rec.get(k)), doc.captured_at)
                    system_hint = str(rec.get("origin_system", rec.get("system", "")) or "")
                    if not system_hint:
                        table_hint = table.casefold()
                        if "customer_profiles" in table_hint or "customer_accounts" in table_hint:
                            system_hint = "account_service"
                        elif "search" in table_hint:
                            system_hint = "search_service"
                        elif "analytics" in table_hint or "telemetry" in table_hint:
                            system_hint = "analytics_platform"
                        elif "support" in table_hint:
                            system_hint = "support_platform"
                        elif "connector" in table_hint or "subscription" in table_hint:
                            system_hint = "integration_service"
                        elif "backup" in table_hint or "restore" in table_hint:
                            system_hint = "backup_service"
                        elif "export" in table_hint:
                            system_hint = "export_service"
                        elif "tombstone" in table_hint or "identity" in table_hint:
                            system_hint = "identity_service"
                        elif "security" in table_hint or "audit" in table_hint:
                            system_hint = "security_service"
                        else:
                            system_hint = table
                    system = _system(system_hint)
                    if system == "unknown":
                        system = _system_from_path(table, "")
                    rid = rec.get("resource_id")
                    if not rid:
                        m = RESOURCE_RE.search(str(rec))
                        rid = m.group(1) if m else ""
                    if rid:
                        rec.setdefault("collection_name", table)
                        rec.setdefault("origin_system", system)
                        parsed_rows.append((table, rec, observed))
        except sqlite3.Error:
            pass
        finally:
            db.close()
        _SQL_CACHE[doc.file_id] = parsed_rows

    for table, rec, observed in _SQL_CACHE[doc.file_id]:
        dt = _utc(observed)
        if dt is None or dt > cutoff:
            continue
        matches = _collect_matches(rec, ids)
        if not matches:
            continue
        system = _system(str(rec.get("origin_system", rec.get("system", "")) or table))
        if system == "unknown":
            system = _system_from_path(table, "")
        rid = rec.get("resource_id")
        if not rid:
            continue
        out.append(_make_obs(case_id, doc, f"sql:{table}", observed, system, rid, rec, matches, str(rec.get("collection_name", table))))
    return out


def _parse_kv(line: str) -> dict[str, str]:
    out = {}
    for m in KV_RE.finditer(line):
        val = m.group(3) if m.group(3) is not None else m.group(4) if m.group(4) is not None else m.group(2)
        out[m.group(1)] = val
    return out


def _log_observations(doc, case_id, cutoff, ids):
    lines = []
    for line_no, line in enumerate(doc.content.splitlines(), start=1):
        m = re.match(r"^\s*(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z?)", line)
        ts = m.group(1) if m else doc.captured_at
        dt = _utc(ts)
        if dt is None or dt > cutoff:
            continue
        fields = _parse_kv(line)
        fields["_line"] = line
        fields["_time"] = ts
        fields["_line_no"] = str(line_no)
        # Different log formats use requestId, trace_id, positional tr-IDs, etc.
        trace = next((fields[k] for k in ("trace_id", "trace", "requestId", "request_id", "correlation_id") if fields.get(k)), "")
        if not trace:
            tm = re.search(r"\btr-[A-Za-z0-9-]+\b", line)
            trace = tm.group(0) if tm else f"line:{line_no}"
        fields["_trace"] = trace
        lines.append(fields)

    groups = {}
    for fields in lines:
        groups.setdefault(fields["_trace"], []).append(fields)

    out = []
    for key, group in groups.items():
        line_text = " ".join(f.get("_line", "") for f in group)
        matches = _document_matches(line_text, ids)
        if not matches:
            continue
        resource_ids = list(dict.fromkeys(RESOURCE_RE.findall(line_text)))
        for fields in group:
            rid = (fields.get("resource_id", "") or "").strip().strip("\\\"' ")
            if rid and rid not in resource_ids:
                resource_ids.append(rid)
        if not resource_ids:
            continue

        # Find the system in the service/function prefix or explicit fields.
        system = "unknown"
        for fields in reversed(group):
            hint = fields.get("service") or fields.get("function") or fields.get("target_system") or fields.get("source_system") or ""
            candidate = _system(hint)
            if candidate != "unknown":
                system = candidate
                break
        if system == "unknown":
            low_text = line_text.casefold()
            for alias in sorted(SYSTEM_ALIASES, key=len, reverse=True):
                if alias in low_text:
                    system = SYSTEM_ALIASES[alias]
                    break

        allfields = {}
        for fields in group:
            allfields.update({k: v for k, v in fields.items() if not k.startswith("_")})
        for rid in resource_ids:
            this_system = system if system != "unknown" else _system_from_resource(rid, doc.path)
            rec = dict(allfields)
            rec.update({"resource_id": rid, "document_text": line_text[:6000]})
            category = _category(this_system, doc.path, rec)
            state = _state(this_system, category, rec, matches)
            low = line_text.casefold()
            if re.search(r"\b(?:rows|total_hits)[^0-9]{0,3}0\b", low) or re.search(r"\bhttp_status[^0-9]{0,3}404\b", low) or re.search(r"\bresult[^a-z]{0,3}(?:miss|not_found)\b", low) or "not_found" in low:
                state = "ABSENT"
            if re.search(r"enabled[^a-z]{0,3}false", low) or "last_delivery_status=stopped" in low or "state=disabled" in low:
                if category == "DATA_FLOW": state = "DISABLED"
            if re.search(r"restore_allowed[^a-z]{0,3}false", low) or re.search(r"result[^a-z]{0,3}blocked", low) or "state=blocked" in low:
                if category == "BACKUP_ARCHIVE": state = "BLOCKED"
            if re.search(r"enabled[^a-z]{0,3}true", low) or "last_delivery_status=delivered" in low:
                if category == "DATA_FLOW": state = "ACTIVE"
            if re.search(r"restore_allowed[^a-z]{0,3}true", low):
                if category == "BACKUP_ARCHIVE": state = "ACTIVE"
            if re.search(r"decision[^a-z]{0,3}deny", low) or re.search(r"restore_blocked[^a-z]{0,3}true", low):
                if category == "BACKUP_ARCHIVE": state = "BLOCKED"
            if "anonymized" in low and category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
                state = "ANONYMIZED"
            if ("direct_identifiers=1" in low or "matched_value=" in low) and category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY", "SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT"}:
                state = "PRESENT"
            if "redacted" in low and category in {"SUPPORT_MESSAGE", "ACCOUNT_TOMBSTONE", "EMAIL_DELIVERY_LOG"}:
                state = "REDACTED"
            observed = group[-1].get("_time", doc.captured_at)
            out.append(StateObservation(
                case_id=case_id, evidence_id=doc.file_id, evidence_path=doc.path,
                json_path=f"log:{key}", captured_at=doc.captured_at,
                observed_at=observed, system_id=this_system, resource_id=rid,
                matched_identifiers=matches, observed_state=state,
                record=rec, data_category=category,
            ))
    return out


def _system_from_resource(rid: str, path: str) -> str:
    prefix = rid.split("_", 1)[0].casefold()
    mapping = {"account":"account_service","identity":"identity_service","search":"search_service","support":"support_platform","analytics":"analytics_platform","data":"integration_service","audit":"security_service","backup":"backup_service","tombstone":"identity_service","export":"export_service","cache":"cache_service","delivery":"email_delivery_service","marketing":"marketing_platform","object":"object_storage"}
    return mapping.get(prefix, next((v for k,v in SYSTEM_ALIASES.items() if k in path.casefold()), "unknown"))


def _text_observations(doc, case_id, cutoff, ids):
    out = []
    for line_no, line in enumerate(doc.content.splitlines(), start=1):
        m = re.match(r"^\s*(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z?)", line)
        ts = m.group(1) if m else doc.captured_at
        dt = _utc(ts)
        if dt is None or dt > cutoff:
            continue
        # Parse handover-style pipe-delimited rows.
        if "|" in line:
            parts = [x.strip() for x in line.split("|")]
            if len(parts) >= 5:
                joined = {"subject_reference": parts[-1], "lookup_key": parts[-1]}
                matches = _collect_matches(joined, ids)
                rid_m = RESOURCE_RE.search(line)
                if matches and rid_m:
                    # The system and resource fields are typically columns 2 and 3.
                    system = _system(parts[1]) if len(parts) > 1 else "unknown"
                    rid = next((x for x in parts if RESOURCE_RE.fullmatch(x)), rid_m.group(1))
                    cat = next((x for x in parts if x.upper() in {"USER_PROFILE","SEARCH_INDEX_ENTRY","ANALYTICS_PROFILE","BACKUP_ARCHIVE","DATA_FLOW","SUPPORT_MESSAGE","SUPPORT_ATTACHMENT","USER_EXPORT","ACCOUNT_TOMBSTONE","SECURITY_AUDIT_LOG"}), "")
                    rec = {"resource_id": rid, "record_type": cat, "result": parts[-2] if len(parts) > 1 else ""}
                    category = _category(system, cat, rec)
                    state_token = str(rec.get("result","")).casefold()
                    state = {"not_found":"ABSENT","anonymized":"ANONYMIZED","redacted":"REDACTED","active":"ACTIVE","blocked":"BLOCKED","disabled":"DISABLED","found":"PRESENT","identifiable":"PRESENT"}.get(state_token, "PRESENT")
                    out.append(StateObservation(case_id, doc.file_id, doc.path, f"text:{line_no}", doc.captured_at, ts, system, rid, matches, state, rec, category))
                    continue
        # Generic line: exact identity + resource ID.
        rid_m = RESOURCE_RE.search(line)
        matches = _document_matches(line, ids)
        if rid_m:
            matches.extend(_collect_matches({"resource_id": rid_m.group(1)}, ids))
        # Keep matching deterministic when a line contains both a direct
        # identifier and a resource link.
        matches = list({
            (m["field"], m["value"], m["match_type"]): m for m in matches
        }.values())
        if matches and rid_m:
            rid = rid_m.group(1)
            system = _system_from_resource(rid, doc.path)
            rec = _parse_kv(line)
            rec["resource_id"] = rid
            cat = _category(system, doc.path, rec)
            state = _state(system, cat, rec, matches)
            out.append(StateObservation(case_id, doc.file_id, doc.path, f"text:{line_no}", doc.captured_at, ts, system, rid, matches, state, rec, cat))
    # PDFs and narrative artifacts often split the identity and resource reference
    # across separate lines. Associate them only within that one document.
    if doc.file_type in {"pdf", "png", "jpg", "jpeg", "tif", "tiff", "bmp"}:
        doc_matches = _document_matches(doc.content, ids)
        resource_ids = list(dict.fromkeys(RESOURCE_RE.findall(doc.content)))
        if doc_matches and resource_ids:
            for rid in resource_ids:
                system = _system_from_resource(rid, doc.path)
                rec = {"resource_id": rid, "document_text": doc.content[:5000], "attachment": True}
                cat = _category(system, doc.path, rec)
                doc_state = _state(system, cat, rec, doc_matches)
                if cat == "DATA_FLOW" and "continuous" in doc.content.casefold() and "healthy" in doc.content.casefold():
                    doc_state = "ACTIVE"
                out.append(StateObservation(
                    case_id, doc.file_id, doc.path, "document", doc.captured_at,
                    doc.captured_at, system, rid, doc_matches, doc_state, rec, cat
                ))
    return out


def _system_from_path(path: str, inherited: str = "") -> str:
    for alias, canonical in SYSTEM_ALIASES.items():
        if alias in path.casefold():
            return canonical
    return inherited or "unknown"


_ACTIVITY_CACHE: dict[str, list[dict[str, str]]] = {}


def _activity_links(dataset: Path, case: dict[str, str], ids: dict[str, set[str]]) -> list[dict[str, str]]:
    path = dataset / "system_activity.csv"
    cache_key = str(path.resolve())
    if cache_key not in _ACTIVITY_CACHE:
        try:
            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                _ACTIVITY_CACHE[cache_key] = list(csv.DictReader(handle))
        except OSError:
            _ACTIVITY_CACHE[cache_key] = []
    cutoff = _utc(case["audit_at"])
    links = []
    for row in _ACTIVITY_CACHE[cache_key]:
        if (row.get("event_type", "") or "").casefold() != "link_resource_identity":
            continue
        dt = _utc(row.get("event_time", ""))
        if cutoff is None or dt is None or dt > cutoff:
            continue
        matches = _document_matches(" ".join([
            row.get("details", ""), row.get("resource_id", ""),
            row.get("source_system", ""), row.get("target_system", ""),
        ]), ids)
        if not matches:
            continue
        rid = (row.get("resource_id") or "").strip()
        if not rid:
            continue
        details = row.get("details", "")
        refs = re.findall(r"\(([^()]+)\)", details)
        links.append({
            "resource_id": rid, "activity_id": row.get("activity_id", ""),
            "event_time": row.get("event_time", ""), "event_type": row.get("event_type", ""),
            "source_system": row.get("source_system", ""), "target_system": row.get("target_system", ""),
            "details": details, "refs": "|".join(refs),
            "matched": json.dumps(matches, ensure_ascii=False),
        })
    return links


_DOC_TEXT_CACHE: dict[str, tuple[str, str]] = {}


def _document_might_match(doc: EvidenceDocument, ids: dict[str, set[str]]) -> bool:
    cached = _DOC_TEXT_CACHE.get(doc.file_id)
    if cached is None:
        lower = doc.content.casefold()
        digits = re.sub(r"\D", "", lower)
        _DOC_TEXT_CACHE[doc.file_id] = (lower, digits)
    else:
        lower, digits = cached
    text = lower
    if any(v and v in text for v in ids.get("email", set())):
        return True
    if any(v and v in text for v in ids.get("email_hash", set())):
        return True
    for uid in ids.get("user_id", set()) | ids.get("resource_id", set()):
        if uid and re.search(r"(?<![A-Za-z0-9_])" + re.escape(uid) + r"(?![A-Za-z0-9_])", text, re.I):
            return True
    for phone in ids.get("phone", set()):
        phone_digits = re.sub(r"\D", "", phone)
        if len(phone_digits) >= 8 and phone_digits in digits:
            return True
    normalized = " ".join(text.split())
    for name in ids.get("name", set()):
        if name and len(name) >= 5 and name in normalized:
            return True
    return False


def reconstruct_case_observations(dataset_dir: str | Path, case: dict[str, str],
                                  identity: IdentityMatch | dict[str, Any],
                                  documents: list[EvidenceDocument] | None = None) -> list[StateObservation]:
    dataset = Path(dataset_dir)
    cutoff = _utc(case["audit_at"])
    if cutoff is None:
        return []
    docs = documents if documents is not None else load_all_evidence(dataset)
    ids = _identity_values(identity)
    links = _activity_links(dataset, case, ids)
    for link in links:
        ids.setdefault("resource_id", set()).add(link["resource_id"])
    observations: list[StateObservation] = []
    # A catalog link proves ownership, not that the linked resource is still
    # present.  Keep it as an identity bridge and only emit a state observation
    # when a participant-visible evidence document describes the resource.
    for doc in docs:
        captured = _utc(doc.captured_at)
        if captured is None or captured > cutoff or not doc.content:
            continue
        if not _document_might_match(doc, ids):
            continue
        try:
            if doc.file_type == "json":
                observations.extend(_json_observations(doc, case["case_id"], cutoff, ids))
            elif doc.file_type == "sql":
                observations.extend(_sql_observations(doc, case["case_id"], cutoff, ids))
            elif doc.file_type == "log":
                observations.extend(_log_observations(doc, case["case_id"], cutoff, ids))
            elif doc.file_type in {"txt", "csv"}:
                observations.extend(_text_observations(doc, case["case_id"], cutoff, ids))
            elif doc.file_type in {"pdf", "png", "jpg", "jpeg", "tif", "tiff", "bmp"}:
                observations.extend(_text_observations(doc, case["case_id"], cutoff, ids))
        except (ValueError, TypeError, sqlite3.Error):
            continue

        # Catalog links sometimes connect a document's business reference to a
        # resource ID even when the document predates the catalog export.
        content_folded = (doc.content + " " + doc.path).casefold()
        for link in links:
            refs = [x.strip() for x in link.get("refs", "").split("|") if x.strip()]
            if not refs or not any(ref.casefold() in content_folded for ref in refs):
                continue
            if captured > cutoff:
                continue
            rid = link["resource_id"]
            system = _system(link.get("target_system", "")) 
            if system == "unknown":
                system = _system_from_resource(rid, doc.path)
            category = _category(system, doc.path, {"resource_id": rid, "collection_name": link.get("event_type", "")})
            try:
                matched = json.loads(link.get("matched", "[]"))
            except json.JSONDecodeError:
                matched = []
            observations.append(StateObservation(
                case_id=case["case_id"], evidence_id=doc.file_id, evidence_path=doc.path,
                json_path="linked-document", captured_at=doc.captured_at,
                observed_at=doc.captured_at, system_id=system, resource_id=rid,
                matched_identifiers=matched, observed_state="PRESENT",
                record={"resource_id": rid, "document_reference": refs[0]},
                data_category=category,
            ))

    # De-duplicate repeated references within the same source while retaining replica evidence.
    unique = {}
    for obs in observations:
        key = (obs.evidence_id, obs.system_id, obs.resource_id, obs.data_category)
        old = unique.get(key)
        rank = {"UNKNOWN":0,"ABSENT":1,"REDACTED":2,"ANONYMIZED":3,"PRESENT":4,"DISABLED":4,"BLOCKED":4,"ACTIVE":5}
        if old is None or rank.get(obs.observed_state,0) > rank.get(old.observed_state,0):
            unique[key] = obs
    return sorted(unique.values(), key=lambda o: (o.system_id, o.resource_id, o.observed_at, o.evidence_id, o.json_path))
