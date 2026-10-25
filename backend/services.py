from __future__ import annotations

import csv
import io
import json
import re
import shutil
import sys
import threading
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CORE_DIR = Path(__file__).resolve().parents[1] / "code"
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))

import main as audit_engine
from evidence_loader import EvidenceDocument, load_all_evidence, load_manifest
from identity_resolver import IdentityMatch, IdentityResolver, parse_timestamp
from state_reconstructor import reconstruct_case_observations

from .demo_data import DEMO_CASES, DEMO_EVIDENCE, DEMO_RESULTS, demo_steps
from .models import (
    AuditJob,
    CaseDetail,
    CaseSummary,
    DeletionStatus,
    EvidenceDetail,
    EvidencePage,
    EvidenceReference,
    EvidenceSummary,
    IdentityHistoryItem,
    ObservationModel,
    StatusCounts,
    StepModel,
    SummaryResponse,
)


@dataclass
class JobRecord:
    job_id: str
    status: str
    total_cases: int
    started_at: str
    demo: bool
    cases_completed: int = 0
    finished_at: str | None = None
    result: dict[str, Any] | None = None
    error: str | None = None
    output_path: str | None = None
    cancel_event: threading.Event = field(default_factory=threading.Event)

    def to_model(self) -> AuditJob:
        return AuditJob(
            job_id=self.job_id,
            status=self.status,
            progress=round((self.cases_completed / self.total_cases) * 100) if self.total_cases else 100,
            cases_completed=self.cases_completed,
            total_cases=self.total_cases,
            started_at=self.started_at,
            finished_at=self.finished_at,
            result=self.result,
            error=self.error,
            cancellable=self.status in {"queued", "running"},
            demo=self.demo,
        )


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sanitize_text(value: str, limit: int = 1000) -> str:
    text = str(value or "")
    text = re.sub(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[email]", text)
    text = re.sub(r"(?<!\w)\+?\d[\d\s().-]{7,}\d(?!\w)", "[phone]", text)
    text = re.sub(r"(?i)(sha256:)?[a-f0-9]{32,}", "[hash]", text)
    return " ".join(text.split())[:limit]


def mask_identifier(value: str, field: str) -> str:
    if not value:
        return ""
    if "email" in field:
        local, _, domain = value.partition("@")
        return f"{local[:1]}***@{domain}" if domain else "[email]"
    if "phone" in field:
        digits = re.sub(r"\D", "", value)
        return f"***{digits[-4:]}" if digits else "[phone]"
    if "hash" in field:
        return f"{value[:6]}…" if len(value) > 6 else "[hash]"
    if field in {"name", "full_name", "requester_name", "display_name"}:
        return " ".join(part[:1] + "***" for part in value.split())
    return sanitize_text(value, 160)


def sanitize_record(record: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in record.items():
        lowered = key.casefold()
        if lowered in {"document_text", "line", "_line"}:
            result[key] = "[excerpt withheld]"
        elif any(token in lowered for token in ("email", "phone", "hash", "name")) and value not in (None, ""):
            result[key] = mask_identifier(str(value), lowered)
        elif isinstance(value, (str, int, float, bool)) or value is None:
            result[key] = sanitize_text(str(value), 240) if isinstance(value, str) else value
    return result


class AuditRepository:
    """Read-only view over the engine's dataset and generated output."""

    def __init__(self, root: str | Path | None = None, force_demo: bool = False):
        self.root = Path(root or Path(__file__).resolve().parents[1]).resolve()
        self.dataset_dir = self.root / "dataset"
        required = ("deletion_requests.csv", "user_identities.csv", "evidence_files.csv")
        self.dataset_available = not force_demo and all((self.dataset_dir / name).is_file() for name in required)
        self.demo = not self.dataset_available
        self._lock = threading.RLock()
        self._documents: list[EvidenceDocument] | None = None
        self._resolver: IdentityResolver | None = None
        self._requests: list[dict[str, str]] = []
        self._results: dict[str, dict[str, str]] = {}
        self._manifest: dict[str, EvidenceDocument] = {}
        self._load_index()

    def _load_index(self) -> None:
        if self.demo:
            self._requests = [dict(row) for row in DEMO_CASES]
            self._results = {key: dict(value) for key, value in DEMO_RESULTS.items()}
            self._manifest = {
                item["evidence_id"]: EvidenceDocument(
                    file_id=item["evidence_id"], path=item["evidence_id"], origin=item["origin"],
                    captured_at=item["captured_at"], file_type=item["file_type"], content=item["content"],
                    extraction_method=item["extraction_method"], extraction_error=item["extraction_error"],
                ) for item in DEMO_EVIDENCE
            }
            return
        self._requests = audit_engine.read_csv(self.dataset_dir / "deletion_requests.csv")
        self._resolver = IdentityResolver.from_dataset(self.dataset_dir)
        self._manifest = {doc.file_id: doc for doc in load_manifest(self.dataset_dir)}
        self.reload_results()

    @property
    def total_cases(self) -> int:
        return len(self._requests)

    def reload_results(self) -> None:
        path = self.root / "output.csv"
        if not path.is_file():
            self._results = {}
            return
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            self._results = {row["case_id"]: row for row in csv.DictReader(handle) if row.get("case_id")}

    def ensure_results(self) -> None:
        if self.demo or self._results:
            return
        with self._lock:
            if not self._results:
                audit_engine.generate_output(self.dataset_dir, self.root / "output.csv")
                self.reload_results()

    def documents(self) -> list[EvidenceDocument]:
        with self._lock:
            if self._documents is None:
                self._documents = list(self._manifest.values()) if self.demo else load_all_evidence(self.dataset_dir)
                self._manifest = {doc.file_id: doc for doc in self._documents}
            return self._documents

    def requests(self) -> list[dict[str, str]]:
        return list(self._requests)

    def summary(self) -> SummaryResponse:
        self.ensure_results()
        counts = Counter(row.get("deletion_status", "INCOMPLETE") for row in self._results.values())
        return SummaryResponse(
            total_requests=len(self._requests),
            status_counts=StatusCounts(
                complete=counts["COMPLETE"], incomplete=counts["INCOMPLETE"], not_applicable=counts["NOT_APPLICABLE"]
            ),
            generated_at=utc_now(), demo=self.demo, dataset_available=self.dataset_available,
            evidence_files=len(self._manifest),
        )

    def _summary(self, request: dict[str, str]) -> CaseSummary:
        result = self._results.get(request["case_id"], {"deletion_status": "INCOMPLETE"})
        status = result.get("deletion_status", "INCOMPLETE")
        if status not in DeletionStatus.__members__:
            status = "INCOMPLETE"
        return CaseSummary(
            case_id=request["case_id"], email=mask_identifier(request.get("email", ""), "email"),
            requested_at=request.get("requested_at", ""), audit_at=request.get("audit_at", ""),
            reported_status=request.get("reported_status", ""), deletion_status=DeletionStatus(status),
            request_excerpt=sanitize_text(request.get("request_text", ""), 180), demo=self.demo,
        )

    def list_cases(self, status: str | None, query: str | None, case_id: str | None,
                   requested_from: str | None, requested_to: str | None,
                   page: int, page_size: int) -> Any:
        self.ensure_results()
        rows = self._requests
        if status:
            rows = [row for row in rows if self._results.get(row["case_id"], {}).get("deletion_status") == status]
        needle = (query or "").casefold()
        if needle:
            rows = [row for row in rows if needle in row["case_id"].casefold() or needle in row.get("email", "").casefold()]
        if case_id:
            rows = [row for row in rows if row["case_id"] == case_id]
        for value, key, comparator in ((requested_from, "requested_at", lambda actual, bound: actual < bound), (requested_to, "requested_at", lambda actual, bound: actual > bound)):
            if value:
                try:
                    bound = parse_timestamp(value)
                except ValueError as exc:
                    raise ValueError(f"Invalid date filter: {value}") from exc
                rows = [row for row in rows if not comparator(parse_timestamp(row[key]), bound)]
        rows = sorted(rows, key=lambda row: row["case_id"])
        start = (page - 1) * page_size
        return {
            "items": [self._summary(row) for row in rows[start:start + page_size]],
            "page": page, "page_size": page_size, "total": len(rows), "demo": self.demo,
        }

    def _identity_history(self, match: IdentityMatch | None) -> list[IdentityHistoryItem]:
        if match is None:
            return []
        data = match.to_dict()
        items: list[IdentityHistoryItem] = []
        for field in ("emails", "phones", "email_hashes", "names"):
            output_field = field.removesuffix("s")
            for value in data.get(field, []):
                items.append(IdentityHistoryItem(field=output_field, value=mask_identifier(value, output_field), source="current or historical identity"))
        return items[:40]

    def _evidence_ref(self, evidence_id: str) -> EvidenceReference:
        doc = self._manifest.get(evidence_id)
        if doc:
            source_path = Path(doc.path).name if doc.path else None
            return EvidenceReference(evidence_id=evidence_id, origin=doc.origin, file_type=doc.file_type, captured_at=doc.captured_at, source_path=source_path)
        return EvidenceReference(evidence_id=evidence_id, origin="system_activity", file_type="csv", source_path="system_activity.csv")

    def case_detail(self, case_id: str) -> CaseDetail | None:
        self.ensure_results()
        request = next((row for row in self._requests if row["case_id"] == case_id), None)
        if request is None:
            return None
        summary = self._summary(request)
        steps_raw = self._results.get(case_id, {}).get("steps_json", "[]")
        try:
            steps = [StepModel.model_validate(step) for step in json.loads(steps_raw)]
        except (json.JSONDecodeError, TypeError, ValueError):
            steps = []
        if self.demo:
            warning = ["Synthetic demo data: no participant dataset is connected."]
            return CaseDetail(**summary.model_dump(), explanation="Demo result generated from synthetic evidence.", identity_history=[], evidence=[self._evidence_ref(step.evidence_id) for step in steps if step.evidence_id], observations=[], steps=steps, warnings=warning)

        warnings: list[str] = []
        match: IdentityMatch | None = None
        observations: list[ObservationModel] = []
        if self._resolver:
            matches = self._resolver.resolve(request.get("email", ""), request.get("audit_at", ""))
            if len(matches) == 1:
                match = matches[0]
                try:
                    raw_observations = audit_engine._collapse_observations(
                        reconstruct_case_observations(self.dataset_dir, request, match, documents=self.documents())
                    )
                    observations = [ObservationModel(
                        evidence_id=obs.evidence_id, system_id=obs.system_id, resource_id=obs.resource_id,
                        data_category=obs.data_category, observed_state=obs.observed_state,
                        observed_at=obs.observed_at, captured_at=obs.captured_at,
                        record=sanitize_record(obs.record),
                    ) for obs in raw_observations]
                except (OSError, ValueError, TypeError) as exc:
                    warnings.append(f"Evidence reconstruction unavailable: {type(exc).__name__}")
            else:
                warnings.append("Identity could not be resolved to one unique subject at the audit cutoff.")
        if summary.deletion_status == DeletionStatus.INCOMPLETE and not observations:
            warnings.append("The available evidence does not establish a complete current state; missing evidence is not proof of deletion.")
        evidence_ids = list(dict.fromkeys([step.evidence_id for step in steps if step.evidence_id] + [obs.evidence_id for obs in observations]))
        explanation = {
            DeletionStatus.COMPLETE: "All observed relevant resources satisfy the policy at the audit cutoff.",
            DeletionStatus.INCOMPLETE: "At least one policy violation, recreation risk, or unresolved verification remains.",
            DeletionStatus.NOT_APPLICABLE: "The request does not authorize deletion.",
        }[summary.deletion_status]
        return CaseDetail(**summary.model_dump(), explanation=explanation, identity_history=self._identity_history(match), evidence=[self._evidence_ref(evidence_id) for evidence_id in evidence_ids], observations=observations, steps=steps, warnings=warnings)

    def list_evidence(self, search: str | None, file_type: str | None, page: int, page_size: int) -> EvidencePage:
        docs = self.documents() if search else list(self._manifest.values())
        needle = (search or "").casefold()[:120]
        if needle:
            docs = [doc for doc in docs if needle in doc.file_id.casefold() or needle in doc.origin.casefold() or needle in doc.content.casefold()]
        if file_type:
            docs = [doc for doc in docs if doc.file_type == file_type.casefold().lstrip(".")]
        items = [EvidenceSummary(evidence_id=doc.file_id, file_type=doc.file_type, origin=doc.origin, captured_at=doc.captured_at, extraction_method=doc.extraction_method or None, has_extraction_error=bool(doc.extraction_error), demo=self.demo) for doc in sorted(docs, key=lambda item: item.file_id)]
        start = (page - 1) * page_size
        return EvidencePage(items=items[start:start + page_size], page=page, page_size=page_size, total=len(items), demo=self.demo)

    def evidence_detail(self, evidence_id: str) -> EvidenceDetail | None:
        doc = self._manifest.get(evidence_id)
        if doc is None:
            return None
        if not self.demo:
            doc = next((item for item in self.documents() if item.file_id == evidence_id), doc)
        lines = [sanitize_text(line, 500) for line in doc.content.splitlines() if line.strip()]
        excerpt = "\n".join(lines[:24])
        summary = EvidenceSummary(evidence_id=doc.file_id, file_type=doc.file_type, origin=doc.origin, captured_at=doc.captured_at, extraction_method=doc.extraction_method or None, has_extraction_error=bool(doc.extraction_error), demo=self.demo)
        return EvidenceDetail(**summary.model_dump(), excerpt=excerpt, extraction_error=doc.extraction_error or None)

    def download_csv(self) -> tuple[Path | None, str]:
        if self.demo:
            stream = io.StringIO()
            writer = csv.DictWriter(stream, fieldnames=["case_id", "deletion_status", "steps_json"])
            writer.writeheader()
            for case in DEMO_CASES:
                result = DEMO_RESULTS[case["case_id"]]
                writer.writerow({"case_id": case["case_id"], **result})
            return None, stream.getvalue()
        self.ensure_results()
        return self.root / "output.csv", ""


class AuditJobManager:
    def __init__(self, repository: AuditRepository):
        self.repository = repository
        self._lock = threading.RLock()
        self._jobs: dict[str, JobRecord] = {}
        self._active_job_id: str | None = None
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ghosttrace-audit")

    def start(self) -> JobRecord:
        with self._lock:
            if self._active_job_id:
                active = self._jobs[self._active_job_id]
                if active.status in {"queued", "running"}:
                    raise RuntimeError("An audit job is already running")
            record = JobRecord(job_id=uuid.uuid4().hex, status="queued", total_cases=self.repository.total_cases, started_at=utc_now(), demo=self.repository.demo)
            self._jobs[record.job_id] = record
            self._active_job_id = record.job_id
            self._executor.submit(self._run, record)
            return record

    def _run(self, record: JobRecord) -> None:
        with self._lock:
            record.status = "running"
        try:
            if self.repository.demo:
                for index in range(1, record.total_cases + 1):
                    if record.cancel_event.is_set():
                        raise audit_engine.AuditCancelled("Audit cancelled by caller")
                    record.cases_completed = index
                result = {"rows": record.total_cases, "status_counts": {"COMPLETE": 1, "INCOMPLETE": 1, "NOT_APPLICABLE": 1}, "demo": True}
            else:
                def progress(completed: int, total: int) -> bool:
                    record.cases_completed = completed
                    return not record.cancel_event.is_set()
                result = audit_engine.generate_output(self.repository.dataset_dir, self.repository.root / "output.csv", progress)
                self.repository.reload_results()
                job_output = self.repository.root / ".runtime" / "jobs" / record.job_id / "output.csv"
                job_output.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(self.repository.root / "output.csv", job_output)
                record.output_path = str(job_output)
            record.result = result
            record.cases_completed = record.total_cases
            record.status = "completed"
        except audit_engine.AuditCancelled:
            record.status = "cancelled"
            record.error = "Audit cancelled; the previous output remains available."
        except Exception as exc:  # boundary for background work; error is exposed in job status
            record.status = "failed"
            record.error = f"{type(exc).__name__}: {exc}"
        finally:
            record.finished_at = utc_now()
            with self._lock:
                if self._active_job_id == record.job_id:
                    self._active_job_id = None

    def get(self, job_id: str) -> JobRecord | None:
        return self._jobs.get(job_id)

    def cancel(self, job_id: str) -> JobRecord | None:
        record = self._jobs.get(job_id)
        if record and record.status in {"queued", "running"}:
            record.cancel_event.set()
            return record
        return record
