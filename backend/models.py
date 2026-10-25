from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class DeletionStatus(str, Enum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class StepModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step_no: int
    phase: str
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str


class IdentityHistoryItem(BaseModel):
    field: str
    value: str
    source: str


class EvidenceReference(BaseModel):
    evidence_id: str
    origin: str = ""
    file_type: str = ""
    captured_at: str = ""
    source_path: str | None = None


class ObservationModel(BaseModel):
    evidence_id: str
    system_id: str
    resource_id: str
    data_category: str
    observed_state: str
    observed_at: str
    captured_at: str
    record: dict[str, Any] = Field(default_factory=dict)


class CaseSummary(BaseModel):
    case_id: str
    email: str
    requested_at: str
    audit_at: str
    reported_status: str
    deletion_status: DeletionStatus
    request_excerpt: str
    demo: bool = False


class CasePage(BaseModel):
    items: list[CaseSummary]
    page: int
    page_size: int
    total: int
    demo: bool


class CaseDetail(CaseSummary):
    explanation: str
    identity_history: list[IdentityHistoryItem] = Field(default_factory=list)
    evidence: list[EvidenceReference] = Field(default_factory=list)
    observations: list[ObservationModel] = Field(default_factory=list)
    steps: list[StepModel] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class StatusCounts(BaseModel):
    complete: int
    incomplete: int
    not_applicable: int


class SummaryResponse(BaseModel):
    total_requests: int
    status_counts: StatusCounts
    generated_at: str
    demo: bool
    dataset_available: bool
    evidence_files: int


class EvidenceSummary(BaseModel):
    evidence_id: str
    file_type: str
    origin: str
    captured_at: str
    extraction_method: str | None = None
    has_extraction_error: bool = False
    matched_case_count: int = 0
    demo: bool = False


class EvidencePage(BaseModel):
    items: list[EvidenceSummary]
    page: int
    page_size: int
    total: int
    demo: bool


class EvidenceDetail(EvidenceSummary):
    excerpt: str
    extraction_error: str | None = None


class AuditRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    use_available_dataset: bool = True


class AuditJob(BaseModel):
    job_id: str
    status: str
    progress: int = Field(ge=0, le=100)
    cases_completed: int
    total_cases: int
    started_at: str
    finished_at: str | None = None
    result: dict[str, Any] | None = None
    error: str | None = None
    cancellable: bool = False
    demo: bool = False
