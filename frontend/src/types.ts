export type DeletionStatus = "COMPLETE" | "INCOMPLETE" | "NOT_APPLICABLE";

export interface Step {
  step_no: number;
  phase: string;
  system_id: string;
  resource_id: string;
  operation: string;
  state: string;
  evidence_id: string;
}

export interface CaseSummary {
  case_id: string;
  email: string;
  requested_at: string;
  audit_at: string;
  reported_status: string;
  deletion_status: DeletionStatus;
  request_excerpt: string;
  demo: boolean;
}

export interface CasePage {
  items: CaseSummary[];
  page: number;
  page_size: number;
  total: number;
  demo: boolean;
}

export interface EvidenceReference {
  evidence_id: string;
  origin: string;
  file_type: string;
  captured_at: string;
  source_path?: string | null;
}

export interface Observation {
  evidence_id: string;
  system_id: string;
  resource_id: string;
  data_category: string;
  observed_state: string;
  observed_at: string;
  captured_at: string;
  record: Record<string, unknown>;
}

export interface CaseDetail extends CaseSummary {
  explanation: string;
  identity_history: { field: string; value: string; source: string }[];
  evidence: EvidenceReference[];
  observations: Observation[];
  steps: Step[];
  warnings: string[];
}

export interface Summary {
  total_requests: number;
  status_counts: { complete: number; incomplete: number; not_applicable: number };
  generated_at: string;
  demo: boolean;
  dataset_available: boolean;
  evidence_files: number;
}

export interface EvidenceSummary {
  evidence_id: string;
  file_type: string;
  origin: string;
  captured_at: string;
  extraction_method?: string | null;
  has_extraction_error: boolean;
  matched_case_count: number;
  demo: boolean;
}

export interface EvidencePage {
  items: EvidenceSummary[];
  page: number;
  page_size: number;
  total: number;
  demo: boolean;
}

export interface EvidenceDetail extends EvidenceSummary {
  excerpt: string;
  extraction_error?: string | null;
}

export interface AuditJob {
  job_id: string;
  status: string;
  progress: number;
  cases_completed: number;
  total_cases: number;
  started_at: string;
  finished_at?: string | null;
  result?: Record<string, unknown> | null;
  error?: string | null;
  cancellable: boolean;
  demo: boolean;
}
