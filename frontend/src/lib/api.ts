import type {
  AuditJob,
  CaseDetail,
  CasePage,
  EvidenceDetail,
  EvidencePage,
  Summary,
} from "../types";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "http://localhost:8000").replace(/\/$/, "");

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(body || `Request failed with ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  baseUrl: API_BASE,
  summary: () => request<Summary>("/api/summary"),
  cases: (params: URLSearchParams) => request<CasePage>(`/api/cases?${params.toString()}`),
  caseDetail: (caseId: string) => request<CaseDetail>(`/api/cases/${encodeURIComponent(caseId)}`),
  evidence: (params: URLSearchParams) => request<EvidencePage>(`/api/evidence?${params.toString()}`),
  evidenceDetail: (evidenceId: string) => request<EvidenceDetail>(`/api/evidence/${encodeURIComponent(evidenceId)}`),
  startAudit: () => request<AuditJob>("/api/audits", { method: "POST", body: JSON.stringify({ use_available_dataset: true }) }),
  auditStatus: (jobId: string) => request<AuditJob>(`/api/audits/${encodeURIComponent(jobId)}`),
  cancelAudit: (jobId: string) => request<AuditJob>(`/api/audits/${encodeURIComponent(jobId)}`, { method: "DELETE" }),
  downloadUrl: (jobId: string) => `${API_BASE}/api/audits/${encodeURIComponent(jobId)}/download`,
};
