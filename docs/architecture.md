# GhostTrace architecture

## Decision flow

1. Load the request and reject non-deletion intent before resolving evidence.
2. Resolve the supplied email against the current snapshot and historical audit events at or before `audit_at`.
3. Load the evidence manifest once. Each document retains its `file_id`, capture time, parser method, and extraction error.
4. Reconstruct only observations whose document capture time and record observation time are eligible for the request cutoff.
5. Collapse duplicate views of the same `(system_id, resource_id, data_category)` to the latest eligible state, preferring the more severe state at the same timestamp.
6. Map each observed violation to an allowed finding, remediation action, and verification operation.
7. Sort by phase, operation, system, and resource, then number steps consecutively.
8. Validate the resulting CSV independently of the predictor.

## Evidence provenance

The evidence loader supports JSON, SQLite-compatible SQL, line-oriented logs, text/CSV, PDFs, and OCR-backed image files. The manifest is treated as an allowlist and paths are checked so an entry cannot escape the dataset directory. A catalog activity link is used only as an identity bridge; it is not itself treated as proof that the linked resource is currently present.

## Temporal safety

The request’s `audit_at` is the decision cutoff. Manifest capture timestamps, record timestamps, log line timestamps, and SQL row timestamps are all checked independently where available. A later observation cannot turn an earlier deletion into a failure or prove a state that did not exist at the cutoff.

## Conservative behavior

The engine fails closed on ambiguous identity resolution and malformed evidence. It does not turn a missing record into a positive deletion finding unless the evidence explicitly establishes the resource and its absent state. This trades some recall for traceability and avoids fabricating resource IDs or evidence references.

## Verification boundary

Observed findings use participant-visible evidence IDs. Remediation and post-remediation verification are plans, so their evidence IDs remain empty. Complete cases are allowed to contain only verification steps with eligible evidence, matching the challenge contract.

## Web application boundary

The FastAPI layer in `backend/` indexes requests and output rows, delegates case reconstruction to the existing engine, and owns the single-flight background job lifecycle. Pydantic response models define the API contract consumed by the frontend. The React/Vite application in `frontend/` renders those responses and never makes policy decisions itself.

Evidence is sanitized before it crosses the API boundary: direct identifiers are masked, document text is excerpted, and file paths are reduced to manifest-safe names. The current job state is in memory and job output snapshots are local under `.runtime/`; this is suitable for a local demo but must be replaced with durable storage for a multi-instance deployment.
