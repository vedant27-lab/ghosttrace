# Resume project entry

## One-line description

GhostTrace is a full-stack privacy-deletion audit application that exposes a deterministic evidence engine through a typed FastAPI API and a React/Vite operations console.

## Resume bullets

- Built a Python evidence pipeline for JSON, SQLite snapshots, logs, PDFs, text, and OCR screenshots, with manifest validation, timestamp cutoffs, and provenance-preserving observations.
- Implemented a typed FastAPI backend with paginated case/evidence APIs, sanitized excerpts, CORS/rate/request-size controls, and single-flight cancellable audit jobs.
- Built a responsive React/TypeScript/Vite/Tailwind console with status analytics, case and evidence exploration, audit progress, CSV download, Vitest coverage, and a reproducible 518-request engine run.

## Technology stack

Python 3.11+, FastAPI, Uvicorn, Pydantic, `csv`, `json`, `sqlite3`, pypdf, Pillow, pytesseract, and pytest; React, TypeScript, Vite, Tailwind CSS, Recharts, Lucide, Vitest, and Testing Library. No external model provider or paid API is used.

## Verified results

On the 32-case public sample, the current implementation measured 71.88% status accuracy, 18.75% exact-row accuracy, 18.75% exact ordered-sequence accuracy, and 69.98% aligned step-field accuracy after the attachment and catalog-link fixes. The full request run generated 518 rows and passed structural validation with zero runtime exceptions in the recorded run.

These figures are sample measurements, not hidden-set performance claims. The main remaining limitation is evidence association when global snapshots omit an explicit link between a resource ID and the requested subject.

## Interview explanation

The architecture separates identity resolution, evidence loading, state reconstruction, policy evaluation, planning, validation, API orchestration, and UI rendering. The important trade-off is conservative evidence use: a workflow’s `COMPLETE` status or a deletion activity is not accepted as proof, and future evidence is excluded by timestamp. That improves auditability and prevents fabricated citations, but it can lower exact-row recall when the participant-visible evidence is intentionally ambiguous. The web layer adds a privacy boundary by masking identifiers before evidence reaches the browser, while preserving the backend as the sole source of audit decisions.
