# Usage and runtime report

## Final full-dataset run

- Input requests processed: **518**
- Evidence manifest entries loaded: **94**
- Evidence extraction errors: **0**
- Output rows written: **518**
- Runtime processing exceptions: **0**
- Output validator errors: **0**
- Output validator warnings: **0**
- Output status counts: 40 `COMPLETE`, 468 `INCOMPLETE`, 10 `NOT_APPLICABLE`
- Measured warm runtime: **11.784 seconds** on Windows with Python 3.14.6.
- Reproducibility check: a second run produced the same SHA-256 output.

## Model and token usage

GhostTrace uses deterministic Python rules, local file parsing, SQLite, and local Tesseract OCR. It does not call an LLM provider or external inference API.

| Usage item | Total |
|---|---:|
| Model provider | None |
| Model name | Not applicable — no model invoked |
| Model calls | 0 |
| Input tokens | 0 |
| Output tokens | 0 |
| Total tokens | 0 |
| Average tokens per request | 0 |
| Estimated model/API cost | $0.00 |
| Estimated cost per request | $0.00 |

There are no per-model totals because no model was used. Tesseract OCR is a local executable; its compute cost is not an LLM/API token charge and is not included in the $0.00 model/API estimate.

## Dependency notes

Python dependencies are pinned by compatible upper/lower bounds in `requirements.txt`: pypdf, Pillow, pytesseract, and pytest. Tesseract itself is an external host prerequisite for full screenshot extraction. The pipeline records missing OCR/extraction errors instead of silently treating image evidence as compliant.
