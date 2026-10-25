# Usage and Token Report

## Final full-dataset run

- Input requests processed: **518**
- Evidence manifest entries loaded: **94**
- Output rows written: **518**
- Runtime processing exceptions: **0**
- Output validator errors: **0**
- Output status counts: 40 `COMPLETE`, 468 `INCOMPLETE`, 10 `NOT_APPLICABLE`

## Model and token usage

This implementation uses deterministic Python rules, local file parsing, SQLite, and local Tesseract OCR. It does not call an LLM provider or external inference API.

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

## Runtime note

The final 518-request processing loop completed in 21.4 seconds with evidence already loaded and extraction caches warm. Evidence extraction/OCR is the variable part of a cold start and depends on the host's CPU, installed Tesseract version, and image quality. A single cold-start end-to-end timing was not recorded for the final package, so no precise cold-start runtime is claimed.
