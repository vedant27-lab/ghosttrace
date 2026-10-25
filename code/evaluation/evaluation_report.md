# Evaluation report

## Scope and methodology

The public evaluation set contains 32 requests in `dataset/sample_deletion_requests.csv`, with expected answers in `dataset/sample_output.csv`. The prediction pipeline does not read `sample_output.csv`; the evaluation runner compares predictions with it after prediction. The full 518-request evaluation dataset has no participant-visible golden answers, so hidden-set accuracy cannot be measured locally.

Metrics are computed by `code/evaluation/main.py`:

- Status accuracy: matching `deletion_status` per case.
- Exact-row accuracy: matching status and every ordered step field.
- Exact sequence accuracy: matching every ordered step regardless of status.
- Aligned step accuracy: matching the six normalized step fields at the same position, with missing steps counted incorrect.
- Step-field accuracy: matching each of `phase`, `system_id`, `resource_id`, `operation`, `state`, and `evidence_id` at aligned positions.

## Baseline versus final public-sample results

The baseline was reproduced before changes with the original implementation. The final run used the same participant-facing sample and evaluator after the evidence-semantics fixes.

| Metric | Baseline | Final | Change |
|---|---:|---:|---:|
| Case-level deletion-status accuracy | 71.88% (23/32) | 71.88% (23/32) | 0.00 pp |
| Exact row accuracy | 18.75% (6/32) | 18.75% (6/32) | 0.00 pp |
| Exact ordered sequence accuracy | 18.75% (6/32) | 18.75% (6/32) | 0.00 pp |
| Aligned step accuracy | Not measured | 53.57% | New metric |
| Step-field accuracy | 69.90% | 69.98% | +0.08 pp |
| Expected sample steps | 193 | 193 | — |
| Predicted sample steps | 171 | 170 | -1 |

The unchanged exact-row score is expected: several public cases contain global evidence where a resource ID has no participant-visible subject link. GhostTrace deliberately does not infer ownership from case numbering, filenames, or a workflow claim.

## Full-dataset structural validation

The final `output.csv` was generated for all 518 requests and passed `code/output_validator.py`:

- Rows: 518, plus the exact header `case_id,deletion_status,steps_json`.
- Sorted by `case_id`.
- Status counts: 40 `COMPLETE`, 468 `INCOMPLETE`, 10 `NOT_APPLICABLE`.
- Invalid JSON arrays, missing/duplicate rows, illegal operation/state pairs, ordering errors, invalid evidence references, and cutoff violations: 0.
- Runtime processing exceptions: 0.
- Repeated-run SHA-256 comparison: identical output (`23A7A5FD70CE7B0ABBAF2F92D232FA6C8CADA3BB74EE93944092F6A0EFA3143F`).

Structural validation establishes output-contract compliance, not hidden-answer accuracy.

## Custom regression cases

Eight deterministic checks run independently of sample answers:

1. English account-deletion wording is recognized as in scope.
2. Korean permanent-deletion wording is recognized despite Unicode normalization.
3. A marketing-only opt-out is `NOT_APPLICABLE`.
4. A request for a copy of account information is `NOT_APPLICABLE`.
5. Step ordering follows `FINDING` → `REMEDIATION` → `VERIFICATION`.
6. A historical email resolves to the stable subject using the audit log.
7. Exact user-ID matching does not confuse `user_18` with `user_189`.
8. Evidence captured after `audit_at` is excluded.

Result: **8/8 custom checks passed**. The pytest suite adds eight focused tests for the same risk areas plus attachment classification, catalog-link semantics, malformed JSON, tombstone redaction, and step evidence rules.

## Failures found and improvements made

- **Attachment policy error:** explicit support attachment evidence was previously classified as a shared support message because OCR text contained ticket/context words. Explicit attachment metadata now takes precedence and maps to deletion.
- **Activity semantics error:** `LINK_RESOURCE_IDENTITY` rows were previously emitted as present resource observations. They now establish ownership only; a state observation requires a participant-visible evidence document.
- **Text matching gap:** generic text evidence now recognizes exact email, phone, user-ID, and linked resource-ID matches instead of treating every lookup field as an email.
- **Execution reliability:** generator and validator accept explicit paths, use the repository location for defaults, and keep output deterministic across repeated runs.
- **Testing/documentation:** added `requirements.txt`, `.gitignore`, pytest coverage, architecture documentation, and resume-ready project documentation.

## Remaining limitations

The primary accuracy limitation is evidence association for global snapshots that contain absent or anonymized resource IDs without an explicit subject link. The engine returns a conservative incomplete plan rather than inventing a finding or citing an unsupported evidence ID. OCR availability and image quality can also affect the evidence surface; extraction failures are retained as diagnostics.
