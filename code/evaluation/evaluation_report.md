# Evaluation Report

## Scope and methodology

The public evaluation set contains 32 requests in `dataset/sample_deletion_requests.csv`, with expected answers in `dataset/sample_output.csv`. The prediction pipeline does not read `sample_output.csv`; the evaluation runner compares predictions with it after prediction. The full 518-request evaluation dataset has no participant-visible golden answers, so hidden-ground-truth accuracy cannot be measured locally.

## Public-sample metrics

Measured with the current deterministic implementation:

| Metric | Result | Definition |
|---|---:|---|
| Case-level deletion-status accuracy | **71.88% (23/32)** | Predicted status equals expected status |
| Exact row accuracy | **18.75% (6/32)** | Status and full ordered step sequence both match |
| Step-field accuracy | **69.90%** | Matching phase/system/resource/operation/state/evidence fields divided by all aligned step-field positions; missing steps count as incorrect |
| Exact sequence accuracy | **18.75% (6/32)** | Every step's phase, system, resource, operation, state, and evidence ID match in order |
| Expected sample steps | 193 | Total steps in the public expected answers |
| Predicted sample steps | 171 | Total steps produced for the same 32 cases |

The exact-row and exact-sequence percentages happen to be equal on this sample. These are measured results, not estimates of hidden-set accuracy.

## Full-dataset structural validation

The final `output.csv` was generated for all **518** requests and passed `code/output_validator.py`:

- Rows: 518, plus the header
- Header: `case_id,deletion_status,steps_json`
- Sorted by `case_id`
- Status counts: 40 `COMPLETE`, 468 `INCOMPLETE`, 10 `NOT_APPLICABLE`
- Invalid JSON arrays, missing/duplicate rows, illegal operation/state pairs, ordering errors, invalid evidence references, and cutoff violations reported by the validator: **0**
- Runtime processing exceptions: **0**

The validator establishes output-contract compliance, not hidden-answer accuracy. In particular, 104 incomplete cases have no observed policy-violation finding; they remain incomplete because the available evidence did not establish a compliant account-profile state or otherwise left verification unresolved. The implementation deliberately does not invent a present-state finding when no evidence supports it.

## Custom regression cases

Eight additional checks are implemented in `code/evaluation/main.py`:

1. English account-deletion wording is recognized as in scope.
2. Korean permanent-deletion wording is recognized despite Unicode normalization.
3. A marketing-only opt-out is classified `NOT_APPLICABLE`.
4. A request for a copy of account information is classified `NOT_APPLICABLE`.
5. Step ordering follows FINDING → REMEDIATION → VERIFICATION.
6. A historical email resolves to the stable subject using the audit log.
7. Exact user-ID matching does not confuse `user_18` with `user_189`.
8. Evidence captured after `audit_at` is excluded.

Result: **8/8 custom checks passed**.

## Failures found and improvements made

- **Intent classification:** Added explicit non-deletion precedence, normalized multilingual deletion cues, and preserved original Unicode text so Hangul is not lost during normalization.
- **Identity resolution:** Uses current and historical identifiers, including hashes, phone numbers, names, and stable IDs; exact matching avoids substring collisions.
- **Evidence coverage:** Added parsing for SQLite-compatible SQL snapshots, nested JSON, trace/request-grouped logs, PDFs, and OCR text from screenshots.
- **Temporal safety:** Filters manifest capture times and record observation times against each request's audit cutoff.
- **Recreation risks:** Handles active data flows and backup restore paths before dependent record remediation.
- **Output contract:** Enforces allowed operations/states, step numbering, phase/operation order, and evidence-ID rules.

## Remaining limitations

Public-sample exact-row performance remains low. Some expected sample resource IDs—particularly absent resources and already-anonymized records—are not directly linked to the subject by a visible identifier in the supplied evidence. The solution avoids hardcoding sample answers or inferring hidden resource IDs from case numbers. When evidence is insufficient, it conservatively emits `INCOMPLETE` and a future verification step rather than claiming deletion is complete. Resource association and verification completeness are the primary areas for further improvement.
