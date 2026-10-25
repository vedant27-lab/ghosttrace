# Decision Policy and Evidence Handling

## 1. Intent

The agent checks explicit deletion intent before processing identity or evidence. Explicit data-access, correction, account-recovery, and marketing-only requests take precedence over deletion-like words. English, Spanish, French, Portuguese, Italian, German, Dutch, Korean, Japanese, and Chinese deletion cues are recognized. This is a deterministic rule set, not a language model.

## 2. Identity

`IdentityResolver` matches the request email to a current email snapshot or an email value in `user_audit_log.csv` at or before `audit_at`. It then collects current and historical emails, phone numbers, email hashes, names, stable user IDs, and supporting audit IDs whose event times are within the cutoff. Values are normalized and matched exactly; identifiers are not matched by substring.

## 3. Evidence and time

`evidence_files.csv` is the allowlist for evidence. Evidence is extracted from JSON, SQLite-compatible SQL, logs, text, PDFs, and screenshots. Both the manifest capture time and any record-level observation time must be no later than the request's `audit_at`. SQL snapshots are executed in an in-memory SQLite database so primary and replica records can be inspected. Log entries are grouped by trace/request ID to connect a lookup key with its result line.

`system_activity.csv` is used to connect a subject with a resource when a `LINK_RESOURCE_IDENTITY` catalog event explicitly establishes that relationship. Activity events are not generally accepted as proof of a workflow's claimed success. The manifest `file_id`, `activity_id`, and `audit_id` are the permitted citation types.

## 4. Policy mapping

| Category | Policy treatment |
|---|---|
| User profile, secondary identifier, search index, cache, support attachment, user export, marketing profile | Delete if present |
| Shared support message | Redact identifying fields while preserving conversation context |
| Analytics profile / product telemetry | Anonymize when still attributable |
| Email delivery log | Redact email identifiers |
| Security audit log | Retain as required by the supplied retention rule |
| Legal-hold record | Retain when the hold is active |
| Account tombstone | Preserve the stable user reference and redact direct identifiers |
| Active data flow | Disable before dependent records are remediated |
| Backup archive with unblocked restore path | Block restore before changing dependent records |

The action planner only uses the challenge's allowed operations and states. It sorts findings, remediation, and verification by phase, then operation order, system ID, and resource ID. `output_validator.py` enforces this ordering and the empty evidence IDs required for future work.

## 5. Conservative behavior and known limitations

The evidence set sometimes does not provide an explicit link from a subject to an anonymized record or an absent resource's identifier. The agent does not invent a current-state finding in those cases. It returns `INCOMPLETE` and a future verification check rather than treating lack of evidence as proof of deletion. That fallback can use the stable subject ID as a lookup handle when no concrete resource ID is available; it is a planned check, not an observed resource.

The policy is deterministic and does not use an LLM. Public-sample evaluation shows that evidence association and completeness of resource-level verification remain the main improvement areas. The evaluation report states the measured metrics and these limitations rather than claiming hidden-answer accuracy.
