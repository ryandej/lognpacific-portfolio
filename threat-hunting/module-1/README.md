# Windows endpoint investigation with Defender KQL

[Portfolio](../../README.md) · [Investigations](../README.md) · [Query index](#query-index) · [Execution results](#observed-execution-and-limits)

Ten original Defender KQL queries support scoped investigation and incident reconstruction. All ten executed successfully against an authorized historical Cyber Range dataset. The work produced an evidence-linked timeline, incident analysis and containment proposal. Restricted findings, event identities, captured values and detailed reports are retained privately; this repository provides the queries, method and sanitized execution record.

## Scope and execution

Use Microsoft Defender Advanced Hunting with authorized Defender for Endpoint telemetry. On November 13, 2026 UTC, all ten queries executed successfully in the authorized Log Analytics workspace with their original null bounds and empty device scopes, returning zero rows. This validates binding to that workspace's current schemas and fail-closed execution, not the assigned incident, Defender Graph authorization or compatibility with every workspace.

Every query starts with null UTC bounds and an empty `DeviceScope`, producing no matching rows by default. In a private query copy, set an explicit half-open window `[Start, End)` and the approved **DeviceId** list. Never remove the scope filter to discover other participants' devices. Obtain any scope expansion before pivoting. Results, commands, registry data, account names, URLs and addresses remain private.

1. Record authorization, hypothesis, device scope, UTC window, retention and onboarding status. Distinguish synthetic data, course telemetry and authorized live observations.
2. Run [coverage](queries/00-coverage.kql) first. Compare returned table/action counts and observed time ranges with the authorized incident window. A missing table is a prerequisite failure; an empty table is not proof that an action did not occur. Confirm action meanings in the portal's schema reference.
3. Follow the relevant queries below. Save query SHA-256, private parameter values, execution time, service result status, row counts and truncation/warnings in the evidence manifest. Do not treat a partial result as complete. Split large windows into nonoverlapping intervals and document gaps and any aggregation.
4. Correlate by device and process creation time plus process ID; PID alone can be reused. Distinguish file hashes by algorithm and do not equate missing hashes. Parent-process properties describe the parent, not the created process. Equal timestamps or shared names alone do not establish causation.
5. Construct the evidence-linked timeline and incident scope, test benign explanations, record unresolved branches, and obtain independent review. Scope boundaries and retention constrain any statement about unaffected devices.

## Query index

| Query | Question and interpretation limit |
|---|---|
| [00 Coverage](queries/00-coverage.kql) | Which tables/actions and time ranges are present? Presence is not complete coverage. |
| [01 Authentication](queries/01-authentication.kql) | Who attempted access, from where, with what outcome and logon type? Confirm outcome semantics before counting. |
| [02 Processes](queries/02-processes.kql) | Which administrative binaries or encoded-command indicators deserve review? Legitimate use is common; this is a focused filter, not exhaustive detection. |
| [03 Network](queries/03-network.kql) | Which destinations and initiating processes were observed? An event does not automatically prove a session, download or exfiltration. |
| [04 Files](queries/04-files.kql) | Which files changed, with which hashes/origins? Creation does not prove execution; empty SHA256 is common. |
| [05 Registry](queries/05-registry-persistence.kql) | Were common persistence-related locations modified? A write is not proof persistence executed; coverage is deliberately partial. |
| [06 Tasks/services](queries/06-tasks-services.kql) | Were creation commands invoked? Corroborate with events/state; API/WMI and other creation methods may be missed. |
| [07 Accounts/privileges](queries/07-accounts-privileges.kql) | Which account/group events or administrative commands occurred? Validate event payloads; actor fields may differ from the affected account. |
| [08 Potential lateral movement](queries/08-lateral-movement.kql) | Did scoped devices contact administrative-service ports? Ports alone do not establish movement or authorize inspection of destinations. |
| [09 Timeline](queries/09-timeline.kql) | How do recorded events align across sources? Retain source table, device, timestamp and ReportId; inspect full source rows for details. |

For task/service and account outcomes, corroborate the process candidates with scoped `DeviceEvents` action types discovered by query 00 and, when separately authorized, read-only host state or Windows auditing. Do not invent action names or assume a generic `AdditionalFields` key exists. This package deliberately contains no confidential scenario answers, expected flags, or predetermined incident timeline.

## Incident report structure

The private investigation uses this structure; future investigations must derive their own findings:

1. Objective, context, authorized scope, hypothesis and UTC window.
2. Data availability: onboarding, tables, retention, missing events, clock uncertainty, query limits and export completeness.
3. Reproducibility: repository revision/file hashes, query names and parameters held privately, execution records, evidence aliases and provenance/digests.
4. Findings: each claim, observed source event, actor versus target, attempted versus confirmed action, confidence, alternative explanation and remaining check.
5. Timeline: UTC timestamp, asset alias, source, event identity, observed behavior, evidence alias and confidence. Keep causal inference separate from timestamp order.
6. Scope: affected assets/accounts supported by evidence, permitted scope boundaries, unknowns and reasoned potential impact.
7. Response proposal: owner, authorization needed, evidence to preserve, least disruptive action, management risks, rollback and same-VM recovery. Identify affected accounts, supported network indicators and each observed persistence artifact from actual evidence. Clearly mark actions proposed versus actually executed; explain the selected detection point and separate containment planning from an executed response.
8. Validation/review: synthetic tests, service execution results, independent review, limitations, disclosure decision and next investigation steps.

The [authentication sequence package](../../cyber-defense/README.md) supplies a concrete temporal-correlation exercise and safe response decision record. Its Python model and observed synthetic Log Analytics execution validate separate layers; neither establishes this incident's Defender schema or findings.

## Observed execution and limits

The earlier Graph request returned 403 and remains an access limitation for that API. The authenticated course workspace selector subsequently identified the correct data destination. Existing authorized Log Analytics access retrieved the assigned endpoint's historical records; no permission bypass or broad device inventory was used.

All ten reviewed queries executed with fixed device identity and the source-prescribed focus window. The combined timeline returned 233 source rows; this is not a count of unique attacker actions. The source's separate, wider UTC scaffold was needed to recover initial-access events outside the narrow focus window. Keep both intervals and their purpose in the private report rather than calling the narrower empty authentication result a clean host.

The investigation documents ten observed values or command artifacts and one explicitly qualified alert-linked endpoint lead. A shared alert linked multiple endpoints, so association alone does not prove a unique second compromise or lateral movement. Only names, alert identifiers and timestamps were collected for that approved scope extension; no peer's raw telemetry or host state was inspected. Task/service creation commands remain distinct from confirmed installed state. Account creation and a registry write have corroborating event evidence. No response was executed on course hosts.

Private evidence alias `EV-MODULE1-V17` preserves query/result hashes, UTC receipts, collection limits, captured values, D1 containment and D2 incident analysis. One earlier collection hit its row cap and is not treated as exhaustive. A later source extraction crossed into an instructor section of a mixed document; the exception is disclosed privately and prevents an unqualified blind-review claim. No instructor text is reproduced here or used as evidence for the findings. The reports cite previously collected telemetry and retain uncertainty even where the exercise may expect a specific answer.

For future execution, confirm workspace identity, retention, assigned device and current schema. Do not remove scope filters or substitute another workspace without authorization. Empty-scope tests, synthetic detector tests, historical investigation, current endpoint ingestion and independent review establish different things. The [web-server investigation](../investigation-method.md) has a separate dataset and evidence record.

## Public technical references

Column selection follows Microsoft's tables for [logons](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table), [processes](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table), [network events](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table), [file events](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table), [registry events](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table) and [general device events](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table). Check the deployed portal schema and permissions before execution. Document any necessary adaptations and rerun their tests.
