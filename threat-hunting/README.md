# Threat hunting and incident reconstruction

[Portfolio](../README.md) · [Detection engineering](../cyber-defense/README.md) · [Validation](../docs/local-validation.md)

This collection shows how to turn security events into a defensible account of what happened: establish data coverage, correlate independent sources, distinguish attempted actions from successful ones, and document uncertainty before proposing containment.

Two authorized investigations inform the work. Their original evidence and detailed reports remain private; the repository provides reusable methods, original queries, and sanitized execution summaries.

## Investigations and artifacts

| Work | Method and result | Read next |
|---|---|---|
| Web-server incident reconstruction | Completed investigation using seven event sources. Correlated HTTP activity with host execution, decoded request content as data, and assessed persistence, evasion attempts, and possible data transfer. Coverage gaps remained explicit. | [HTTP-to-host investigation method](investigation-method.md) |
| Windows endpoint investigation | Executed ten scoped KQL queries against authorized historical telemetry. Produced an evidence-linked timeline, incident analysis, and a proposed containment plan. The combined focus timeline contained 233 source rows, not 233 unique attacker actions. | [Defender query catalog and execution report](module-1/README.md) |

## Investigation workflow

1. Define the authorized device set, time window, hypothesis, and available event sources.
2. Check coverage before interpreting a missing result. Preserve query hashes, timestamps, row limits, and source event identifiers.
3. Correlate authentication, process, network, file, registry, account, and persistence evidence. Keep actor and target fields distinct.
4. Build a timeline and test alternative explanations. A shared alert is an investigation lead; it does not establish that every linked endpoint was compromised.
5. Propose a bounded response and recovery plan based on supported findings. Separate proposed actions from actions actually performed.

The [query catalog](module-1/README.md#query-index) covers each evidence category. All saved queries default to empty device scope and null time bounds; authorized values belong in a private execution copy. The [report structure](module-1/README.md#incident-report-structure) makes findings, uncertainty, provenance, and response decisions reviewable.

## From investigation to detection and response

The [authentication-sequence detector](../cyber-defense/README.md) and [Sentinel workbook](../cyber-defense/workbooks/README.md) demonstrate a separate, testable correlation use case. Their synthetic results do not establish that they detected these historical incidents. The [endpoint response report](../docs/endpoint-validation.md) records a separately authorized isolation/recovery exercise on the owned VM; no response was performed against the historical investigation endpoints.

Restricted answers, account names, internal addresses, raw telemetry, and private incident timelines are excluded. The detailed [execution limits](module-1/README.md#observed-execution-and-limits) remain part of the technical record.
