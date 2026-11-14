# Authentication sequence investigation

[Portfolio](../README.md) · [Sentinel workbook](workbooks/README.md) · [Investigation queries](../threat-hunting/module-1/README.md)

This detection-engineering project tests a specific hypothesis: repeated failed remote logons followed by a successful logon for the same device, domain, account, source and logon type deserve investigation. It combines original KQL, an independent Python reference model, synthetic regression cases, and an investigation workbook. Eight synthetic cases passed in Log Analytics; the results establish tested correlation behavior, not a deployed detection or an observed compromise.

## Implemented logic

[auth-sequence.kql](auth-sequence.kql) correlates at least five distinct failed events in the ten minutes before a success. It normalizes account/domain case, excludes missing correlation keys, preserves source and logon type, and deduplicates identical projected events. The lower time bound is inclusive; failures at or after the success are excluded. The join is explicitly `kind=inner`, retaining all matching success/failure pairs before aggregation. [Microsoft inner-join semantics](https://learn.microsoft.com/en-us/kusto/query/join-inner?view=microsoft-fabric).

Null time bounds and an empty approved-device list prevent useful execution until scoped. Confirm `LogonFailed` and `LogonSuccess` against actual telemetry. The required table columns were observed in the authorized Log Analytics schema; the owned VM had no authentication events in the checked interval. Run only in an authorized context; no detection rule or automated response is deployed. For a success near `Start`, the preceding lookback is incomplete unless the authorized window includes the needed ten minutes. Do not silently query outside the approved interval.

[auth_sequence.py](auth_sequence.py) is an independent, in-memory Python reference model. Tests cover the positive sequence, threshold, missing success, wrong identity/source/device/type, normalization, missing keys, duplicate events, reused ReportId, ordering, time boundaries and empty scope. Fixture identifiers are synthetic. Model tests establish the chosen temporal semantics; they **do not** parse or execute KQL or validate Defender schema and ingestion.

Run the shared local suite from the repository root:

```bash
python3 -B -m unittest discover -s tests -v
```

## Interpretation and validation

Correlation requires the same source IP and logon type, as well as the same device, domain and account. Failures split across source IPs or logon types are counted separately. Distributed or source-rotating brute-force activity may therefore evade this detector even when the combined number of attempts exceeds its threshold. This is a focused investigation lead, not comprehensive authentication-attack detection coverage.

An alert candidate may reflect mistyped credentials, stale service credentials, user retries, shared/NAT sources or approved automation. It may also miss local activity with no source address, missing telemetry, and attacks with fewer failures. Reused names, renames and SID changes need further identity checks. The same event identity with conflicting payloads needs source reconciliation; deduplication is not authenticity validation.

[kql_fixture.py](kql_fixture.py) renders an executable synthetic regression query using the **actual detector body**, replacing only its live source and scope parameters. It includes eight labeled positive/negative cases, an unscoped device, exact/beyond lookback boundaries and duplicate events. The generated query compares expected versus actual row counts and returns a `Passed` column. Render locally without submitting anything:

```bash
python3 -B cyber-defense/kql_fixture.py
```

On November 13, 2026 UTC, all **eight synthetic cases passed** in an explicitly authorized Log Analytics service with no query errors. The submitted query used only synthetic datatables and the actual detector body; it read no live source tables. Evidence alias `EV-KQL-SYNTHETIC-RUNTIME-20261113` preserves the query, response and digests privately; query SHA-256: `4dc8a7badf7488b15a1f56ca1967d7e6d5dec60e1f54343ed0b60a99daaa1e55`. Positive and boundary cases returned one match each; below-threshold, duplicate, late, outside-window, source-mismatch and unscoped cases returned none.

This establishes the tested KQL semantics in Log Analytics, not live ingestion, production coverage or an observed attack. Subsequent metadata-only checks confirmed the required columns in the authorized Log Analytics workspace; this is distinct from Defender portal access. Execute the actual live-table query only in a separately authorized, bounded telemetry window, recording coverage, warnings, false positives and analyst decisions. No detection rule or response was deployed. Do not turn a hypothesis into a production threshold without a baseline and review.

Use the [Defender investigation queries and report structure](../threat-hunting/module-1/README.md) to reconstruct the logon, process, network, file and persistence context. Retain event provenance and distinguish correlation from causation. A successful authentication after failures is an investigation lead, not proof of credential theft or lateral movement.

## Safe response decision record

| Decision | Required evidence and boundary |
|---|---|
| Continue investigation | Confirm device/account ownership, authorized scope, source data coverage and benign explanations. Preserve minimal evidence with query hashes and UTC capture times. |
| Propose account containment | Identify the affected account and owner, supported malicious activity, dependencies and approval authority. Credential reset/revocation is not automated here. |
| Propose endpoint containment | Identify the precise owned VM, incident severity, management/scanner impact, approved access path and recovery plan. Do not isolate shared assets or modify rules from this package. |
| Validate recovery | After separately authorized response, observe the same VM's identity, security controls, access and required telemetry. A quieter event stream alone does not prove recovery. |

Any later study involving an exposed service requires separate scope, exposure, monitoring, response and same-VM recovery approval. This package performs analysis only; it does not expose RDP, disable security controls, generate attack traffic, or install a telemetry agent.

## Investigation workbook

The [Sentinel workbook](workbooks/README.md) adds five operational panels around this detector: coverage, trends, sources, candidate sequences and event context. All five generated synthetic queries passed service execution and expected-result checks. Its default artifact contains no live workspace or device identifiers. One approved synthetic workbook is deployed and visually validated, including full-range and empty-window behavior. No live detector or automated response is claimed.
