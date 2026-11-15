# Technical methodology

[Portfolio](../README.md) · [Project status](project-progress.md) · [Validation](local-validation.md)

Start with a scoped question or finding. Record what changed, how it was checked and where the evidence is stored.

## Common workflow

1. Confirm the permitted asset, data, actions and execution window. Save the authorization privately.
2. Capture the baseline, software versions, UTC time and available data. Define success before making changes.
3. Implement with clear inputs, prerequisite checks, error handling and recovery. Attribute any permitted adaptation.
4. Run the relevant tests and platform checks. Record failures and incomplete results.
5. Preserve the source, results and hashes. Write a short report with the remaining limits.
6. Record review by version and scope. Keep publication approval separate.
7. Update the project status and private evidence ledger.

## STIG remediation

Confirm the Windows edition, benchmark revision, exact rule and policy owner. Select an applicable failed control from the authenticated assessment. Leave already-passing settings intact.

Each package includes remediation, a read-only verifier, tests and recovery instructions. Run the parser and mocked tests first. On the approved Windows VM, capture the original state and inspect the preview. Apply only the authorized changes with private snapshots.

Record `Status`, `Changed` and the exit code together. Verify the stored value, repeat behavior, relevant feature effects and recovery. Schedule any sign-in, policy refresh or reboot separately.

Use a comparable authenticated Tenable assessment for the follow-up. Retain the exact control result, audit revision, coverage and authentication evidence. Document revision differences before comparing results. The [evidence workflow](../stig-remediations/evidence-workflow.md) defines the record format.

## Threat hunting

State whether the source is generated test data, historical training telemetry or current operational data. Record the hypothesis, device, UTC window, platform, schema and retention.

Begin with coverage checks. Keep device and time filters in every query. A query error, an empty result and a partial response need different follow-up. Preserve warnings and collection limits.

Correlate events using their source identifiers, timestamps and process context. Test plausible benign explanations. Describe attempted actions and confirmed outcomes precisely. Request scope expansion before investigating another endpoint.

Build a timeline and report with query hashes, evidence references, findings and open questions. Proposed containment needs a separate approval and recovery plan. Keep instructor answers and gated solutions out of source, fixtures and reports.

## Security automation and AI experiments

Build automation around a concrete task. Define permitted inputs, actions, error paths and repeat behavior. Test scope rejection and partial failures before allowing live operations.

For an AI experiment, define the threat model, data permissions, baseline and evaluation criteria. Keep held-out answers separate from development. Record the model version, settings, inputs and measured outcomes. Review the implementation and its claims before publication.

## Status and evidence standards

| Status | Meaning |
|---|---|
| Unverified | Supporting evidence has not been established. |
| Proposed | Scope, feasibility or selection remains open. |
| Planned | Work is identified; execution and evidence are pending. |
| In progress | Authorized work has begun. |
| Tested | Specified checks ran and their outcomes were recorded. Inspect the result to see whether they passed. |
| Verified | Observed evidence meets the stated criteria in the tested environment. |

Record independent review as pending, changes requested or reviewed, with the version, reviewer, date and findings. An operator waiver has its own record. Publication approval and external acceptance also need separate records.

The [validation record](local-validation.md) lists local tests, Windows execution, Tenable assessments and KQL results. Evidence tools check the supplied metadata; the original source records still need review.

## Shared-environment safety

Preserve the same VM. Confirm its identity before each operation and keep management recovery available. Do not replace it or create another VM as a routine lab step.

Operate only on approved assets. Shared visibility does not grant permission to scan, isolate or change another participant's system. Stop on denied access.

Cloud operations, scans, security changes, installations and response need authorization. Keep Windows Firewall and endpoint protection enabled. An exposure exercise needs a defined window, monitoring and recovery plan.

Confirm shutdown and inactivity-purge behavior. Keep authorized evidence outside the VM so loss of the VM cannot erase the record.

## Confidentiality and publication

Store raw evidence in approved private storage. Use stable evidence aliases and UTC timestamps in reports. Keep credentials, tenant identifiers, raw telemetry, course documents, answer keys and administrative records out of Git.

`Planning/` is ignored and requires explicit access authorization. Screenshots and attachments are also ignored by default. To publish a sanitized image, inspect its content and metadata, record its source, then add only the approved exact path to the allowlist. Review text and data files for disclosure as well.

`.gitignore` reduces accidental staging. It cannot protect material that was force-added or already tracked. Review the proposed changes before any authorized commit, push or public release.

Later NCyTE reuse requires approved original material, attribution and validation in that separate project.
