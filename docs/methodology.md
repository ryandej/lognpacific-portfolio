# Technical methodology

Every work item should connect an authorized engineering objective to a reproducible method, observed results, supporting evidence, and an explicit status. Reference examples establish neither the operator's results nor permission to execute their steps.

## Common workflow

1. **Confirm authorization and scope.** Identify the objective, permitted asset and data, allowed actions, reviewer, and evidence restrictions. Verify actual access and applicable terms before operating in the range. Record permission privately and use a non-sensitive reference in the report.
2. **Establish a baseline.** Record relevant software and policy versions, UTC time, initial state, and data coverage. Define the success criteria and capture only the evidence needed for the claim.
3. **Implement and document.** Write original code or queries with clear inputs, prerequisites, expected behavior, failure handling, and rollback or recovery considerations. Attribute permitted adaptations.
4. **Verify.** Observe local checks and the relevant platform results. Identify which checks were run, on what version, and with what outcome. Expected output is not an observed test result.
5. **Preserve evidence and limitations.** Link findings to approved artifacts or private evidence references. State gaps, unsuccessful checks, uncertainty, and remaining risk.
6. **Obtain independent review.** Have Claude review the implementation, tests, evidence, scope, attribution, and claims independently. Record the reviewed revision or file hashes, findings, and their disposition. The human operator verifies results and approves subsequent Git actions.
7. **Update project progress.** Record the implementation status, actual test outcomes, security-platform validation, evidence links, and independent-review outcome separately. Identify the next unresolved dependency.

## Windows 11 STIG remediation

Use one work item per distinct control. Its report should include the STIG/rule identifier, control purpose, benchmark revision, official reference, Windows build, PowerShell version, pseudonymous asset, prerequisites, and evidence references.

1. Confirm the control is applicable and its change will not disrupt management access, Defender, Tenable, telemetry, or later exercises. Define rollback before changing state.
2. Record local configuration and the authorized Tenable baseline audit result. Capture the actual policy/benchmark version, finding status, and UTC time. Keep raw scan identifiers and target details in private evidence. An empty or incomplete scan does not prove compliance.
3. Document the manual remediation and observed local and Tenable validation. If an approved test includes reverting a change and rescanning, do so only when explicitly authorized and safe. Otherwise agree on an alternative test method with the operator and reviewer. Do not weaken an already-passing control merely to manufacture a failure.
4. Implement original `remediate.ps1` code with appropriate preconditions, error handling, repeat-run behavior, and rollback guidance. Keep secrets and actual tenant or asset identifiers out of source. Preserve prior configuration privately when needed for rollback.
5. Provide read-only `verify.ps1` checks and meaningful tests beside the script. Test relevant success/failure paths and idempotence. Local tests must not change the coordination workstation; configuration-changing execution belongs on the authorized VM. Record any pending reboot or policy refresh.
6. Run the authorized follow-up Tenable audit and compare the same applicable control and benchmark. Record the observed result even when it fails or remains unassessed. Passing unit tests or local checks does not establish a Tenable pass.
7. Write a concise finding, change, and result report. Include side effects, limitations, independent-review findings, sanitized evidence references, disclosure status, and the corresponding project-progress item.

Reference materials may use different STIG revisions. Record the version actually used rather than silently equating results across revisions. Copied templates and their example results do not constitute an implementation or validation.

## Threat-hunting investigations

Identify whether an investigation uses training data, synthetic fixtures, or authorized live telemetry. Keep that context explicit in findings and any claims about detection coverage.

1. State the hypothesis or initiating alert, authorized scope, UTC window, and query platform: Defender Advanced Hunting or Sentinel/Log Analytics. Confirm actual tables, retention, permissions, and relevant data coverage.
2. Write original KQL with explicit time and permitted-asset restrictions. Use placeholders or parameters for sensitive identifiers; resolve them only in the authorized execution context. Do not assume a query or schema works unchanged across platforms.
3. Validate relevant query logic, join keys, timestamp handling, and false-positive cases. Use clearly labeled synthetic positive and negative cases when useful. Record their expected and observed results separately from live execution.
4. Execute only within approved scope and retain the minimum permitted evidence. A query error, unavailable data, and zero matching records are different results. None alone establishes that compromise did not occur.
5. Build an evidence-linked timeline and describe supported findings, alternatives, and confidence. Distinguish attempted activity from successful actions, and proposed containment from executed containment. Map behaviors only when supported by evidence.
6. Review the queries, findings, and disclosure boundaries independently. Record the tested environment, execution evidence, review findings, and limitations in the report and progress index. A saved query or proposed rule does not establish a deployed or validated detection pipeline.

Do not copy instructor answers, gated hints, or expected solutions into reports, tests, or AI evaluation inputs. Validate example query semantics and timelines independently.

## Security automation and AI experiments

Select a concrete objective before building automation. Define inputs, allowed actions, preconditions, error handling, and meaningful tests. Keep operations bounded to the authorized environment; do not introduce tenant access or scheduled actions without approval.

For a proposed AI security experiment, define the threat model, data permissions, baseline, evaluation criteria, and failure cases before implementation. Use authorized or synthetic data, keep held-out evaluation answers separate from system development and model inputs, and record the implementation/model version, settings, inputs, and actual trial outcomes needed to reproduce the assessment. Require independent review of both the experiment and its claims. A design, prompt, or successful example alone does not establish a reliable system or security improvement.

## Status and evidence standards

| Status | Meaning |
|---|---|
| Unverified | Implementation or supporting evidence has not been established. This does not assert that no work occurred. |
| Proposed | A candidate engineering activity whose scope, feasibility, or selection is unresolved. |
| Planned | Intended work is identified; detailed scope, execution, and evidence remain outstanding. Planning does not authorize execution. |
| In progress | Authorized development or investigation has begun, with remaining steps recorded. |
| Tested | Specific checks were executed and their outcomes recorded. Tests may have failed; this status does not imply success or completeness. |
| Verified | Observed evidence supports the stated technical criteria in the documented environment, including platform validation where applicable. This does not imply broader coverage or production deployment. |

Track independent review separately as pending, changes requested, or reviewed, with the reviewer, artifact version, date, and findings. A review records its outcome; it is not automatically an approval or a substitute for executed tests. Claim independent validation only when the required evidence has been reviewed and relevant findings resolved. Record publication permission separately from technical status.

Update the [project tracker](project-progress.md) after each work item. No report should label a test passed unless that outcome was observed.

## Shared-environment safety

- Use the same participant-owned VM throughout. Never create a second VM, delete/recreate the VM, or reset the resource group as an ordinary transition between labs. Verify whether an existing VM is present before considering any deployment.
- Verify the assigned resource scope and effective permissions. Shared visibility is not authorization to scan peers, export their records, isolate their endpoints, or modify shared resources.
- Obtain explicit approval for cloud operations, scans, configuration changes, installations, role changes, exposure, containment, and recovery. A read-only operation in a cloud service still requires authorized scope. Do not automate tenant access through this repository without separate approval.
- Prefer the current approved management-access method and preserve security controls. Do not adopt legacy public-access or firewall-disablement instructions as a default baseline.
- Before any honeypot study, approve its engineering objective, scope, exposure window, monitoring, containment, and same-VM recovery plan. Separately authorize exposure and containment. Document the resulting investigation and recovery with evidence.
- Confirm shutdown and inactivity-purge behavior; existing descriptions conflict. Do not assume portal viewing preserves the VM. Keep necessary authorized evidence outside the VM, in an approved store, so a purge does not erase the record.

## Confidentiality and publication review

Keep raw evidence in a separately approved, access-controlled store outside this repository. Do not create that store or export data without authorization. Use stable, non-sensitive evidence references and UTC timestamps; record capture provenance privately. Repository artifacts may contain original code, reports, synthetic fixtures, and separately approved sanitized derivatives.

Never place credentials, MFA material, sensitive tenant/resource identifiers, raw telemetry or scan exports, peer information, confidential course documents, instructor solutions, or personal administrative records in Git. `Planning/` remains local-only and ignored; do not inspect or alter its contents without explicit authorization. Do not send confidential evidence to external tools or models without permission.

Screenshots, Office documents, PDFs, and common attachment formats are ignored by default. For an approved sanitized artifact, review its content, background details, metadata, and provenance. Obtain LOG(N) disclosure permission and human approval, then add an exact-path `.gitignore` exception under the relevant work item's evidence directory. Use a path whose parent directories are not ignored; do not whitelist a whole evidence directory or force-add raw/private material. This review process applies to text and data files too, even when their extensions are not ignored.

Private GitHub visibility does not authorize an upload. `.gitignore` reduces accidental staging but does not inspect file contents, prevent forced staging, or protect files already tracked. Human disclosure review must precede any authorized staging, commit, push, or public release.

Later reuse in a separate NCyTE-aligned project requires approved original material, attribution to its LOG(N) origin, separate history, and new validation. Never move confidential evidence or relabel LOG(N) Pacific work as historical NCyTE work.
