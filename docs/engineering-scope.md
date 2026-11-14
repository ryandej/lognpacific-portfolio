# Engineering scope

[Portfolio](../README.md) · [Project status](project-progress.md) · [Validation](local-validation.md)

This portfolio develops original work in Cyber Defense, Vulnerability Management, Threat Detection, Security Automation, and AI Security Engineering. Its objectives are reproducible implementations, observable security outcomes, and independent review. This document defines scope; actual implementation and validation status are recorded in [project progress](project-progress.md).

## Technical scope and deliverables

| Area | Intended deliverables | Validation needed |
|---|---|---|
| Windows 11 STIG remediation | Original PowerShell remediation, read-only verification, meaningful tests, rollback guidance, and a report per selected control. | Applicable benchmark and baseline, observed local tests, authorized before/after Tenable audits, side-effect checks, and independent review. |
| Vulnerability Management | Finding analysis, justified remediation decisions, before/after comparisons, and documented residual findings. | Relevant scan coverage and configuration, actual platform results, version consistency, and evidence for each claimed change. |
| Threat Detection | Original Defender or Sentinel KQL, query tests, investigation timelines, supported findings, and detection limitations. | Authorized asset/time scope, available tables and retention, positive/negative cases where useful, observed query results, and independent review. |
| Cyber Defense | Scoped investigations, response recommendations, and potentially a controlled honeypot study. | Evidence provenance, tested detection logic, distinction between attempted and successful activity, and separately approved containment/recovery if performed. |
| Security Automation | Scripts or utilities for an identified defensive workflow, with explicit inputs, bounded actions, error handling, and tests. | Reproducible execution, relevant failure paths, repeat-run behavior, and evidence that the automation achieves its stated objective. |
| AI Security Engineering | Proposed original implementations and evaluations, such as a read-only analysis experiment assessing evidence grounding or resistance to instructions embedded in event data. | Defined threat model, approved or synthetic dataset, baseline, metrics, held-out evaluation cases, actual trial results, limitations, and independent review. No AI implementation is currently established here. |

Each work item needs a defined objective, authorized scope, reproducible method, test outcomes, relevant platform validation, evidence references, and a review record. Capture failures and unresolved findings as well as successful checks. A lab result supports only the environment and conditions actually tested.

## Artifact organization

Current artifact locations:

- `stig-remediations/<rule-id>/`: remediation and verification scripts, tests, a report, and approved evidence.
- `threat-hunting/<investigation-id>/`: original KQL, relevant test cases, a report, and approved evidence.
- `cyber-defense/`: the authentication sequence detector, synthetic reference model, response decisions and five-panel Sentinel workbook.
- `vulnerability-management/`: the scoped program report, original policy/tabletop, evidence-derived assessment summary and consistency-checked metrics.
- `deployment/`: a pinned Windows 11 proposal and offline, non-deploying preflight.
- `tests/` and `tools/`: synthetic behavioral checks and read-only repository quality checks.

The [evidence ledger](../stig-remediations/evidence-workflow.md) remains beside the STIG workflow it supports. Cross-workstream tests cover evidence, deployment and detection boundaries. Decide an AI experiment's layout when its implementation scope is approved. Do not create empty work directories, speculative frameworks, CI, or unapproved tenant automation.

## Operating constraints

- Work only in this repository and the explicitly authorized range scope. Preserve the same participant-owned VM and confirm any existing VM before considering deployment. No second VM or routine deletion/recreation.
- Verify actual roles, data access, assigned resources, and applicable terms. Architecture descriptions and dashboard visibility are not proof of operational authorization.
- Obtain approval before cloud operations, scans, configuration changes, installations, role changes, exposure, containment, or recovery. A honeypot study requires a defined exposure window, monitoring, and a same-VM recovery plan before execution.
- Preserve management access, endpoint protection, scanning capability, and telemetry while testing changes. Resolve conflicts between hardening and later exercises before altering controls.
- Keep secrets, raw logs, sensitive resource information, confidential source documents, and third-party data out of Git. Export and publication require explicit permission and disclosure review.
- Treat AI experiments as scoped engineering work. Use authorized data, prevent evaluation-answer leakage, and do not give an experimental system unapproved access or authority.
- Keep NCyTE and other project directories and histories separate. Later reuse requires approved original material, attribution, and validation in the new context.

See the [methodology](methodology.md) for evidence and verification standards.

## Unresolved engineering dependencies

| Dependency | Evidence or decision needed before dependent work |
|---|---|
| Existing environment and permissions | One Windows VM is running on the assigned private subnet with no public IP. Bastion use is operator-confirmed; VM Run Command is observed working. Preserve this VM. Shared NSG read access was denied and not bypassed. Authenticated scanner access succeeded through bounded local prerequisites, now restored; licensing confirmation remains unresolved. See the [deployment record](../deployment/README.md). |
| VM lifecycle | Resolve shutdown and inactivity-purge behavior; establish how the same VM and necessary evidence will be preserved. |
| Windows and Tenable baseline | Windows 11 Pro 25H2 build 26200 has authenticated V2R11 fail-to-pass results for all ten selected controls. Exact Rule IDs and comparable scan configuration were checked. Additional independent review was waived by the operator; broader residual audit findings remain outside these ten controls. See the [execution report](windows-stig-validation.md). |
| Telemetry availability | The correct course workspace is identified; all ten queries executed against the assigned historical dataset. The owned endpoint is onboarded and a benign process event is centrally observed. Authentication coverage, broader ingestion and live detector performance remain separate checks. |
| Control and investigation selection | Ten real failed controls were selected and tested after the authenticated baseline. Keep further controls outside scope until justified by actual findings. Module 1 has an evidence-linked private report; the linked second-endpoint lead remains qualified and no peer response or raw telemetry is included. |
| Controlled honeypot feasibility | Decide whether the study is useful and authorize exposure, monitoring, containment, costs, and recovery before implementation. |
| Runtime and automation validation | PowerShell parsing/mocked tests, real registry apply/rollback/repeatability, native script-block logging and the ten Tenable checks have observed results. Actual populated compliance exports passed extraction. Eight detector fixtures and all five workbook panels passed synthetic Log Analytics execution. All ten investigation queries also executed against actual assigned historical data. One synthetic workbook is deployed and visually validated. Owned-endpoint process ingestion is observed; fleet performance and live detection effectiveness remain unvalidated. |
| AI experiment design | Select the question, threat model, dataset permissions, baseline, metrics, evaluation separation, and execution boundary. |
| Evidence and disclosure | Approve private evidence storage, sanitized outputs, and reviewer/publication access without exposing shared-environment details. |
| Verification and review | Define technical success criteria and record the exact artifact version, observed outcomes, reviewer findings, and their resolution. |

Update these dependencies as evidence becomes available. Record implementation and review status in [project progress](project-progress.md), without including confidential correspondence or source material.
